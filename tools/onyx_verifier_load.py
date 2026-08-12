#!/usr/bin/env python3
"""Bounded local Onyx verifier load qualification.

This consumes distinct, already-built transaction hex files so proof construction is not included in
the admission measurement. Reports are local qualification evidence, never release evidence.
"""

import argparse
import base64
import concurrent.futures
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


SCHEMA = "bytecoin-onyx-verifier-load-v1"
VERIFIER_BUSY = -104
METRIC_FIELDS = (
    "onyx_verifier_active",
    "onyx_verifier_peak_active",
    "onyx_verifier_acquired",
    "onyx_verifier_rejected_global",
    "onyx_verifier_rejected_source",
    "onyx_verifier_precheck_conflicts",
    "onyx_verifier_abandoned_rpcs",
    "transaction_downloads_active",
    "onyx_verifier_retry_cooldowns",
)


def utc_now():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rpc(url, method, params, authorization, timeout):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": params},
        separators=(",", ":"),
    ).encode("ascii")
    headers = {"Content-Type": "application/json-rpc"}
    if authorization:
        token = base64.b64encode(authorization.encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        payload = error.read().decode("utf-8", errors="replace")
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return {"transport_error": f"HTTP {error.code}: {payload}"}
    except Exception as error:  # The report must retain timeouts/refusals rather than hide them.
        return {"transport_error": f"{type(error).__name__}: {error}"}


def normalized_metrics(response):
    result = response.get("result", {}) if isinstance(response, dict) else {}
    return {field: int(result.get(field, 0)) for field in METRIC_FIELDS}


def read_transactions(paths):
    transactions = []
    seen = set()
    for path in paths:
        text = path.read_text(encoding="utf-8").strip()
        if text.startswith("{"):
            value = json.loads(text)
            text = value.get("binary_transaction", "")
        text = "".join(text.split()).lower()
        if not text or len(text) % 2:
            raise ValueError(f"{path}: transaction must be non-empty even-length hex")
        try:
            raw = bytes.fromhex(text)
        except ValueError as error:
            raise ValueError(f"{path}: transaction is not hex") from error
        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen:
            raise ValueError(f"{path}: duplicate transaction input {digest}")
        seen.add(digest)
        transactions.append({"source": str(path), "sha256": digest, "hex": text, "bytes": len(raw)})
    if len(transactions) < 2:
        raise ValueError("at least two distinct transaction files are required")
    return transactions


def windows_process_sample(pid):
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
        class MemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = MemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), counters.cb
        ):
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not ctypes.windll.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise OSError(ctypes.get_last_error(), "GetProcessTimes failed")

        def filetime(value):
            return ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000.0

        return {
            "rss_bytes": int(counters.WorkingSetSize),
            "peak_rss_bytes": int(counters.PeakWorkingSetSize),
            "cpu_seconds": filetime(kernel) + filetime(user),
        }
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def linux_process_sample(pid):
    status = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            key, value, _unit = line.split()
            status[key.rstrip(":")] = int(value) * 1024
    fields = pathlib.Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    return {
        "rss_bytes": status.get("VmRSS", 0),
        "peak_rss_bytes": status.get("VmHWM", 0),
        "cpu_seconds": (int(fields[13]) + int(fields[14])) / ticks,
    }


def posix_process_sample(pid):
    output = subprocess.check_output(
        ["ps", "-o", "rss=", "-o", "time=", "-p", str(pid)], text=True
    ).strip()
    rss, cpu = output.split()
    parts = [int(part) for part in cpu.split(":")]
    seconds = parts[-1] + 60 * parts[-2] + (3600 * parts[-3] if len(parts) == 3 else 0)
    return {"rss_bytes": int(rss) * 1024, "peak_rss_bytes": 0, "cpu_seconds": seconds}


def process_sample(pid):
    if os.name == "nt":
        return windows_process_sample(pid)
    if sys.platform.startswith("linux"):
        return linux_process_sample(pid)
    return posix_process_sample(pid)


def classify(response):
    if "result" in response:
        return "accepted"
    if response.get("error", {}).get("code") == VERIFIER_BUSY:
        return "verifier_busy"
    if "transport_error" in response:
        return "transport_error"
    return "rejected"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc-url", default="http://127.0.0.1:18081/json_rpc")
    parser.add_argument("--authorization", required=True, help="private RPC user:password")
    parser.add_argument("--pid", required=True, type=int, help="bytecoind process id")
    parser.add_argument("--transaction-file", action="append", type=pathlib.Path, required=True)
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--sample-interval", type=float, default=0.25)
    parser.add_argument("--rpc-timeout", type=float, default=1800.0)
    parser.add_argument("--statistics-timeout", type=float, default=2.0)
    parser.add_argument("--max-rss-growth-mib", type=float)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--allow-no-overload", action="store_true")
    args = parser.parse_args()
    if args.parallel < 2 or args.sample_interval <= 0:
        parser.error("--parallel must be at least 2 and --sample-interval must be positive")

    transactions = read_transactions(args.transaction_file)
    selected = transactions[: args.parallel]
    if len(selected) < args.parallel:
        parser.error("--parallel exceeds the number of distinct transaction files")

    baseline_stats_response = rpc(
        args.rpc_url, "get_statistics", {}, args.authorization, args.statistics_timeout
    )
    if "result" not in baseline_stats_response:
        raise RuntimeError(f"authenticated get_statistics failed: {baseline_stats_response!r}")
    baseline_status = rpc(args.rpc_url, "get_status", {}, None, args.statistics_timeout)
    if "result" not in baseline_status:
        raise RuntimeError(f"get_status failed before load: {baseline_status!r}")
    baseline_process = process_sample(args.pid)

    stop = threading.Event()
    start = threading.Event()
    process_samples = []
    daemon_samples = []

    def process_sampler():
        while not stop.is_set():
            stamp = time.monotonic()
            sample = {"elapsed_seconds": stamp - started}
            try:
                sample.update(process_sample(args.pid))
            except Exception as error:
                sample["process_error"] = f"{type(error).__name__}: {error}"
            process_samples.append(sample)
            stop.wait(args.sample_interval)

    def daemon_sampler():
        while not stop.is_set():
            sample = {"elapsed_seconds": time.monotonic() - started}
            stats = rpc(
                args.rpc_url, "get_statistics", {}, args.authorization, args.statistics_timeout
            )
            if "result" in stats:
                sample.update(normalized_metrics(stats))
            else:
                sample["statistics_error"] = stats
            daemon_samples.append(sample)
            stop.wait(args.sample_interval)

    def submit(transaction):
        start.wait()
        begin = time.monotonic()
        response = rpc(
            args.rpc_url,
            "send_transaction",
            {"binary_transaction": transaction["hex"]},
            None,
            args.rpc_timeout,
        )
        return {
            "sha256": transaction["sha256"],
            "bytes": transaction["bytes"],
            "elapsed_seconds": time.monotonic() - begin,
            "classification": classify(response),
            "response": response,
        }

    started = time.monotonic()
    process_thread = threading.Thread(
        target=process_sampler, name="onyx-load-process-sampler", daemon=True
    )
    daemon_thread = threading.Thread(
        target=daemon_sampler, name="onyx-load-daemon-sampler", daemon=True
    )
    process_thread.start()
    daemon_thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = [executor.submit(submit, transaction) for transaction in selected]
        start.set()
        submissions = [future.result(timeout=args.rpc_timeout + 30) for future in futures]
    stop.set()
    process_thread.join(timeout=args.sample_interval + 2)
    daemon_thread.join(timeout=args.statistics_timeout + args.sample_interval + 2)
    finished = time.monotonic()

    final_stats_response = rpc(
        args.rpc_url, "get_statistics", {}, args.authorization, args.statistics_timeout
    )
    final_status = rpc(args.rpc_url, "get_status", {}, None, args.statistics_timeout)
    final_process = process_sample(args.pid)
    baseline_metrics = normalized_metrics(baseline_stats_response)
    final_metrics = normalized_metrics(final_stats_response)
    peak_active = max(
        [
            baseline_metrics["onyx_verifier_active"],
            final_metrics["onyx_verifier_active"],
            final_metrics["onyx_verifier_peak_active"],
        ]
        + [sample.get("onyx_verifier_active", 0) for sample in daemon_samples]
    )
    peak_rss = max(
        [baseline_process["rss_bytes"], final_process["rss_bytes"]]
        + [sample.get("rss_bytes", 0) for sample in process_samples]
    )
    rss_growth = max(0, peak_rss - baseline_process["rss_bytes"])
    busy_count = sum(item["classification"] == "verifier_busy" for item in submissions)
    successful_daemon_samples = [
        sample for sample in daemon_samples if "onyx_verifier_active" in sample
    ]
    daemon_sample_errors = [
        sample for sample in daemon_samples if "statistics_error" in sample
    ]
    transport_errors = [
        item for item in submissions if item["classification"] == "transport_error"
    ]
    checks = {
        "node_responded_after_load": "result" in final_status and "result" in final_stats_response,
        "node_responded_during_load": len(successful_daemon_samples) >= 2,
        "no_daemon_sampling_errors": not daemon_sample_errors,
        "no_submission_transport_errors": not transport_errors,
        "verifier_peak_within_bound": peak_active <= 1
        and final_metrics["onyx_verifier_peak_active"] <= 1,
        "verifier_permit_observed": final_metrics["onyx_verifier_acquired"]
        > baseline_metrics["onyx_verifier_acquired"],
        "overload_observed": args.allow_no_overload
        or busy_count > 0
        or final_metrics["onyx_verifier_rejected_global"]
        > baseline_metrics["onyx_verifier_rejected_global"]
        or final_metrics["onyx_verifier_rejected_source"]
        > baseline_metrics["onyx_verifier_rejected_source"],
        "rss_growth_within_requested_bound": args.max_rss_growth_mib is None
        or rss_growth <= args.max_rss_growth_mib * 1024 * 1024,
    }
    report = {
        "schema": SCHEMA,
        "qualification_scope": "local-load-not-release-evidence",
        "revision": args.revision,
        "generated_at": utc_now(),
        "platform": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
        },
        "configuration": {
            "rpc_url": args.rpc_url,
            "pid": args.pid,
            "parallel": args.parallel,
            "sample_interval_seconds": args.sample_interval,
            "max_rss_growth_mib": args.max_rss_growth_mib,
        },
        "transactions": [{key: value for key, value in tx.items() if key != "hex"} for tx in selected],
        "elapsed_seconds": finished - started,
        "baseline": {"daemon": baseline_metrics, "process": baseline_process, "status": baseline_status},
        "process_samples": process_samples,
        "daemon_samples": daemon_samples,
        "submissions": submissions,
        "final": {"daemon": final_metrics, "process": final_process, "status": final_status},
        "observed": {
            "peak_verifier_active": peak_active,
            "peak_rss_bytes": peak_rss,
            "rss_growth_bytes": rss_growth,
            "busy_responses": busy_count,
            "successful_daemon_samples": len(successful_daemon_samples),
            "daemon_sampling_errors": len(daemon_sample_errors),
            "submission_transport_errors": len(transport_errors),
        },
        "checks": checks,
        "passed": all(checks.values()),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_suffix(args.report.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(args.report)
    print(json.dumps({"report": str(args.report), "passed": report["passed"], "checks": checks}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
