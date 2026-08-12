#!/usr/bin/env python3
"""Run retained deterministic Onyx reference-ledger campaigns under explicit seeds."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "vendor" / "onyx-zk" / "Cargo.toml"
TEST_NAME = "state_model_tests::deterministic_state_model_apply_undo_fork_reopen_campaign"
SUMMARY_PREFIX = "ONYX_STATE_MODEL_RESULT "
DIVERGENCE_PATTERN = re.compile(
    r"Onyx state-model divergence: (?P<message>[^;\r\n]+); "
    r"seed=(?P<seed>0x[0-9a-fA-F]+); step=(?P<step>[0-9]+); shortest_prefix="
)
REQUIRED_OPERATIONS = (
    "bridge",
    "transfer",
    "deployment",
    "issuance",
    "contextual",
    "rejection",
    "undo",
    "fork",
    "reopen",
)
DEFAULT_SEEDS = (
    0x0123456789ABCDEF,
    0x9E3779B97F4A7C15,
    0xD1B54A32D192ED03,
    0x94D049BB133111EB,
    0xC0DEC0DEC0DEC0DE,
    0xF00D1234F00D1234,
    0xA5A5A5A55A5A5A5A,
    0xDEADBEEF8BADF00D,
)


class BuildFailure(ValueError):
    def __init__(self, message: str, output: str):
        super().__init__(message)
        self.output = output


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_seed(value: str) -> int:
    try:
        seed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("seed must be an integer literal") from error
    if seed <= 0 or seed > (1 << 64) - 1:
        raise argparse.ArgumentTypeError("seed must be in 1..2^64-1")
    return seed


def parse_divergence(output: str) -> dict[str, object] | None:
    matches = list(DIVERGENCE_PATTERN.finditer(output))
    if len(matches) != 1:
        return None
    match = matches[0]
    return {
        "message": match.group("message"),
        "seed": f"0x{int(match.group('seed'), 0):016x}",
        "step": int(match.group("step")),
    }


def minimized_requested_steps(divergence: dict[str, object]) -> int:
    return max(10, int(divergence["step"]) + 1)


def parse_summary(output: str, expected_seed: int, expected_steps: int) -> dict[str, object]:
    summaries = []
    for line in output.splitlines():
        marker = line.find(SUMMARY_PREFIX)
        if marker >= 0:
            summaries.append(line[marker + len(SUMMARY_PREFIX) :])
    if len(summaries) != 1:
        raise ValueError(f"expected one state-model summary, found {len(summaries)}")
    fields: dict[str, str] = {}
    for token in summaries[0].split():
        if "=" not in token:
            raise ValueError(f"malformed summary token: {token!r}")
        key, value = token.split("=", 1)
        if key in fields:
            raise ValueError(f"duplicate summary field: {key}")
        fields[key] = value
    required = {
        "seed",
        "requested_steps",
        "trace_steps",
        "checkpoints",
        "snapshot_bytes",
        "root",
        *REQUIRED_OPERATIONS,
    }
    missing = required - fields.keys()
    if missing:
        raise ValueError(f"summary is missing fields: {sorted(missing)}")
    seed = int(fields["seed"], 0)
    steps = int(fields["requested_steps"])
    if seed != expected_seed or steps != expected_steps:
        raise ValueError(
            f"summary identity mismatch seed=0x{seed:016x}/{steps}, "
            f"expected 0x{expected_seed:016x}/{expected_steps}"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", fields["root"]):
        raise ValueError("summary root is not canonical lowercase SHA-sized hex")
    numeric = {
        key: int(value)
        for key, value in fields.items()
        if key not in {"seed", "root"}
    }
    for operation in REQUIRED_OPERATIONS:
        if numeric[operation] <= 0:
            raise ValueError(f"required operation family has zero coverage: {operation}")
    if numeric["trace_steps"] <= 0 or numeric["trace_steps"] > expected_steps:
        raise ValueError("summary trace step count is outside the requested campaign")
    if numeric["checkpoints"] <= 0 or numeric["snapshot_bytes"] <= 0:
        raise ValueError("summary has no successful checkpoint or snapshot")
    return {
        "seed": f"0x{seed:016x}",
        "requested_steps": steps,
        "root": fields["root"],
        **numeric,
    }


def windows_process_sample(pid: int) -> dict[str, float | int]:
    from ctypes import wintypes

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

    handle = ctypes.windll.kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess failed")
    try:
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

        def filetime(value: object) -> float:
            return (
                (value.dwHighDateTime << 32) | value.dwLowDateTime
            ) / 10_000_000.0

        return {
            "rss_bytes": int(counters.WorkingSetSize),
            "peak_rss_bytes": int(counters.PeakWorkingSetSize),
            "cpu_seconds": filetime(kernel) + filetime(user),
        }
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def linux_process_sample(pid: int) -> dict[str, float | int]:
    status: dict[str, int] = {}
    for line in pathlib.Path(f"/proc/{pid}/status").read_text(
        encoding="ascii"
    ).splitlines():
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


def posix_process_sample(pid: int) -> dict[str, float | int]:
    output = subprocess.check_output(
        ["ps", "-o", "rss=", "-o", "time=", "-p", str(pid)], text=True
    ).strip()
    rss, cpu = output.split()
    parts = [int(part) for part in cpu.split(":")]
    seconds = parts[-1] + 60 * parts[-2] + (3600 * parts[-3] if len(parts) == 3 else 0)
    return {"rss_bytes": int(rss) * 1024, "peak_rss_bytes": 0, "cpu_seconds": seconds}


def process_sample(pid: int) -> dict[str, float | int]:
    if os.name == "nt":
        return windows_process_sample(pid)
    if sys.platform.startswith("linux"):
        return linux_process_sample(pid)
    return posix_process_sample(pid)


def run_measured(
    command: list[str],
    environment: dict[str, str],
    timeout: float,
    sample_interval: float,
) -> dict[str, object]:
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    stop = threading.Event()
    samples: list[dict[str, float | int]] = []

    def sample_process() -> None:
        while not stop.is_set():
            try:
                samples.append(process_sample(process.pid))
            except (OSError, ValueError, subprocess.SubprocessError):
                if process.poll() is not None:
                    break
            stop.wait(sample_interval)

    started = time.monotonic()
    sampler = threading.Thread(target=sample_process, name="onyx-state-sampler", daemon=True)
    sampler.start()
    timed_out = False
    try:
        output, _unused = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        output, _unused = process.communicate()
    finally:
        stop.set()
        sampler.join(timeout=sample_interval + 2)
    elapsed = round(time.monotonic() - started, 6)
    return {
        "output": output,
        "return_code": None if timed_out else process.returncode,
        "elapsed_seconds": elapsed,
        "cpu_seconds": round(
            max((float(sample["cpu_seconds"]) for sample in samples), default=0.0), 6
        ),
        "peak_rss_bytes": max(
            (
                max(int(sample["rss_bytes"]), int(sample["peak_rss_bytes"]))
                for sample in samples
            ),
            default=0,
        ),
        "sample_count": len(samples),
    }


def atomic_write(path: pathlib.Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def failure_log_path(report: pathlib.Path, seed: int) -> pathlib.Path:
    return report.with_name(f"{report.stem}-seed-{seed:016x}.log")


def build_log_path(report: pathlib.Path) -> pathlib.Path:
    return report.with_name(f"{report.stem}-build.log")


def minimized_log_path(report: pathlib.Path, seed: int) -> pathlib.Path:
    return report.with_name(f"{report.stem}-seed-{seed:016x}-minimized.log")


def build_test_binary(args: argparse.Namespace) -> dict[str, object]:
    command = [
        args.cargo,
        "test",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        str(args.manifest.resolve()),
        "--no-run",
        "--message-format=json",
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=args.build_timeout,
        check=False,
    )
    output = completed.stdout
    executables: list[pathlib.Path] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target", {})
        profile_data = event.get("profile", {})
        executable = event.get("executable")
        if (
            event.get("reason") == "compiler-artifact"
            and target.get("name") == "onyx_zk"
            and profile_data.get("test") is True
            and executable
        ):
            executables.append(pathlib.Path(executable).resolve())
    if completed.returncode != 0:
        raise BuildFailure(
            f"locked release test build returned {completed.returncode}", output
        )
    unique = list(dict.fromkeys(executables))
    if len(unique) != 1 or not unique[0].is_file():
        raise BuildFailure(
            f"expected one Onyx library test executable, found {len(unique)}", output
        )
    executable = unique[0]
    return {
        "command": command,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "output": output,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "executable": executable,
        "executable_sha256": sha256_file(executable),
    }


def test_command(executable: pathlib.Path) -> list[str]:
    return [str(executable), TEST_NAME, "--exact", "--nocapture", "--test-threads=1"]


def replay(
    executable: pathlib.Path, seed: int, steps: int, timeout: float
) -> dict[str, object]:
    environment = os.environ.copy()
    environment["ONYX_STATE_MODEL_SEED"] = f"0x{seed:016x}"
    environment["ONYX_STATE_MODEL_STEPS"] = str(steps)
    try:
        completed = subprocess.run(
            test_command(executable),
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {"return_code": completed.returncode, "output": completed.stdout}
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return {"return_code": None, "output": output}


def same_divergence(
    observed: dict[str, object] | None, expected: dict[str, object]
) -> bool:
    return observed == expected


def minimize_divergence(
    executable: pathlib.Path,
    seed: int,
    requested_steps: int,
    divergence: dict[str, object],
    timeout: float,
    report_path: pathlib.Path,
) -> dict[str, object]:
    candidate_steps = minimized_requested_steps(divergence)
    candidate = replay(executable, seed, candidate_steps, timeout)
    candidate_output = str(candidate["output"])
    candidate_divergence = parse_divergence(candidate_output)
    reproduced = same_divergence(candidate_divergence, divergence)
    predecessor_steps = candidate_steps - 1 if candidate_steps > 10 else None
    predecessor_reproduced = False
    predecessor: dict[str, object] | None = None
    if reproduced and predecessor_steps is not None:
        predecessor = replay(executable, seed, predecessor_steps, timeout)
        predecessor_reproduced = same_divergence(
            parse_divergence(str(predecessor["output"])), divergence
        )
    artifact = minimized_log_path(report_path, seed)
    artifact.write_text(candidate_output, encoding="utf-8")
    return {
        "attempted": True,
        "original_requested_steps": requested_steps,
        "candidate_requested_steps": candidate_steps,
        "candidate_return_code": candidate["return_code"],
        "reproduced": reproduced,
        "predecessor_requested_steps": predecessor_steps,
        "predecessor_return_code": None if predecessor is None else predecessor["return_code"],
        "predecessor_reproduced": predecessor_reproduced,
        "minimality_proven": reproduced and not predecessor_reproduced,
        "artifact": artifact.name,
        "artifact_sha256": sha256_file(artifact),
    }


def resource_checks(args: argparse.Namespace, measured: dict[str, object]) -> dict[str, bool]:
    output_bytes = len(str(measured["output"]).encode("utf-8"))
    return {
        "wall_time_within_limit": float(measured["elapsed_seconds"])
        <= args.timeout_per_seed,
        "cpu_time_within_limit": args.max_seed_cpu_seconds is None
        or float(measured["cpu_seconds"]) <= args.max_seed_cpu_seconds,
        "peak_rss_within_limit": args.max_seed_rss_mib is None
        or int(measured["peak_rss_bytes"]) <= args.max_seed_rss_mib * 1024 * 1024,
        "output_size_within_limit": args.max_seed_output_mib is None
        or output_bytes <= args.max_seed_output_mib * 1024 * 1024,
        "resource_samples_observed": int(measured["sample_count"]) > 0
        and int(measured["peak_rss_bytes"]) > 0,
    }


def run_campaign(args: argparse.Namespace) -> int:
    manifest = args.manifest.resolve()
    lockfile = manifest.with_name("Cargo.lock")
    if not manifest.is_file() or not lockfile.is_file():
        raise ValueError(f"manifest or lockfile is missing: {manifest}")
    seeds = args.seed or list(DEFAULT_SEEDS)
    if len(set(seeds)) != len(seeds):
        raise ValueError("campaign seeds must be unique")

    report_path = args.report.resolve()
    report: dict[str, object] = {
        "schema": "bytecoin-onyx-state-model-campaign-v2",
        "scope": "deterministic-local-or-ci-not-release-evidence",
        "revision": args.revision,
        "generated_at": utc_now(),
        "platform": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "python": sys.version.split()[0],
        },
        "manifest": manifest.relative_to(ROOT).as_posix(),
        "manifest_sha256": sha256_file(manifest),
        "lockfile_sha256": sha256_file(lockfile),
        "test": TEST_NAME,
        "requested_steps_per_seed": args.steps,
        "requested_seeds": [f"0x{seed:016x}" for seed in seeds],
        "resource_limits": {
            "timeout_per_seed_seconds": args.timeout_per_seed,
            "max_seed_cpu_seconds": args.max_seed_cpu_seconds,
            "max_seed_rss_mib": args.max_seed_rss_mib,
            "max_seed_output_mib": args.max_seed_output_mib,
            "sample_interval_seconds": args.sample_interval,
        },
        "campaigns": [],
        "passed": False,
    }
    atomic_write(report_path, report)
    started = time.monotonic()
    try:
        build = build_test_binary(args)
    except (subprocess.TimeoutExpired, BuildFailure) as error:
        output = error.stdout if isinstance(error, subprocess.TimeoutExpired) else error.output
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        log_path = build_log_path(report_path)
        log_path.write_text(output or str(error), encoding="utf-8")
        report["build"] = {
            "passed": False,
            "error": str(error),
            "failure_log": log_path.name,
            "failure_log_sha256": sha256_file(log_path),
        }
        report["completed_at"] = utc_now()
        report["elapsed_seconds"] = round(time.monotonic() - started, 6)
        atomic_write(report_path, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    executable = build.pop("executable")
    build.pop("output")
    build["passed"] = True
    build["test_executable"] = pathlib.Path(executable).relative_to(ROOT).as_posix()
    report["build"] = build
    atomic_write(report_path, report)

    for seed in seeds:
        environment = os.environ.copy()
        environment["ONYX_STATE_MODEL_SEED"] = f"0x{seed:016x}"
        environment["ONYX_STATE_MODEL_STEPS"] = str(args.steps)
        measured = run_measured(
            test_command(pathlib.Path(executable)),
            environment,
            args.timeout_per_seed,
            args.sample_interval,
        )
        output = str(measured.pop("output"))
        return_code = measured.pop("return_code")
        checks = resource_checks(args, {**measured, "output": output})
        result: dict[str, object] = {
            "seed": f"0x{seed:016x}",
            **measured,
            "return_code": return_code,
            "output_bytes": len(output.encode("utf-8")),
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            "checks": checks,
        }
        try:
            if return_code != 0:
                raise ValueError(
                    "campaign timed out"
                    if return_code is None
                    else f"test executable returned {return_code}"
                )
            result["summary"] = parse_summary(output, seed, args.steps)
            failed_checks = [name for name, passed in checks.items() if not passed]
            if failed_checks:
                raise ValueError(f"resource checks failed: {', '.join(failed_checks)}")
            result["passed"] = True
        except ValueError as error:
            log_path = failure_log_path(report_path, seed)
            log_path.write_text(output, encoding="utf-8")
            divergence = parse_divergence(output)
            result.update(
                {
                    "passed": False,
                    "error": str(error),
                    "failure_log": log_path.name,
                    "failure_log_sha256": sha256_file(log_path),
                }
            )
            if divergence is not None:
                result["divergence"] = divergence
                result["minimization"] = minimize_divergence(
                    pathlib.Path(executable),
                    seed,
                    args.steps,
                    divergence,
                    args.minimize_timeout,
                    report_path,
                )
            report["campaigns"].append(result)
            report["elapsed_seconds"] = round(time.monotonic() - started, 6)
            report["completed_at"] = utc_now()
            atomic_write(report_path, report)
            print(json.dumps(report, indent=2, sort_keys=True))
            return 1
        report["campaigns"].append(result)
        atomic_write(report_path, report)

    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report["completed_at"] = utc_now()
    report["total_requested_steps"] = args.steps * len(seeds)
    report["total_trace_steps"] = sum(
        campaign["summary"]["trace_steps"] for campaign in report["campaigns"]
    )
    report["observed"] = {
        "max_seed_elapsed_seconds": max(
            campaign["elapsed_seconds"] for campaign in report["campaigns"]
        ),
        "max_seed_cpu_seconds": max(
            campaign["cpu_seconds"] for campaign in report["campaigns"]
        ),
        "max_seed_peak_rss_bytes": max(
            campaign["peak_rss_bytes"] for campaign in report["campaigns"]
        ),
        "max_seed_output_bytes": max(
            campaign["output_bytes"] for campaign in report["campaigns"]
        ),
    }
    report["passed"] = True
    atomic_write(report_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", action="append", type=parse_seed)
    parser.add_argument("--steps", type=int, default=2000)
    parser.add_argument("--build-timeout", type=float, default=900.0)
    parser.add_argument("--timeout-per-seed", type=float, default=900.0)
    parser.add_argument("--minimize-timeout", type=float, default=300.0)
    parser.add_argument("--sample-interval", type=float, default=0.05)
    parser.add_argument("--max-seed-cpu-seconds", type=float)
    parser.add_argument("--max-seed-rss-mib", type=float)
    parser.add_argument("--max-seed-output-mib", type=float)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.steps < 10 or args.steps > 1_000_000:
        parser.error("--steps must be in 10..1000000")
    for name in ("build_timeout", "timeout_per_seed", "minimize_timeout", "sample_interval"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    for name in ("max_seed_cpu_seconds", "max_seed_rss_mib", "max_seed_output_mib"):
        if getattr(args, name) is not None and getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    try:
        return run_campaign(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
