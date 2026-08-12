#!/usr/bin/env python3
"""Measure exact accepted Onyx snapshot collection limits under bounded resources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys
import time

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.onyx.state_model_campaign import (
    DEFAULT_MANIFEST,
    ROOT,
    BuildFailure,
    atomic_write,
    build_test_binary,
    run_measured,
    sha256_file,
    utc_now,
)


TEST_NAME = "state::tests::snapshot_accepts_exact_configured_collection_limit"
RESULT_PREFIX = "ONYX_SNAPSHOT_LIMIT_RESULT "
KINDS = ("anchors", "nullifiers", "program_states")


def parse_result(output: str, expected_kind: str) -> dict[str, object]:
    summaries = []
    for line in output.splitlines():
        marker = line.find(RESULT_PREFIX)
        if marker >= 0:
            summaries.append(line[marker + len(RESULT_PREFIX) :])
    if len(summaries) != 1:
        raise ValueError(f"expected one snapshot-limit result, found {len(summaries)}")
    fields: dict[str, str] = {}
    for token in summaries[0].split():
        if "=" not in token:
            raise ValueError(f"malformed result token: {token!r}")
        key, value = token.split("=", 1)
        if key in fields:
            raise ValueError(f"duplicate result field: {key}")
        fields[key] = value
    if set(fields) != {"kind", "count", "snapshot_bytes"}:
        raise ValueError(f"unexpected result fields: {sorted(fields)}")
    count = int(fields["count"])
    snapshot_bytes = int(fields["snapshot_bytes"])
    if fields["kind"] != expected_kind:
        raise ValueError(
            f"snapshot kind mismatch: {fields['kind']!r} != {expected_kind!r}"
        )
    if count != 1_000_000 or snapshot_bytes <= count:
        raise ValueError("snapshot result did not exercise the exact configured limit")
    return {"kind": expected_kind, "count": count, "snapshot_bytes": snapshot_bytes}


def case_log_path(report: pathlib.Path, kind: str) -> pathlib.Path:
    return report.with_name(f"{report.stem}-{kind}.log")


def checks(args: argparse.Namespace, measured: dict[str, object]) -> dict[str, bool]:
    return {
        "wall_time_within_limit": float(measured["elapsed_seconds"])
        <= args.timeout_per_case,
        "cpu_time_within_limit": args.max_case_cpu_seconds is None
        or float(measured["cpu_seconds"]) <= args.max_case_cpu_seconds,
        "peak_rss_within_limit": args.max_case_rss_mib is None
        or int(measured["peak_rss_bytes"]) <= args.max_case_rss_mib * 1024 * 1024,
        "output_size_within_limit": args.max_case_output_mib is None
        or int(measured["output_bytes"]) <= args.max_case_output_mib * 1024 * 1024,
        "resource_samples_observed": int(measured["sample_count"]) > 0
        and int(measured["peak_rss_bytes"]) > 0,
    }


def run(args: argparse.Namespace) -> int:
    manifest = args.manifest.resolve()
    lockfile = manifest.with_name("Cargo.lock")
    if not manifest.is_file() or not lockfile.is_file():
        raise ValueError(f"manifest or lockfile is missing: {manifest}")
    kinds = args.kind or list(KINDS)
    if len(set(kinds)) != len(kinds):
        raise ValueError("snapshot-limit kinds must be unique")
    report_path = args.report.resolve()
    report: dict[str, object] = {
        "schema": "bytecoin-onyx-snapshot-limit-campaign-v1",
        "scope": "exact-limit-local-or-ci-not-release-evidence",
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
        "requested_kinds": kinds,
        "resource_limits": {
            "timeout_per_case_seconds": args.timeout_per_case,
            "max_case_cpu_seconds": args.max_case_cpu_seconds,
            "max_case_rss_mib": args.max_case_rss_mib,
            "max_case_output_mib": args.max_case_output_mib,
            "sample_interval_seconds": args.sample_interval,
        },
        "cases": [],
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
        log_path = report_path.with_name(f"{report_path.stem}-build.log")
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
        return 1
    executable = pathlib.Path(build.pop("executable"))
    build.pop("output")
    build["passed"] = True
    build["test_executable"] = executable.relative_to(ROOT).as_posix()
    report["build"] = build
    atomic_write(report_path, report)

    command = [
        str(executable),
        TEST_NAME,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    for kind in kinds:
        environment = os.environ.copy()
        environment["ONYX_SNAPSHOT_LIMIT_KIND"] = kind
        measured = run_measured(
            command, environment, args.timeout_per_case, args.sample_interval
        )
        output = str(measured.pop("output"))
        return_code = measured.pop("return_code")
        result: dict[str, object] = {
            "kind": kind,
            **measured,
            "return_code": return_code,
            "output_bytes": len(output.encode("utf-8")),
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
        case_checks = checks(args, {**result, "output_bytes": result["output_bytes"]})
        result["checks"] = case_checks
        try:
            if return_code != 0:
                raise ValueError(
                    "case timed out"
                    if return_code is None
                    else f"test executable returned {return_code}"
                )
            result["summary"] = parse_result(output, kind)
            failed = [name for name, passed in case_checks.items() if not passed]
            if failed:
                raise ValueError(f"resource checks failed: {', '.join(failed)}")
            result["passed"] = True
        except ValueError as error:
            log_path = case_log_path(report_path, kind)
            log_path.write_text(output, encoding="utf-8")
            result.update(
                {
                    "passed": False,
                    "error": str(error),
                    "failure_log": log_path.name,
                    "failure_log_sha256": sha256_file(log_path),
                }
            )
        report["cases"].append(result)
        atomic_write(report_path, report)

    report["completed_at"] = utc_now()
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report["observed"] = {
        "max_case_elapsed_seconds": max(
            case["elapsed_seconds"] for case in report["cases"]
        ),
        "max_case_cpu_seconds": max(case["cpu_seconds"] for case in report["cases"]),
        "max_case_peak_rss_bytes": max(
            case["peak_rss_bytes"] for case in report["cases"]
        ),
        "max_snapshot_bytes": max(
            case.get("summary", {}).get("snapshot_bytes", 0)
            for case in report["cases"]
        ),
    }
    report["passed"] = all(case["passed"] for case in report["cases"])
    atomic_write(report_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--kind", action="append", choices=KINDS)
    parser.add_argument("--build-timeout", type=float, default=900.0)
    parser.add_argument("--timeout-per-case", type=float, default=2700.0)
    parser.add_argument("--sample-interval", type=float, default=0.1)
    parser.add_argument("--max-case-cpu-seconds", type=float)
    parser.add_argument("--max-case-rss-mib", type=float)
    parser.add_argument("--max-case-output-mib", type=float)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    for name in ("build_timeout", "timeout_per_case", "sample_interval"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    for name in ("max_case_cpu_seconds", "max_case_rss_mib", "max_case_output_mib"):
        if getattr(args, name) is not None and getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    try:
        return run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
