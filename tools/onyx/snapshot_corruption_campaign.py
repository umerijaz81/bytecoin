#!/usr/bin/env python3
"""Run retained seeded structural corruption campaigns against Onyx snapshots."""

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

from tools.onyx.snapshot_limit_campaign import checks as resource_checks
from tools.onyx.state_model_campaign import (
    DEFAULT_MANIFEST,
    ROOT,
    BuildFailure,
    atomic_write,
    build_test_binary,
    parse_seed,
    run_measured,
    sha256_file,
    utc_now,
)


TEST_NAME = "state::tests::snapshot_structured_corruption_campaign"
RESULT_PREFIX = "ONYX_SNAPSHOT_CORRUPTION_RESULT "
DEFAULT_SEEDS = (
    0x534E4150434F5252,
    0x9E3779B97F4A7C15,
    0xD1B54A32D192ED03,
    0xDEADBEEF8BADF00D,
)


def parse_result(output: str, expected_seed: int, expected_cases: int) -> dict[str, object]:
    summaries = []
    for line in output.splitlines():
        marker = line.find(RESULT_PREFIX)
        if marker >= 0:
            summaries.append(line[marker + len(RESULT_PREFIX) :])
    if len(summaries) != 1:
        raise ValueError(f"expected one snapshot-corruption result, found {len(summaries)}")
    fields: dict[str, str] = {}
    for token in summaries[0].split():
        if "=" not in token:
            raise ValueError(f"malformed result token: {token!r}")
        key, value = token.split("=", 1)
        if key in fields:
            raise ValueError(f"duplicate result field: {key}")
        fields[key] = value
    required = {
        "seed",
        "cases",
        "targeted",
        "rejected",
        "accepted_current",
        "accepted_migrated",
        "max_input_bytes",
    }
    if set(fields) != required:
        raise ValueError(f"unexpected result fields: {sorted(fields)}")
    seed = int(fields["seed"], 0)
    numeric = {key: int(value) for key, value in fields.items() if key != "seed"}
    if seed != expected_seed or numeric["cases"] != expected_cases:
        raise ValueError("snapshot-corruption result identity mismatch")
    if numeric["targeted"] < 6:
        raise ValueError("targeted structural coverage was incomplete")
    classified = (
        numeric["rejected"]
        + numeric["accepted_current"]
        + numeric["accepted_migrated"]
    )
    if classified != expected_cases:
        raise ValueError("mutation classifications do not sum to requested cases")
    if numeric["rejected"] <= 0 or numeric["accepted_current"] <= 0:
        raise ValueError("campaign did not cover both rejection and canonical acceptance")
    if numeric["max_input_bytes"] <= 0 or numeric["max_input_bytes"] > 1024 * 1024:
        raise ValueError("campaign input size escaped its structural bound")
    return {"seed": f"0x{seed:016x}", **numeric}


def log_path(report: pathlib.Path, seed: int) -> pathlib.Path:
    return report.with_name(f"{report.stem}-seed-{seed:016x}.log")


def run(args: argparse.Namespace) -> int:
    manifest = args.manifest.resolve()
    lockfile = manifest.with_name("Cargo.lock")
    if not manifest.is_file() or not lockfile.is_file():
        raise ValueError(f"manifest or lockfile is missing: {manifest}")
    seeds = args.seed or list(DEFAULT_SEEDS)
    if len(set(seeds)) != len(seeds):
        raise ValueError("snapshot-corruption seeds must be unique")
    report_path = args.report.resolve()
    report: dict[str, object] = {
        "schema": "bytecoin-onyx-snapshot-corruption-campaign-v1",
        "scope": "structured-local-or-ci-not-coverage-guided-release-evidence",
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
        "requested_cases_per_seed": args.cases,
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
        artifact = report_path.with_name(f"{report_path.stem}-build.log")
        artifact.write_text(output or str(error), encoding="utf-8")
        report["build"] = {
            "passed": False,
            "error": str(error),
            "failure_log": artifact.name,
            "failure_log_sha256": sha256_file(artifact),
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

    command = [str(executable), TEST_NAME, "--exact", "--nocapture", "--test-threads=1"]
    for seed in seeds:
        environment = os.environ.copy()
        environment["ONYX_SNAPSHOT_CORRUPTION_SEED"] = f"0x{seed:016x}"
        environment["ONYX_SNAPSHOT_CORRUPTION_CASES"] = str(args.cases)
        measured = run_measured(
            command, environment, args.timeout_per_seed, args.sample_interval
        )
        output = str(measured.pop("output"))
        return_code = measured.pop("return_code")
        result: dict[str, object] = {
            "seed": f"0x{seed:016x}",
            **measured,
            "return_code": return_code,
            "output_bytes": len(output.encode("utf-8")),
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
        limit_args = argparse.Namespace(
            timeout_per_case=args.timeout_per_seed,
            max_case_cpu_seconds=args.max_seed_cpu_seconds,
            max_case_rss_mib=args.max_seed_rss_mib,
            max_case_output_mib=args.max_seed_output_mib,
        )
        case_checks = resource_checks(limit_args, result)
        result["checks"] = case_checks
        try:
            if return_code != 0:
                raise ValueError(
                    "campaign timed out"
                    if return_code is None
                    else f"test executable returned {return_code}"
                )
            result["summary"] = parse_result(output, seed, args.cases)
            failed = [name for name, passed in case_checks.items() if not passed]
            if failed:
                raise ValueError(f"resource checks failed: {', '.join(failed)}")
            result["passed"] = True
        except ValueError as error:
            artifact = log_path(report_path, seed)
            artifact.write_text(output, encoding="utf-8")
            result.update(
                {
                    "passed": False,
                    "error": str(error),
                    "failure_log": artifact.name,
                    "failure_log_sha256": sha256_file(artifact),
                }
            )
        report["campaigns"].append(result)
        atomic_write(report_path, report)

    report["completed_at"] = utc_now()
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report["total_requested_cases"] = args.cases * len(seeds)
    report["total_rejected"] = sum(
        campaign.get("summary", {}).get("rejected", 0) for campaign in report["campaigns"]
    )
    report["total_accepted_canonical"] = sum(
        campaign.get("summary", {}).get("accepted_current", 0)
        + campaign.get("summary", {}).get("accepted_migrated", 0)
        for campaign in report["campaigns"]
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
    }
    report["passed"] = all(campaign["passed"] for campaign in report["campaigns"])
    atomic_write(report_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--seed", action="append", type=parse_seed)
    parser.add_argument("--cases", type=int, default=20_000)
    parser.add_argument("--build-timeout", type=float, default=900.0)
    parser.add_argument("--timeout-per-seed", type=float, default=300.0)
    parser.add_argument("--sample-interval", type=float, default=0.05)
    parser.add_argument("--max-seed-cpu-seconds", type=float)
    parser.add_argument("--max-seed-rss-mib", type=float)
    parser.add_argument("--max-seed-output-mib", type=float)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.cases < 64 or args.cases > 1_000_000:
        parser.error("--cases must be in 64..1000000")
    for name in ("build_timeout", "timeout_per_seed", "sample_interval"):
        if getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    for name in ("max_seed_cpu_seconds", "max_seed_rss_mib", "max_seed_output_mib"):
        if getattr(args, name) is not None and getattr(args, name) <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    try:
        return run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
