#!/usr/bin/env python3
"""Run retained deterministic Onyx reference-ledger campaigns under explicit seeds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "vendor" / "onyx-zk" / "Cargo.toml"
TEST_NAME = "state_model_tests::deterministic_state_model_apply_undo_fork_reopen_campaign"
SUMMARY_PREFIX = "ONYX_STATE_MODEL_RESULT "
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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_seed(value: str) -> int:
    seed = int(value, 0)
    if seed <= 0 or seed > (1 << 64) - 1:
        raise argparse.ArgumentTypeError("seed must be in 1..2^64-1")
    return seed


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


def atomic_write(path: pathlib.Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def failure_log_path(report: pathlib.Path, seed: int) -> pathlib.Path:
    return report.with_name(f"{report.stem}-seed-{seed:016x}.log")


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
        "schema": "bytecoin-onyx-state-model-campaign-v1",
        "scope": "deterministic-local-or-ci-not-release-evidence",
        "revision": args.revision,
        "generated_at": utc_now(),
        "manifest": manifest.relative_to(ROOT).as_posix(),
        "manifest_sha256": sha256_file(manifest),
        "lockfile_sha256": sha256_file(lockfile),
        "test": TEST_NAME,
        "requested_steps_per_seed": args.steps,
        "requested_seeds": [f"0x{seed:016x}" for seed in seeds],
        "campaigns": [],
        "passed": False,
    }
    atomic_write(report_path, report)

    command = [
        args.cargo,
        "test",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        str(manifest),
        TEST_NAME,
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]
    started = time.monotonic()
    for seed in seeds:
        environment = os.environ.copy()
        environment["ONYX_STATE_MODEL_SEED"] = f"0x{seed:016x}"
        environment["ONYX_STATE_MODEL_STEPS"] = str(args.steps)
        seed_started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout_per_seed,
                check=False,
            )
            output = completed.stdout
            return_code = completed.returncode
        except subprocess.TimeoutExpired as error:
            output = error.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            return_code = None
        elapsed = round(time.monotonic() - seed_started, 6)
        result: dict[str, object] = {
            "seed": f"0x{seed:016x}",
            "elapsed_seconds": elapsed,
            "return_code": return_code,
            "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }
        try:
            if return_code != 0:
                raise ValueError(
                    "campaign timed out" if return_code is None else f"cargo returned {return_code}"
                )
            result["summary"] = parse_summary(output, seed, args.steps)
            result["passed"] = True
        except ValueError as error:
            log_path = failure_log_path(report_path, seed)
            log_path.write_text(output, encoding="utf-8")
            result.update(
                {
                    "passed": False,
                    "error": str(error),
                    "failure_log": log_path.name,
                    "failure_log_sha256": sha256_file(log_path),
                }
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
    parser.add_argument("--timeout-per-seed", type=float, default=900.0)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.steps < 10 or args.steps > 1_000_000:
        parser.error("--steps must be in 10..1000000")
    if args.timeout_per_seed <= 0:
        parser.error("--timeout-per-seed must be positive")
    try:
        return run_campaign(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
