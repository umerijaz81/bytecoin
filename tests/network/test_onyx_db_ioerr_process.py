#!/usr/bin/env python3
"""Require exact Onyx recovery after test-only SQLite write and sync I/O faults."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone


STATE_KEY = b"Z"
UNDO_KEY = b"z" + b"B" * 32
BEFORE = b"snapshot-before"
AFTER = b"snapshot-after"
SQLITE_IOERR_WRITE = 778
SQLITE_IOERR_FSYNC = 1034
IOERR_MARKER = re.compile(
    r"ONYX_DB_IOERR target=(journal|database) operation=(write|sync) "
    r"stage=(state|undo|commit) sqlite_code=(\d+) triggers=(\d+)"
)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def image_manifest(directory: pathlib.Path) -> dict[str, dict[str, object]]:
    return {
        path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


def atomic_write(path: pathlib.Path, document: dict[str, object], max_bytes: int) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > max_bytes:
        raise RuntimeError(f"I/O-fault report exceeded {max_bytes} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)


def run_child(
    executable: pathlib.Path,
    database_base: pathlib.Path,
    mode: str,
    allowed: set[int],
    timeout: float,
) -> dict[str, object]:
    command = [
        str(executable),
        f"--db-crash-child={mode}",
        f"--db-crash-path={database_base}",
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout.encode("utf-8")
    if completed.returncode not in allowed:
        raise RuntimeError(
            f"child {mode!r} returned {completed.returncode}, expected {sorted(allowed)}\n"
            f"{completed.stdout}"
        )
    if len(output) > 1024 * 1024:
        raise RuntimeError(f"child {mode!r} output exceeded 1 MiB")
    result: dict[str, object] = {
        "mode": mode,
        "return_code": completed.returncode,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "output_bytes": len(output),
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    if mode.startswith("ioerr-"):
        marker = IOERR_MARKER.search(completed.stdout)
        if marker is None:
            raise RuntimeError(f"I/O-fault child omitted its result marker: {completed.stdout!r}")
        result.update(
            {
                "target": marker.group(1),
                "operation": marker.group(2),
                "stage": marker.group(3),
                "sqlite_extended_code": int(marker.group(4)),
                "sqlite_primary_code": int(marker.group(4)) & 0xFF,
                "trigger_count": int(marker.group(5)),
            }
        )
    if mode.startswith("probe-") and "ONYX_DB_PROBE result=exact" not in completed.stdout:
        raise RuntimeError(f"recovery probe omitted exact marker: {completed.stdout!r}")
    return result


def inspect_database(database_path: pathlib.Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        rows = connection.execute("SELECT kk, vv FROM kv_table ORDER BY kk").fetchall()
    finally:
        connection.close()
    return {
        "integrity": integrity,
        "rows": [{"key_hex": key.hex(), "value_hex": value.hex()} for key, value in rows],
        "exact_before": rows == [(STATE_KEY, BEFORE)],
        "exact_after": rows == [(STATE_KEY, AFTER), (UNDO_KEY, BEFORE)],
    }


def fault_case_passed(case: dict[str, object]) -> bool:
    fault = case.get("fault", {})
    recovery = case.get("recovery", {})
    independent_before = case.get("independent_before", {})
    independent_after = case.get("independent_after", {})
    return bool(
        fault.get("sqlite_primary_code") == 10
        and fault.get("sqlite_extended_code") == case.get("expected_extended_code")
        and fault.get("trigger_count") == 1
        and fault.get("target") == case.get("expected_target")
        and fault.get("operation") == case.get("expected_operation")
        and fault.get("stage") == case.get("expected_stage")
        and recovery.get("return_code") == 0
        and independent_before.get("exact_before") is True
        and independent_after.get("integrity") == "ok"
        and independent_after.get("exact_before") is True
    )


def run_fault_case(
    executable: pathlib.Path,
    root: pathlib.Path,
    name: str,
    expected_exit: int,
    expected_target: str,
    expected_operation: str,
    expected_stage: str,
    expected_code: int,
    timeout: float,
) -> dict[str, object]:
    case_root = root / name
    case_root.mkdir()
    database_base = case_root / "blockchain"
    database_path = pathlib.Path(str(database_base) + ".sqlite")
    prepare = run_child(executable, database_base, "prepare", {0}, timeout)
    independent_before = inspect_database(database_path)
    input_images = image_manifest(case_root)
    fault = run_child(executable, database_base, name, {expected_exit}, timeout)
    images_after_fault = image_manifest(case_root)
    recovery = run_child(executable, database_base, "probe-before", {0}, timeout)
    independent_after = inspect_database(database_path)
    case: dict[str, object] = {
        "family": "sqlite-ioerr",
        "name": name,
        "expected_target": expected_target,
        "expected_operation": expected_operation,
        "expected_stage": expected_stage,
        "expected_extended_code": expected_code,
        "prepare": prepare,
        "independent_before": independent_before,
        "input_images": input_images,
        "fault": fault,
        "images_after_fault": images_after_fault,
        "recovery": recovery,
        "independent_after": independent_after,
        "output_images": image_manifest(case_root),
    }
    case["passed"] = fault_case_passed(case)
    return case


def run_control(executable: pathlib.Path, root: pathlib.Path, timeout: float) -> dict[str, object]:
    case_root = root / "committed-control"
    case_root.mkdir()
    database_base = case_root / "blockchain"
    database_path = pathlib.Path(str(database_base) + ".sqlite")
    prepare = run_child(executable, database_base, "prepare", {0}, timeout)
    commit = run_child(executable, database_base, "crash-after-commit", {87}, timeout)
    recovery = run_child(executable, database_base, "probe-after", {0}, timeout)
    independent = inspect_database(database_path)
    return {
        "family": "control",
        "name": "committed-control",
        "prepare": prepare,
        "commit": commit,
        "recovery": recovery,
        "independent_after": independent,
        "output_images": image_manifest(case_root),
        "passed": independent["integrity"] == "ok" and independent["exact_after"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--child-timeout", type=float, default=30.0)
    parser.add_argument("--max-report-mib", type=float, default=4.0)
    args = parser.parse_args()
    executable = args.tests.resolve()
    if not executable.is_file():
        parser.error(f"tests executable does not exist: {executable}")
    if args.child_timeout <= 0 or args.max_report_mib <= 0:
        parser.error("timeouts and report limits must be positive")
    max_report_bytes = int(args.max_report_mib * 1024 * 1024)
    report: dict[str, object] = {
        "schema": "bytecoin-onyx-db-ioerr-campaign-v1",
        "scope": "compile-time-test-vfs-single-write-or-sync-fault-local-or-ci-not-device-release-evidence",
        "revision": args.revision,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tests_executable_sha256": sha256(executable),
        "child_timeout_seconds": args.child_timeout,
        "max_report_bytes": max_report_bytes,
        "cases": [],
        "passed": False,
    }
    atomic_write(args.report, report, max_report_bytes)
    started = time.monotonic()
    specifications = (
        ("ioerr-journal-write", 96, "journal", "write", "state", SQLITE_IOERR_WRITE),
        ("ioerr-journal-sync", 97, "journal", "sync", "commit", SQLITE_IOERR_FSYNC),
        ("ioerr-database-write", 98, "database", "write", "commit", SQLITE_IOERR_WRITE),
        ("ioerr-database-sync", 99, "database", "sync", "commit", SQLITE_IOERR_FSYNC),
    )
    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-db-ioerr-") as directory:
        root = pathlib.Path(directory)
        for specification in specifications:
            name = specification[0]
            try:
                case = run_fault_case(executable, root, *specification, args.child_timeout)
            except (OSError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
                case = {"family": "sqlite-ioerr", "name": name, "passed": False, "error": str(error)}
            report["cases"].append(case)
            atomic_write(args.report, report, max_report_bytes)
        try:
            control = run_control(executable, root, args.child_timeout)
        except (OSError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
            control = {"family": "control", "name": "committed-control", "passed": False, "error": str(error)}
        report["cases"].append(control)

    report["completed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report["passed"] = all(case["passed"] for case in report["cases"])
    atomic_write(args.report, report, max_report_bytes)
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "passed": report["passed"],
                "case_count": len(report["cases"]),
                "elapsed_seconds": report["elapsed_seconds"],
                "report": str(args.report),
            },
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
