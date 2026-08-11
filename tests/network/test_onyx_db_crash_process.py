#!/usr/bin/env python3
"""Kill a real SQLite writer at Onyx state/undo transaction boundaries and verify recovery."""

import argparse
import hashlib
import json
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


STATE_KEY = b"Z"
UNDO_KEY = b"z" + b"B" * 32
BEFORE = b"snapshot-before"
AFTER = b"snapshot-after"


def run_child(executable, database_base, mode, expected):
    command = [
        str(executable),
        f"--db-crash-child={mode}",
        f"--db-crash-path={database_base}",
    ]
    completed = subprocess.run(command, check=False, timeout=30)
    if completed.returncode != expected:
        raise RuntimeError(
            f"child mode {mode!r} returned {completed.returncode}, expected {expected}"
        )
    return {"mode": mode, "return_code": completed.returncode}


def inspect_database(database_path, expected_rows):
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        rows = connection.execute("SELECT kk, vv FROM kv_table ORDER BY kk").fetchall()
    finally:
        connection.close()
    if integrity != "ok":
        raise RuntimeError(f"SQLite integrity check failed: {integrity}")
    if rows != expected_rows:
        raise RuntimeError(f"unexpected recovered rows: {rows!r} != {expected_rows!r}")
    return {
        "integrity": integrity,
        "rows": [
            {"key_hex": key.hex(), "value_hex": value.hex()} for key, value in rows
        ],
    }


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    executable = args.tests.resolve()
    if not executable.is_file():
        parser.error(f"tests executable does not exist: {executable}")

    children = []
    checks = {}
    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-db-crash-") as directory:
        database_base = Path(directory) / "blockchain"
        database_path = Path(str(database_base) + ".sqlite")

        children.append(run_child(executable, database_base, "prepare", 0))
        children.append(
            run_child(executable, database_base, "crash-after-state-write", 85)
        )
        children.append(run_child(executable, database_base, "verify-before", 0))
        checks["partial_state_write_rolled_back"] = inspect_database(
            database_path, [(STATE_KEY, BEFORE)]
        )

        children.append(run_child(executable, database_base, "prepare", 0))
        children.append(run_child(executable, database_base, "crash-before-commit", 86))
        children.append(run_child(executable, database_base, "verify-before", 0))
        checks["complete_uncommitted_pair_rolled_back"] = inspect_database(
            database_path, [(STATE_KEY, BEFORE)]
        )

        children.append(run_child(executable, database_base, "prepare", 0))
        children.append(run_child(executable, database_base, "crash-after-commit", 87))
        children.append(run_child(executable, database_base, "verify-after", 0))
        checks["committed_state_undo_pair_recovered"] = inspect_database(
            database_path, [(STATE_KEY, AFTER), (UNDO_KEY, BEFORE)]
        )
        database_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()

    report = {
        "schema": "bytecoin-onyx-db-crash-v1",
        "scope": "local-process-crash-not-release-evidence",
        "revision": args.revision,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "children": children,
        "checks": {name: True for name in checks},
        "observed": checks,
        "final_database_sha256": database_sha256,
        "passed": True,
    }
    write_report(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
