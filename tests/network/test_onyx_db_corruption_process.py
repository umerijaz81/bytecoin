#!/usr/bin/env python3
"""Mutate disposable Onyx SQLite images/journals and require exact recovery or failure."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile
import time
from datetime import datetime, timezone


STATE_KEY = b"Z"
UNDO_KEY = b"z" + b"B" * 32
BEFORE = b"snapshot-before"
AFTER = b"snapshot-after"
PROBE_RESULTS = {0: "exact", 88: "adapter-failure", 89: "semantic-mismatch"}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write(path: pathlib.Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
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
    elapsed = round(time.monotonic() - started, 6)
    if completed.returncode not in allowed:
        raise RuntimeError(
            f"child {mode!r} returned {completed.returncode}, expected {sorted(allowed)}\n"
            f"{completed.stdout}"
        )
    if len(completed.stdout.encode("utf-8")) > 1024 * 1024:
        raise RuntimeError(f"child {mode!r} output exceeded 1 MiB")
    result: dict[str, object] = {
        "mode": mode,
        "return_code": completed.returncode,
        "elapsed_seconds": elapsed,
        "output_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
    }
    if mode.startswith("probe-"):
        classification = PROBE_RESULTS[completed.returncode]
        marker = f"ONYX_DB_PROBE result={classification}"
        if marker not in completed.stdout:
            raise RuntimeError(f"probe output omitted marker {marker!r}: {completed.stdout!r}")
        result["classification"] = classification
    return result


def independent_inspect(database_path: pathlib.Path) -> dict[str, object]:
    try:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            rows = connection.execute(
                "SELECT kk, vv FROM kv_table ORDER BY kk"
            ).fetchall()
        finally:
            connection.close()
        return {
            "opened": True,
            "integrity": integrity,
            "rows": [
                {"key_hex": key.hex(), "value_hex": value.hex()} for key, value in rows
            ],
            "exact_before": rows == [(STATE_KEY, BEFORE)],
            "exact_after": rows == [(STATE_KEY, AFTER), (UNDO_KEY, BEFORE)],
        }
    except sqlite3.DatabaseError as error:
        return {"opened": False, "error": str(error)}


def copy_image(source: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir()
    for path in source.iterdir():
        shutil.copy2(path, destination / path.name)
    return destination / "blockchain"


def mutate_main(path: pathlib.Path, name: str) -> dict[str, object]:
    data = bytearray(path.read_bytes())
    original_size = len(data)
    metadata: dict[str, object] = {"name": name, "original_size": original_size}
    if name == "header-magic-flip":
        data[0] ^= 0x80
        metadata["offset"] = 0
    elif name == "invalid-page-size":
        data[16:18] = b"\x00\x01"
        metadata["offset"] = 16
    elif name == "truncate-header":
        del data[100:]
        metadata["new_size"] = len(data)
    elif name == "truncate-half":
        del data[len(data) // 2 :]
        metadata["new_size"] = len(data)
    elif name == "truncate-final-byte":
        data.pop()
        metadata["new_size"] = len(data)
    elif name in {"state-payload-flip", "undo-payload-flip"}:
        needle = AFTER if name.startswith("state") else BEFORE
        offset = data.find(needle)
        if offset < 0:
            raise RuntimeError(f"could not locate {name} payload")
        offset += len(needle) // 2
        data[offset] ^= 1
        metadata["offset"] = offset
    elif name == "schema-name-flip":
        offset = data.find(b"kv_table")
        if offset < 0:
            raise RuntimeError("could not locate SQLite schema name")
        data[offset] ^= 1
        metadata["offset"] = offset
    else:
        raise ValueError(f"unknown main-image mutation: {name}")
    path.write_bytes(data)
    metadata.update({"size": len(data), "sha256": sha256(path)})
    return metadata


def mutate_journal(path: pathlib.Path, name: str) -> dict[str, object]:
    data = bytearray(path.read_bytes())
    original_size = len(data)
    metadata: dict[str, object] = {"name": name, "original_size": original_size}
    if name == "intact-control":
        pass
    elif name == "header-flip":
        data[0] ^= 0x80
        metadata["offset"] = 0
    elif name == "truncate-empty":
        data.clear()
    elif name == "truncate-half":
        del data[len(data) // 2 :]
    elif name == "truncate-final-byte":
        data.pop()
    elif name == "payload-flip":
        offset = len(data) // 2
        data[offset] ^= 1
        metadata["offset"] = offset
    elif name == "append-garbage":
        data.extend(b"ONYX-CORRUPT-JOURNAL")
    else:
        raise ValueError(f"unknown journal mutation: {name}")
    path.write_bytes(data)
    metadata.update({"size": len(data), "sha256": sha256(path)})
    return metadata


def run_case(
    executable: pathlib.Path,
    source: pathlib.Path,
    cases_root: pathlib.Path,
    family: str,
    name: str,
    timeout: float,
) -> dict[str, object]:
    case_root = cases_root / f"{family}-{name}"
    database_base = copy_image(source, case_root)
    database_path = pathlib.Path(str(database_base) + ".sqlite")
    journal_path = pathlib.Path(str(database_base) + ".sqlite-journal")
    before_hashes = {
        path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
        for path in case_root.iterdir()
    }
    if family == "main":
        mutation = mutate_main(database_path, name)
        independent_before = independent_inspect(database_path)
        child = run_child(executable, database_base, "probe-after", {0, 88, 89}, timeout)
        passed = child["classification"] in {"adapter-failure", "semantic-mismatch"}
    elif family == "journal":
        mutation = mutate_journal(journal_path, name)
        independent_before = None
        child = run_child(executable, database_base, "probe-before", {0, 88, 89}, timeout)
        passed = child["classification"] != "semantic-mismatch"
    else:
        raise ValueError(f"unknown corruption family: {family}")
    independent_after = independent_inspect(database_path)
    if child["classification"] == "exact":
        expected = "exact_after" if family == "main" else "exact_before"
        passed = passed and independent_after.get("integrity") == "ok" and bool(
            independent_after.get(expected)
        )
    after_hashes = {
        path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
        for path in case_root.iterdir()
    }
    return {
        "family": family,
        "name": name,
        "input_images": before_hashes,
        "mutation": mutation,
        "independent_before_probe": independent_before,
        "probe": child,
        "independent_after_probe": independent_after,
        "output_images": after_hashes,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--child-timeout", type=float, default=30.0)
    args = parser.parse_args()
    executable = args.tests.resolve()
    if not executable.is_file():
        parser.error(f"tests executable does not exist: {executable}")
    if args.child_timeout <= 0:
        parser.error("--child-timeout must be positive")

    report: dict[str, object] = {
        "schema": "bytecoin-onyx-db-corruption-v1",
        "scope": "disposable-sqlite-image-local-or-ci-not-power-loss-release-evidence",
        "revision": args.revision,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tests_executable_sha256": sha256(executable),
        "child_timeout_seconds": args.child_timeout,
        "cases": [],
        "passed": False,
    }
    atomic_write(args.report, report)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-db-corruption-") as directory:
        root = pathlib.Path(directory)
        committed = root / "committed-source"
        committed.mkdir()
        committed_base = committed / "blockchain"
        run_child(executable, committed_base, "prepare", {0}, args.child_timeout)
        run_child(executable, committed_base, "crash-after-commit", {87}, args.child_timeout)
        run_child(executable, committed_base, "probe-after", {0}, args.child_timeout)

        hot = root / "hot-journal-source"
        hot.mkdir()
        hot_base = hot / "blockchain"
        run_child(executable, hot_base, "prepare", {0}, args.child_timeout)
        run_child(executable, hot_base, "crash-after-state-write", {85}, args.child_timeout)
        hot_journal = pathlib.Path(str(hot_base) + ".sqlite-journal")
        if not hot_journal.is_file() or hot_journal.stat().st_size == 0:
            raise RuntimeError("crash child did not leave a nonempty rollback journal")

        report["baseline_images"] = {
            "committed": {
                path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
                for path in committed.iterdir()
            },
            "hot_journal": {
                path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
                for path in hot.iterdir()
            },
        }
        cases_root = root / "cases"
        cases_root.mkdir()
        for family, source, names in (
            (
                "main",
                committed,
                (
                    "header-magic-flip",
                    "invalid-page-size",
                    "truncate-header",
                    "truncate-half",
                    "truncate-final-byte",
                    "state-payload-flip",
                    "undo-payload-flip",
                    "schema-name-flip",
                ),
            ),
            (
                "journal",
                hot,
                (
                    "intact-control",
                    "header-flip",
                    "truncate-empty",
                    "truncate-half",
                    "truncate-final-byte",
                    "payload-flip",
                    "append-garbage",
                ),
            ),
        ):
            for name in names:
                try:
                    case = run_case(
                        executable,
                        source,
                        cases_root,
                        family,
                        name,
                        args.child_timeout,
                    )
                except (OSError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
                    case = {"family": family, "name": name, "passed": False, "error": str(error)}
                report["cases"].append(case)
                atomic_write(args.report, report)

    report["completed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    report["elapsed_seconds"] = round(time.monotonic() - started, 6)
    report["classifications"] = {
        classification: sum(
            case.get("probe", {}).get("classification") == classification
            for case in report["cases"]
        )
        for classification in PROBE_RESULTS.values()
    }
    report["passed"] = all(case["passed"] for case in report["cases"])
    atomic_write(args.report, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
