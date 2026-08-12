#!/usr/bin/env python3
"""Exercise bounded Onyx SQLite WAL corruption and checkpoint-bundle recovery."""

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
WAL_HEADER_SIZE = 32
WAL_FRAME_HEADER_SIZE = 24


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write(path: pathlib.Path, document: dict[str, object], max_bytes: int) -> None:
    encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded) > max_bytes:
        raise RuntimeError(f"WAL report exceeded {max_bytes} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)


def image_manifest(directory: pathlib.Path) -> dict[str, dict[str, object]]:
    return {
        path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
        for path in sorted(directory.iterdir())
        if path.is_file()
    }


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
        "elapsed_seconds": elapsed,
        "output_bytes": len(output),
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    if mode.startswith("probe-"):
        classification = PROBE_RESULTS[completed.returncode]
        marker = f"ONYX_DB_PROBE result={classification}"
        if marker not in completed.stdout:
            raise RuntimeError(f"probe omitted marker {marker!r}: {completed.stdout!r}")
        result["classification"] = classification
    return result


def independent_inspect(database_path: pathlib.Path) -> dict[str, object]:
    try:
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
            rows = connection.execute("SELECT kk, vv FROM kv_table ORDER BY kk").fetchall()
        finally:
            connection.close()
        return {
            "opened": True,
            "integrity": integrity,
            "journal_mode": journal_mode,
            "rows": [
                {"key_hex": key.hex(), "value_hex": value.hex()} for key, value in rows
            ],
            "exact_before": rows == [(STATE_KEY, BEFORE)],
            "exact_after": rows == [(STATE_KEY, AFTER), (UNDO_KEY, BEFORE)],
        }
    except sqlite3.DatabaseError as error:
        return {"opened": False, "error": str(error)}


def copy_bundle(source: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    destination.mkdir()
    for path in source.iterdir():
        if path.is_file():
            shutil.copy2(path, destination / path.name)
    return destination / "blockchain"


def wal_layout(data: bytes) -> dict[str, object]:
    if len(data) < WAL_HEADER_SIZE:
        raise RuntimeError("WAL is shorter than its 32-byte header")
    encoded_page_size = int.from_bytes(data[8:12], "big")
    page_size = 65536 if encoded_page_size == 1 else encoded_page_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise RuntimeError(f"invalid WAL page size {page_size}")
    frame_size = WAL_FRAME_HEADER_SIZE + page_size
    complete_frames = (len(data) - WAL_HEADER_SIZE) // frame_size
    commit_ends: list[int] = []
    for index in range(complete_frames):
        offset = WAL_HEADER_SIZE + index * frame_size
        database_pages = int.from_bytes(data[offset + 4 : offset + 8], "big")
        if database_pages != 0:
            commit_ends.append(offset + frame_size)
    return {
        "page_size": page_size,
        "frame_size": frame_size,
        "complete_frames": complete_frames,
        "trailing_bytes": (len(data) - WAL_HEADER_SIZE) % frame_size,
        "commit_ends": commit_ends,
    }


def mutate_wal(path: pathlib.Path, name: str) -> dict[str, object]:
    data = bytearray(path.read_bytes())
    original_size = len(data)
    layout = wal_layout(data)
    metadata: dict[str, object] = {
        "name": name,
        "original_size": original_size,
        "layout_before": layout,
    }
    if name == "intact-control":
        pass
    elif name == "header-magic-flip":
        data[0] ^= 0x80
        metadata["offset"] = 0
    elif name == "header-checksum-flip":
        data[24] ^= 1
        metadata["offset"] = 24
    elif name == "frame-checksum-flip":
        if int(layout["complete_frames"]) == 0:
            raise RuntimeError("WAL has no complete frame")
        data[WAL_HEADER_SIZE + 16] ^= 1
        metadata["offset"] = WAL_HEADER_SIZE + 16
    elif name == "truncate-empty":
        data.clear()
    elif name == "truncate-header":
        del data[WAL_HEADER_SIZE - 1 :]
    elif name == "truncate-first-commit":
        commit_ends = layout["commit_ends"]
        if not commit_ends:
            raise RuntimeError("WAL has no complete commit boundary")
        del data[int(commit_ends[0]) :]
    elif name == "truncate-final-byte":
        data.pop()
    elif name in {"state-payload-flip", "undo-payload-flip"}:
        needle = AFTER if name.startswith("state") else BEFORE
        offset = data.rfind(needle)
        if offset < 0:
            raise RuntimeError(f"could not locate {name} in WAL")
        offset += len(needle) // 2
        data[offset] ^= 1
        metadata["offset"] = offset
    elif name == "append-garbage":
        data.extend(b"ONYX-CORRUPT-WAL")
    else:
        raise ValueError(f"unknown WAL mutation: {name}")
    path.write_bytes(data)
    metadata.update({"size": len(data), "sha256": sha256(path)})
    return metadata


def run_wal_case(
    executable: pathlib.Path,
    source: pathlib.Path,
    cases_root: pathlib.Path,
    name: str,
    timeout: float,
) -> dict[str, object]:
    case_root = cases_root / f"wal-{name}"
    database_base = copy_bundle(source, case_root)
    wal_path = pathlib.Path(str(database_base) + ".sqlite-wal")
    before = image_manifest(case_root)
    mutation = mutate_wal(wal_path, name)
    probe = run_child(executable, database_base, "probe-after", {0, 88, 89}, timeout)
    independent = independent_inspect(pathlib.Path(str(database_base) + ".sqlite"))
    passed = probe["classification"] in {
        "exact",
        "adapter-failure",
        "semantic-mismatch",
    }
    if probe["classification"] == "exact":
        passed = (
            independent.get("integrity") == "ok"
            and bool(independent.get("exact_after"))
        )
    return {
        "family": "wal",
        "name": name,
        "input_images": before,
        "mutation": mutation,
        "probe": probe,
        "independent_after_probe": independent,
        "output_images": image_manifest(case_root),
        "passed": passed,
    }


def assemble_mix(
    destination: pathlib.Path,
    main_source: pathlib.Path,
    sidecar_source: pathlib.Path,
    include_wal: bool,
    include_shm: bool,
) -> pathlib.Path:
    destination.mkdir()
    shutil.copy2(main_source / "blockchain.sqlite", destination / "blockchain.sqlite")
    for suffix, include in (("-wal", include_wal), ("-shm", include_shm)):
        source = sidecar_source / f"blockchain.sqlite{suffix}"
        if include and source.is_file():
            shutil.copy2(source, destination / source.name)
    return destination / "blockchain"


def run_mix_case(
    executable: pathlib.Path,
    pre_checkpoint: pathlib.Path,
    post_checkpoint: pathlib.Path,
    cases_root: pathlib.Path,
    name: str,
    timeout: float,
) -> dict[str, object]:
    case_root = cases_root / f"mix-{name}"
    if name == "pre-main-no-sidecars":
        database_base = assemble_mix(case_root, pre_checkpoint, pre_checkpoint, False, False)
    elif name == "pre-main-wal-no-shm":
        database_base = assemble_mix(case_root, pre_checkpoint, pre_checkpoint, True, False)
    elif name == "post-main-pre-sidecars":
        database_base = assemble_mix(case_root, post_checkpoint, pre_checkpoint, True, True)
    elif name == "post-main-pre-wal-no-shm":
        database_base = assemble_mix(case_root, post_checkpoint, pre_checkpoint, True, False)
    else:
        raise ValueError(f"unknown checkpoint mix: {name}")
    before = image_manifest(case_root)
    probe = run_child(executable, database_base, "probe-after", {0, 88, 89}, timeout)
    independent = independent_inspect(pathlib.Path(str(database_base) + ".sqlite"))
    passed = probe["classification"] in {
        "exact",
        "adapter-failure",
        "semantic-mismatch",
    }
    if probe["classification"] == "exact":
        passed = (
            independent.get("integrity") == "ok"
            and bool(independent.get("exact_after"))
        )
    return {
        "family": "checkpoint-mix",
        "name": name,
        "input_images": before,
        "probe": probe,
        "independent_after_probe": independent,
        "output_images": image_manifest(case_root),
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tests", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--child-timeout", type=float, default=30.0)
    parser.add_argument("--max-report-mib", type=float, default=8.0)
    args = parser.parse_args()
    executable = args.tests.resolve()
    if not executable.is_file():
        parser.error(f"tests executable does not exist: {executable}")
    if args.child_timeout <= 0 or args.max_report_mib <= 0:
        parser.error("timeouts and report limits must be positive")
    max_report_bytes = int(args.max_report_mib * 1024 * 1024)

    report: dict[str, object] = {
        "schema": "bytecoin-onyx-db-wal-campaign-v1",
        "scope": "disposable-sqlite-wal-checkpoint-mix-local-or-ci-not-power-loss-release-evidence",
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
    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-db-wal-") as directory:
        root = pathlib.Path(directory)
        pre_checkpoint = root / "pre-checkpoint"
        pre_checkpoint.mkdir()
        pre_base = pre_checkpoint / "blockchain"
        run_child(executable, pre_base, "wal-prepare", {90}, args.child_timeout)
        run_child(executable, pre_base, "wal-commit-after", {91}, args.child_timeout)
        wal_path = pathlib.Path(str(pre_base) + ".sqlite-wal")
        if not wal_path.is_file() or wal_path.stat().st_size <= WAL_HEADER_SIZE:
            raise RuntimeError("WAL fixture has no retained frames")

        post_checkpoint = root / "post-checkpoint"
        post_base = copy_bundle(pre_checkpoint, post_checkpoint)
        run_child(executable, post_base, "wal-checkpoint", {0}, args.child_timeout)
        run_child(executable, post_base, "probe-after", {0}, args.child_timeout)
        report["baseline_images"] = {
            "pre_checkpoint": image_manifest(pre_checkpoint),
            "post_checkpoint": image_manifest(post_checkpoint),
            "wal_layout": wal_layout(wal_path.read_bytes()),
        }
        cases_root = root / "cases"
        cases_root.mkdir()
        for name in (
            "intact-control",
            "header-magic-flip",
            "header-checksum-flip",
            "frame-checksum-flip",
            "truncate-empty",
            "truncate-header",
            "truncate-first-commit",
            "truncate-final-byte",
            "state-payload-flip",
            "undo-payload-flip",
            "append-garbage",
        ):
            try:
                case = run_wal_case(
                    executable, pre_checkpoint, cases_root, name, args.child_timeout
                )
            except (OSError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
                case = {"family": "wal", "name": name, "passed": False, "error": str(error)}
            report["cases"].append(case)
            atomic_write(args.report, report, max_report_bytes)
        for name in (
            "pre-main-no-sidecars",
            "pre-main-wal-no-shm",
            "post-main-pre-sidecars",
            "post-main-pre-wal-no-shm",
        ):
            try:
                case = run_mix_case(
                    executable,
                    pre_checkpoint,
                    post_checkpoint,
                    cases_root,
                    name,
                    args.child_timeout,
                )
            except (OSError, RuntimeError, sqlite3.DatabaseError, subprocess.SubprocessError) as error:
                case = {
                    "family": "checkpoint-mix",
                    "name": name,
                    "passed": False,
                    "error": str(error),
                }
            report["cases"].append(case)
            atomic_write(args.report, report, max_report_bytes)

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
    atomic_write(args.report, report, max_report_bytes)
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "passed": report["passed"],
                "case_count": len(report["cases"]),
                "classifications": report["classifications"],
                "elapsed_seconds": report["elapsed_seconds"],
                "report": str(args.report),
            },
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
