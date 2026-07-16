#!/usr/bin/env python3
"""Compare normalized platform binaries and emit deterministic release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


PROGRAMS = ("bytecoind", "walletd", "minerd")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def resolve_program(directory: Path, program: str) -> Path:
    candidates = (directory / program, directory / f"{program}.exe")
    present = [candidate for candidate in candidates if candidate.is_file()]
    if len(present) != 1:
        raise ValueError(f"expected exactly one {program} executable in {directory}")
    return present[0]


def compare(first: Path, second: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for program in PROGRAMS:
        left = resolve_program(first, program)
        right = resolve_program(second, program)
        left_digest = digest(left)
        right_digest = digest(right)
        if left.read_bytes() != right.read_bytes():
            raise ValueError(
                f"{program} is not reproducible: {left_digest} != {right_digest}"
            )
        results.append({"name": left.name, "sha256": left_digest, "size": left.stat().st_size})
    return results


def command_version(command: list[str]) -> str:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).splitlines()[0]
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch is None or not source_date_epoch.isdigit():
        print("ERROR: numeric SOURCE_DATE_EPOCH is required", file=sys.stderr)
        return 1
    try:
        binaries = compare(args.first, args.second)
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    document = {
        "schema_version": 1,
        "revision": args.revision,
        "source_date_epoch": source_date_epoch,
        "platform": platform.platform(),
        "compiler": os.environ.get("CXX_DESCRIPTION")
        or command_version([os.environ.get("CXX", "c++"), "--version"]),
        "cmake": command_version(["cmake", "--version"]),
        "rustc": command_version(["rustc", "--version"]),
        "binaries": binaries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"verified {len(binaries)} byte-for-byte reproducible executables")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
