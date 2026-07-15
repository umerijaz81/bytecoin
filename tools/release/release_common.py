#!/usr/bin/env python3
"""Shared deterministic release helpers; standard-library only."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "release" / "dependencies.lock.json"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=text)


def tracked_files(prefix: str | None = None) -> list[str]:
    args = ["ls-files", "-z"]
    if prefix:
        args.extend(["--", prefix])
    raw = git(*args, text=False)
    assert isinstance(raw, bytes)
    return sorted(part.decode("utf-8") for part in raw.split(b"\0") if part)


def tracked_tree_sha256(prefix: str) -> str:
    digest = hashlib.sha256()
    files = tracked_files(prefix)
    if not files:
        raise ValueError(f"no tracked files below {prefix}")
    for relative in files:
        path = ROOT / relative
        digest.update(relative.replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_lock() -> dict:
    with LOCK_PATH.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def source_date_epoch(revision: str) -> int:
    value = git("show", "-s", "--format=%ct", revision).strip()
    return int(value)


def spdx_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", value)
    return f"SPDXRef-{cleaned}"
