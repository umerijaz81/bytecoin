#!/usr/bin/env python3
"""Shared deterministic release helpers; standard-library only."""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "release" / "dependencies.lock.json"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class DuplicateJsonKey(ValueError):
    pass


class NonFiniteJsonNumber(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise NonFiniteJsonNumber(f"non-finite JSON number: {value}")


def _strict_json_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise NonFiniteJsonNumber(f"JSON number exceeds finite range: {value}")
    return result


def strict_json_loads(value: str | bytes | bytearray) -> object:
    return json.loads(
        value,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
        parse_float=_strict_json_float,
    )


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str, text: bool = True) -> str | bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=text)


def index_entries(prefix: str | None = None) -> list[tuple[str, str, str]]:
    """Return (path, mode, object id) entries without checkout/EOL conversion."""
    args = ["ls-files", "-s", "-z"]
    if prefix:
        args.extend(["--", prefix])
    raw = git(*args, text=False)
    assert isinstance(raw, bytes)
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        if stage != "0":
            raise ValueError(f"unmerged index entry: {raw_path.decode('utf-8')}")
        entries.append((raw_path.decode("utf-8"), mode, object_id))
    return sorted(entries)


def revision_entries(revision: str) -> list[tuple[str, str, str]]:
    """Return (path, mode, object id) entries from an immutable Git tree."""
    raw = git("ls-tree", "-r", "-z", revision, text=False)
    assert isinstance(raw, bytes)
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        if object_type != "blob":
            raise ValueError(
                f"unsupported Git tree entry type {object_type} at "
                f"{raw_path.decode('utf-8')}"
            )
        entries.append((raw_path.decode("utf-8"), mode, object_id))
    return sorted(entries)


def git_blob(object_id: str) -> bytes:
    value = git("cat-file", "blob", object_id, text=False)
    assert isinstance(value, bytes)
    return value


def git_blobs(object_ids: list[str]) -> list[bytes]:
    """Read many blobs in one process; output order matches object_ids."""
    if not object_ids:
        return []
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output, error = process.communicate("".join(f"{item}\n" for item in object_ids).encode("ascii"))
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, process.args, output, error)
    result = []
    cursor = 0
    for expected in object_ids:
        line_end = output.index(b"\n", cursor)
        actual, object_type, raw_size = output[cursor:line_end].decode("ascii").split()
        if actual != expected or object_type != "blob":
            raise ValueError(f"unexpected Git object response for {expected}")
        size = int(raw_size)
        start = line_end + 1
        end = start + size
        result.append(output[start:end])
        cursor = end + 1  # cat-file terminates every batch object with a newline.
    return result


def revision_file(revision: str, relative: str) -> bytes:
    value = git("show", f"{revision}:{relative}", text=False)
    assert isinstance(value, bytes)
    return value


def revision_file_sha256(revision: str, relative: str) -> str:
    return hashlib.sha256(revision_file(revision, relative)).hexdigest()


def tracked_files(prefix: str | None = None) -> list[str]:
    args = ["ls-files", "-z"]
    if prefix:
        args.extend(["--", prefix])
    raw = git(*args, text=False)
    assert isinstance(raw, bytes)
    return sorted(part.decode("utf-8") for part in raw.split(b"\0") if part)


def tracked_tree_sha256(prefix: str) -> str:
    """Hash canonical index blobs, never platform-dependent checkout bytes."""
    digest = hashlib.sha256()
    entries = index_entries(prefix)
    if not entries:
        raise ValueError(f"no tracked files below {prefix}")
    blobs = git_blobs([object_id for _, _, object_id in entries])
    for (relative, mode, _), blob in zip(entries, blobs):
        digest.update(mode.encode("ascii"))
        digest.update(b"\0")
        digest.update(relative.replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(blob).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def load_lock() -> dict:
    value = strict_json_loads(LOCK_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("dependency lock must contain a JSON object")
    return value


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def source_date_epoch(revision: str) -> int:
    value = git("show", "-s", "--format=%ct", revision).strip()
    return int(value)


def spdx_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", value)
    return f"SPDXRef-{cleaned}"
