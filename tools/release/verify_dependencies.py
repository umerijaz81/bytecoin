#!/usr/bin/env python3
"""Fail closed when release dependency identities drift or become incomplete."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import urllib.request

from release_common import HEX_40, HEX_64, ROOT, index_entries, git_blob, load_lock, tracked_tree_sha256


REQUIRED_COMMON = {"name", "version", "kind", "purl"}
ALLOWED_KINDS = {"archive", "git", "vendored", "toolchain"}


def verify() -> list[str]:
    errors: list[str] = []
    lock = load_lock()
    if lock.get("schema_version") != 1:
        errors.append("dependencies.lock.json schema_version must be 1")
    dependencies = lock.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        return errors + ["dependencies must be a non-empty list"]

    names: set[str] = set()
    purls: set[str] = set()
    for index, dependency in enumerate(dependencies):
        label = f"dependencies[{index}]"
        if not isinstance(dependency, dict):
            errors.append(f"{label} must be an object")
            continue
        missing = REQUIRED_COMMON - dependency.keys()
        if missing:
            errors.append(f"{label} missing {sorted(missing)}")
            continue
        name = dependency["name"]
        purl = dependency["purl"]
        kind = dependency["kind"]
        if name in names:
            errors.append(f"duplicate dependency name {name}")
        if purl in purls:
            errors.append(f"duplicate dependency purl {purl}")
        names.add(name)
        purls.add(purl)
        if kind not in ALLOWED_KINDS:
            errors.append(f"{name}: unsupported kind {kind}")
            continue

        if kind == "archive":
            if not str(dependency.get("url", "")).startswith("https://"):
                errors.append(f"{name}: archive URL must use HTTPS")
            if not HEX_64.fullmatch(str(dependency.get("sha256", ""))):
                errors.append(f"{name}: archive sha256 must be 64 lowercase hex characters")
        elif kind == "git":
            revision = str(dependency.get("revision", ""))
            if not str(dependency.get("url", "")).startswith("https://") or not HEX_40.fullmatch(revision):
                errors.append(f"{name}: git source requires an HTTPS URL and full 40-hex revision")
            if dependency.get("version") != revision:
                errors.append(f"{name}: git version must equal its immutable revision")
        elif kind == "vendored":
            relative = str(dependency.get("path", ""))
            path = (ROOT / relative).resolve()
            if not relative or not path.is_dir() or ROOT not in path.parents:
                errors.append(f"{name}: invalid vendored path {relative}")
            else:
                expected = str(dependency.get("tree_sha256", ""))
                actual = tracked_tree_sha256(relative)
                if not HEX_64.fullmatch(expected):
                    errors.append(f"{name}: tree_sha256 must be 64 lowercase hex characters")
                elif actual != expected:
                    errors.append(f"{name}: tracked tree digest {actual} != lock {expected}")
            revision = dependency.get("revision")
            if revision is not None and not HEX_40.fullmatch(str(revision)):
                errors.append(f"{name}: revision must be a full 40-hex commit")
            lockfile = dependency.get("lockfile")
            if lockfile and not (ROOT / str(lockfile)).is_file():
                errors.append(f"{name}: lockfile is missing: {lockfile}")
        elif kind == "toolchain":
            relative = str(dependency.get("path", ""))
            path = ROOT / relative
            expected = str(dependency.get("sha256", ""))
            if not path.is_file():
                errors.append(f"{name}: toolchain descriptor is missing: {relative}")
            elif not HEX_64.fullmatch(expected):
                errors.append(f"{name}: sha256 must be 64 lowercase hex characters")
            else:
                entries = index_entries(relative)
                actual = hashlib.sha256(git_blob(entries[0][2])).hexdigest() if len(entries) == 1 else ""
                if actual != expected:
                    errors.append(f"{name}: descriptor digest does not match the lock")

    required = {"boost", "openssl", "lmdb-bytecoin", "randomx", "onyx-zk", "rust-toolchain"}
    if missing := required - names:
        errors.append(f"release lock missing required dependencies: {sorted(missing)}")
    return errors


def verify_upstream() -> list[str]:
    """Re-fetch immutable external materials. Intended for release tags, not every local build."""
    errors: list[str] = []
    for dependency in load_lock()["dependencies"]:
        name = dependency["name"]
        if dependency["kind"] == "archive":
            digest = hashlib.sha256()
            try:
                with urllib.request.urlopen(dependency["url"], timeout=60) as response:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        digest.update(chunk)
            except Exception as exc:  # Network/certificate failures must fail a release verification.
                errors.append(f"{name}: archive fetch failed: {exc}")
                continue
            if digest.hexdigest() != dependency["sha256"]:
                errors.append(f"{name}: fetched archive digest does not match the lock")
        elif dependency["kind"] == "git":
            try:
                with tempfile.TemporaryDirectory(prefix=f"bytecoin-{name}-") as raw:
                    directory = pathlib.Path(raw)
                    subprocess.run(["git", "init", "--quiet", str(directory)], check=True)
                    subprocess.run(
                        ["git", "-C", str(directory), "fetch", "--quiet", "--depth", "1", dependency["url"], dependency["revision"]],
                        check=True,
                    )
                    actual = subprocess.check_output(
                        ["git", "-C", str(directory), "rev-parse", "FETCH_HEAD"], text=True
                    ).strip()
                    if actual != dependency["revision"]:
                        errors.append(f"{name}: fetched revision {actual} does not match the lock")
            except (OSError, subprocess.CalledProcessError) as exc:
                errors.append(f"{name}: immutable Git fetch failed: {exc}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-tree", metavar="PATH", help="print the tracked tree SHA-256 for lock maintenance")
    parser.add_argument("--verify-upstream", action="store_true", help="download and hash immutable external inputs")
    args = parser.parse_args()
    if args.print_tree:
        print(tracked_tree_sha256(args.print_tree))
        return 0
    errors = verify()
    if not errors and args.verify_upstream:
        errors.extend(verify_upstream())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("release dependency lock verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
