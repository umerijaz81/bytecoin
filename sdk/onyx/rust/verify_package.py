#!/usr/bin/env python3
"""Verify deterministic, complete Bytecoin Onyx Rust SDK crate archives."""

from __future__ import annotations

import hashlib
import pathlib
import sys
import tarfile


ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE = "bytecoin-onyx-sdk-1.1.0"
REQUIRED = {
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "COMPATIBILITY.md",
    "README.md",
    "src/lib.rs",
    "tests/conformance.rs",
    "wallet-rpc-v1.json",
}


def crate(directory: pathlib.Path) -> pathlib.Path:
    matches = sorted(directory.glob("bytecoin-onyx-sdk-*.crate"))
    if len(matches) != 1:
        raise SystemExit(f"{directory}: expected exactly one Rust SDK crate, found {len(matches)}")
    return matches[0]


def verify_archive(path: pathlib.Path) -> bytes:
    data = path.read_bytes()
    with tarfile.open(path, "r:gz") as archive:
        names = {
            name.removeprefix(PACKAGE + "/")
            for name in archive.getnames()
            if name.startswith(PACKAGE + "/")
        }
        missing = REQUIRED - names
        if missing:
            raise SystemExit(f"{path}: package is missing {sorted(missing)}")
        profile = archive.extractfile(f"{PACKAGE}/wallet-rpc-v1.json")
        if profile is None or profile.read() != (ROOT.parent / "v1" / "wallet-rpc.json").read_bytes():
            raise SystemExit(f"{path}: packaged wallet RPC profile differs from frozen v1 source")
    return data


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: verify_package.py CRATE_DIRECTORY [CRATE_DIRECTORY ...]")
    archives = [crate(pathlib.Path(value)) for value in sys.argv[1:]]
    payloads = [verify_archive(path) for path in archives]
    expected = payloads[0]
    if any(payload != expected for payload in payloads[1:]):
        digests = [hashlib.sha256(payload).hexdigest() for payload in payloads]
        raise SystemExit(f"Rust SDK crate archives are not byte-reproducible: {digests}")
    print(f"Rust SDK crate verified: sha256={hashlib.sha256(expected).hexdigest()}")


if __name__ == "__main__":
    main()
