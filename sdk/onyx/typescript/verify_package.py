#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path


ONYX_ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "package/package.json",
    "package/index.js",
    "package/index.d.ts",
    "package/wallet-rpc-v1.json",
    "package/README.md",
    "package/COMPATIBILITY.md",
}


def archive(directory: Path) -> Path:
    packages = list(directory.glob("bytecoin-onyx-sdk-*.tgz"))
    if len(packages) != 1:
        raise ValueError(f"expected one npm package in {directory}, found {len(packages)}")
    return packages[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    first, second = archive(args.first), archive(args.second)
    if first.read_bytes() != second.read_bytes():
        raise SystemExit("npm packages are not byte-for-byte reproducible")
    with tarfile.open(first, "r:gz") as package:
        names = set(package.getnames())
        if not REQUIRED <= names:
            raise SystemExit(f"npm package is missing: {sorted(REQUIRED - names)}")
        metadata = json.load(package.extractfile("package/package.json"))
        profile = json.load(package.extractfile("package/wallet-rpc-v1.json"))
    source_profile = json.loads((ONYX_ROOT / "v1" / "wallet-rpc.json").read_text(encoding="utf-8"))
    if metadata.get("name") != "@bytecoin/onyx-sdk" or metadata.get("version") != "1.0.0":
        raise SystemExit("npm package identity is invalid")
    if profile != source_profile:
        raise SystemExit("packaged wallet RPC contract differs from frozen v1 profile")
    print("verified reproducible Onyx TypeScript SDK package")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
