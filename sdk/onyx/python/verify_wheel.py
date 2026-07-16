"""Validate the distributable Onyx SDK wheel without installing it."""

from __future__ import annotations

import email.parser
import json
import pathlib
import sys
import zipfile


EXPECTED_FILES = {
    "onyx_sdk.py",
    "bytecoin_onyx/__init__.py",
    "bytecoin_onyx/rpc.py",
    "bytecoin_onyx/wallet_rpc_v1.json",
}


def verify(wheel_directory: pathlib.Path) -> None:
    wheels = list(wheel_directory.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")

    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        missing = sorted(EXPECTED_FILES - names)
        if missing:
            raise RuntimeError("wheel is missing: " + ", ".join(missing))

        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise RuntimeError("wheel must contain exactly one METADATA file")
        metadata = email.parser.Parser().parsestr(
            archive.read(metadata_names[0]).decode("utf-8")
        )
        expected_metadata = {
            "Name": "bytecoin-onyx-sdk",
            "Version": "1.0.0",
            "Requires-Python": ">=3.9",
            "License": "LGPL-3.0-or-later",
        }
        for key, expected in expected_metadata.items():
            if metadata.get(key) != expected:
                raise RuntimeError(
                    f"unexpected {key}: {metadata.get(key)!r} (expected {expected!r})"
                )

        packaged_profile = json.loads(
            archive.read("bytecoin_onyx/wallet_rpc_v1.json").decode("utf-8")
        )
        source_profile = json.loads(
            (pathlib.Path(__file__).parent.parent / "v1" / "wallet-rpc.json").read_text(
                encoding="utf-8"
            )
        )
        if packaged_profile != source_profile:
            raise RuntimeError("wheel RPC profile differs from the v1 source contract")

    print(f"verified {wheels[0]}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_wheel.py WHEEL_DIRECTORY")
    verify(pathlib.Path(sys.argv[1]))
