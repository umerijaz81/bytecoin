#!/usr/bin/env python3
"""Prove that default/release walletd artifacts contain no hardware emulator."""

import argparse
import pathlib
import subprocess
import tempfile


FORBIDDEN_MARKERS = (
    b"Emulator, mnemonic=",
    b"bip44 child private key",
    b"m_audit_key_base_secret_key",
    b"output_secret_scalar=",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    walletd = args.walletd.resolve()

    image = walletd.read_bytes()
    present = [marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in image]
    if present:
        raise RuntimeError(f"release walletd contains hardware-emulator secret markers: {present}")

    with tempfile.TemporaryDirectory(prefix="bytecoin-no-emulator-") as temporary:
        result = subprocess.run(
            [
                str(walletd),
                "--net=test",
                f"--data-folder={temporary}",
                "--emulate-hardware-wallet=not-a-real-mnemonic",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
    if "unavailable in release builds" not in result.stdout:
        raise RuntimeError(f"release walletd did not fail closed for emulator option:\n{result.stdout}")
    print("release walletd excludes and rejects the hardware-wallet emulator")


if __name__ == "__main__":
    main()
