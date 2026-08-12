#!/usr/bin/env python3
"""Prove that default/release bytecoind artifacts contain no crash-test control."""

import argparse
import pathlib
import subprocess
import tempfile


FORBIDDEN_MARKERS = (
    b"ONYX_CRASH_TEST_POINT=",
    b"--onyx-crash-test-point",
    b"apply-after-state-write",
    b"reorg-after-undo",
    b"ONYX_DB_IOERR",
    b"onyx-fault-vfs",
    b"ioerr-journal-write",
    b"ioerr-database-sync",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    args = parser.parse_args()
    bytecoind = args.bytecoind.resolve()

    image = bytecoind.read_bytes()
    present = [marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in image]
    if present:
        raise RuntimeError(f"release bytecoind contains crash-test markers: {present}")

    with tempfile.TemporaryDirectory(prefix="bytecoin-no-crash-hook-") as temporary:
        result = subprocess.run(
            [
                str(bytecoind),
                "--net=test",
                f"--data-folder={temporary}",
                "--onyx-crash-test-point=apply-after-state-write",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
            check=False,
        )
    rejected_as_unknown = "not recognized" in result.stdout or "has no meaning" in result.stdout
    if result.returncode == 0 or not rejected_as_unknown:
        raise RuntimeError(
            "release bytecoind did not reject the crash-test option as unknown:\n"
            + result.stdout
        )
    print("release bytecoind excludes and rejects Onyx crash-test controls")


if __name__ == "__main__":
    main()
