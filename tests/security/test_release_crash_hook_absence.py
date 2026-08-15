#!/usr/bin/env python3
"""Prove that ordinary artifacts contain no non-distributable Onyx controls."""

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
    b"ioerr-journal-partial-write",
    b"ioerr-wal-sync",
    b"ioerr-journal-partial-first",
    b"ioerr-journal-partial-final",
    b"ioerr-database-partial-first",
    b"ioerr-database-partial-final",
    b"ioerr-wal-partial-first",
    b"ioerr-wal-partial-half",
    b"ioerr-wal-partial-final",
    b"qualification_invalid_proof",
    b"onyx_wallet_create_authenticated_invalid_proof_transfer",
    b"onyx_wallet_create_authenticated_invalid_proof_program_deployment",
    b"onyx_wallet_create_authenticated_invalid_proof_standard_program_call",
    b"onyx_wallet_create_authenticated_invalid_proof_token_issuance",
    b"onyx_wallet_create_authenticated_invalid_proof_bridge",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--walletd", type=pathlib.Path)
    args = parser.parse_args()
    bytecoind = args.bytecoind.resolve()

    artifacts = [bytecoind]
    if args.walletd is not None:
        artifacts.append(args.walletd.resolve())
    for artifact in artifacts:
        image = artifact.read_bytes()
        present = [
            marker.decode("ascii") for marker in FORBIDDEN_MARKERS if marker in image
        ]
        if present:
            raise RuntimeError(
                f"ordinary artifact {artifact} contains qualification markers: {present}"
            )

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
    print("ordinary artifacts exclude non-distributable Onyx qualification controls")


if __name__ == "__main__":
    main()
