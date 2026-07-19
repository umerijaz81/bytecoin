#!/usr/bin/env python3
"""Process-level checks for walletd authentication secret handling."""

import argparse
import os
import pathlib
import stat
import subprocess
import tempfile


def run(walletd, *arguments):
    return subprocess.run(
        [str(walletd), *map(str, arguments)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
        check=False,
    )


def require_output(result, expected):
    if expected not in result.stdout:
        raise RuntimeError(f"expected {expected!r} in walletd output:\n{result.stdout}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    walletd = args.walletd.resolve()

    help_result = run(walletd, "--help")
    require_output(help_result, "--walletd-http-auth-file=<file-path>")

    with tempfile.TemporaryDirectory(prefix="bytecoin-wallet-auth-") as temporary:
        root = pathlib.Path(temporary)
        data = root / "data"
        (data / "logs").mkdir(parents=True)
        run_wallet = lambda *arguments: run(
            walletd, "--net=test", f"--data-folder={data}", *arguments
        )
        credential = root / "walletd.auth"
        secret = "rpc-user:a-long-test-password"
        credential.write_text(secret + "\n", encoding="utf-8")
        credential.chmod(stat.S_IRUSR | stat.S_IWUSR)

        accepted = run_wallet(f"--walletd-http-auth-file={credential}")
        require_output(accepted, "--wallet-file=<file> is mandatory")
        if secret in accepted.stdout:
            raise RuntimeError("walletd echoed the authentication secret")

        legacy = run_wallet("--walletd-http-auth=legacy:secret")
        require_output(legacy, "was removed because it exposes credentials")

        oversized = root / "oversized.auth"
        oversized.write_bytes(b"a:" + b"x" * 4096)
        oversized.chmod(stat.S_IRUSR | stat.S_IWUSR)
        require_output(run_wallet(f"--walletd-http-auth-file={oversized}"), "exceeds 4096 bytes")

        if os.name != "nt":
            credential.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            require_output(
                run_wallet(f"--walletd-http-auth-file={credential}"),
                "must not be accessible by group or other users",
            )

    print("walletd authentication file and legacy-secret rejection policy passed")


if __name__ == "__main__":
    main()
