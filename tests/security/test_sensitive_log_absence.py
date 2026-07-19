#!/usr/bin/env python3
"""Reject known walletd log formats that serialize privacy-sensitive RPC bodies."""

import argparse
import pathlib


FORBIDDEN_LOG_MARKERS = (
    b"start of body=",
    b"sending get_random_outputs, body=",
    b"sending get_raw_transaction, body=",
)

FORBIDDEN_SOURCE_PATTERNS = (
    "<< raw_request.body",
    "<< new_request.body",
    "<< random_response.body",
    "<< raw_transaction_response.body",
    "request.body.substr(0, 200)",
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    image = args.walletd.resolve().read_bytes()
    present = [marker.decode("ascii") for marker in FORBIDDEN_LOG_MARKERS if marker in image]
    if present:
        raise RuntimeError(f"walletd contains privacy-sensitive log formats: {present}")
    source = (pathlib.Path(__file__).resolve().parents[2] / "src/Core/WalletNode.cpp").read_text(
        encoding="utf-8"
    )
    source_present = [pattern for pattern in FORBIDDEN_SOURCE_PATTERNS if pattern in source]
    if source_present:
        raise RuntimeError(f"WalletNode contains privacy-sensitive body logging: {source_present}")
    print("walletd artifact contains no known privacy-sensitive RPC body log formats")


if __name__ == "__main__":
    main()
