#!/usr/bin/env python3
"""Generate the deterministic starter corpus for the Bytecoin libFuzzer harness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


SELECTORS = tuple(range(17)) + tuple(range(128, 139)) + tuple(range(200, 207))


KV_HEADER = bytes.fromhex("011101010101020101")


def seeds() -> list[bytes]:
    corpus = [bytes((selector,)) for selector in SELECTORS]
    corpus.extend(
        [
            b"\x10\x05\x00",  # SOCKS5 no-auth method response
            b"\x10\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",  # IPv4 CONNECT response
            b"\x10\x05\x00\x00\x03\x03i2p\x00\x50",  # domain CONNECT response
            b"\xc8null",
            b"\xc8{}",
            b"\xc8[]",
            b"\xc8{\"jsonrpc\":\"2.0\",\"id\":1}",
            b"\xc8{\"method\":\"a\",\"\\u006dethod\":\"b\"}",
            b"\xc8\"\\ud83d\\ude00\"",
            b"\xc8\"\\ud800\"",
            b"\xc8\"\xed\xa0\x80\"",
            b"\xc9invalid-address",
            b"\x8a\x00",  # canonical empty compact-binary vector
            b"\x8a\x80\x80\x40",  # compact vector count 1,048,576 in a truncated input
            b"\x00" + KV_HEADER + b"\x00",  # canonical empty KV root, typed request is incomplete
            b"\x00" + KV_HEADER + b"\x01\x00",  # non-minimal word encoding of empty KV root
            b"\x00" + KV_HEADER
            + b"\x08\x01a\x08\x01\x01a\x08\x02",  # duplicate KV object key
            b"\x00" + KV_HEADER
            + b"\x04\x01s\x0a\x06\x00\x00\x10",  # declared 64 MiB + 1 KV string
            b"\xca\x01",  # malformed Onyx envelopes retain their version byte
            b"\xcb\x01",
            b"\xcc\x01",
            b"\xcd\x01",
            b"\xce\x07\x20",  # truncated Onyx v7/depth-32 state snapshot
            b"\xce\x07\x20\x00\x00",  # malformed empty-tree frontier/snapshot body
        ]
    )
    return corpus


def write_corpus(output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    for seed in seeds():
        name = hashlib.sha256(seed).hexdigest()
        (output / name).write_bytes(seed)
    return len({hashlib.sha256(seed).hexdigest() for seed in seeds()})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    count = write_corpus(args.output)
    print(f"generated {count} deterministic fuzz seeds in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
