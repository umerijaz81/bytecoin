#!/usr/bin/env python3
"""Create a byte-reproducible gzip-compressed archive of tracked source files."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import pathlib
import subprocess
import tarfile

from release_common import ROOT, tracked_files


def index_modes() -> dict[str, int]:
    raw = subprocess.check_output(["git", "ls-files", "-s", "-z"], cwd=ROOT)
    modes: dict[str, int] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0]
        modes[path.decode("utf-8")] = int(mode, 8)
    return modes


def create(output: pathlib.Path, revision: str, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    modes = index_modes()
    prefix = f"bytecoin-{revision[:12]}"
    with output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for relative in tracked_files():
                    path = ROOT / relative
                    git_mode = modes[relative]
                    info = tarfile.TarInfo(f"{prefix}/{relative.replace(os.sep, '/')}")
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    if git_mode == 0o120000:
                        info.type = tarfile.SYMTYPE
                        info.mode = 0o777
                        info.linkname = os.readlink(path)
                        info.size = 0
                        archive.addfile(info)
                        continue
                    data = path.read_bytes()
                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if git_mode & 0o111 else 0o644
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    create(args.output, args.revision, args.epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
