#!/usr/bin/env python3
"""Create a byte-reproducible gzip-compressed archive of tracked source files."""

from __future__ import annotations

import argparse
import gzip
import io
import pathlib
import tarfile

from release_common import git_blobs, revision_entries


def safe_symlink_target(relative: str, raw_target: bytes) -> str:
    target = raw_target.decode("utf-8")
    if (
        not target
        or target.startswith("/")
        or "\\" in target
        or (len(target) >= 2 and target[1] == ":")
    ):
        raise ValueError(f"unsafe symlink target at {relative}: {target!r}")
    resolved = list(pathlib.PurePosixPath(relative).parent.parts)
    for part in pathlib.PurePosixPath(target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise ValueError(f"symlink escapes source archive at {relative}: {target!r}")
            resolved.pop()
        else:
            resolved.append(part)
    if not resolved:
        raise ValueError(f"symlink resolves to archive root at {relative}: {target!r}")
    return target


def create(output: pathlib.Path, revision: str, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"bytecoin-{revision[:12]}"
    with output.open("wb") as raw_output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                entries = revision_entries(revision)
                blobs = git_blobs([object_id for _, _, object_id in entries])
                for (relative, raw_mode, _), data in zip(entries, blobs):
                    git_mode = int(raw_mode, 8)
                    info = tarfile.TarInfo(f"{prefix}/{relative}")
                    info.mtime = epoch
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    if git_mode == 0o120000:
                        info.type = tarfile.SYMTYPE
                        info.mode = 0o777
                        info.linkname = safe_symlink_target(relative, data)
                        info.size = 0
                        archive.addfile(info)
                        continue
                    if git_mode not in (0o100644, 0o100755):
                        raise ValueError(f"unsupported Git mode {raw_mode} at {relative}")
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
