#!/usr/bin/env python3
"""Build and independently reproduce source, SBOM, checksums, and provenance evidence."""

from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import shutil
import subprocess
import tempfile

from create_source_archive import create as create_archive
from generate_spdx import generate as generate_spdx
from release_common import (
    LOCK_PATH,
    ROOT,
    canonical_json_bytes,
    git,
    sha256_file,
    source_date_epoch,
)
from verify_dependencies import verify as verify_dependencies


def dirty_worktree() -> bool:
    return bool(git("status", "--porcelain", "--untracked-files=no").strip())


def build_once(directory: pathlib.Path, revision: str, epoch: int) -> tuple[pathlib.Path, pathlib.Path]:
    short = revision[:12]
    archive = directory / f"bytecoin-{short}-source.tar.gz"
    sbom = directory / f"bytecoin-{short}.spdx.json"
    create_archive(archive, revision, epoch)
    sbom.write_bytes(canonical_json_bytes(generate_spdx(revision, epoch)))
    return archive, sbom


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--revision", default="HEAD")
    parser.add_argument("--allow-dirty", action="store_true", help="development only; prohibited for release tags")
    args = parser.parse_args()

    errors = verify_dependencies()
    if errors:
        raise SystemExit("\n".join(f"dependency lock: {error}" for error in errors))
    dirty = dirty_worktree()
    if dirty and not args.allow_dirty:
        raise SystemExit("tracked worktree is dirty; commit the exact release source or use --allow-dirty for development")

    revision = git("rev-parse", f"{args.revision}^{{commit}}").strip()
    epoch = source_date_epoch(revision)
    output = args.output_dir.resolve()
    if output == ROOT:
        raise SystemExit("release output directory cannot be the repository root")
    output.mkdir(parents=True, exist_ok=True)
    if ROOT in output.parents:
        # Release output inside the tree must not itself be tracked and accidentally enter a later archive.
        relative_output = output.relative_to(ROOT).as_posix()
        output_is_not_ignored = subprocess.run(
            ["git", "check-ignore", "-q", "--", relative_output], cwd=ROOT, check=False
        ).returncode != 0
        if output_is_not_ignored:
            raise SystemExit("output directory inside the repository must be ignored by git")

    with tempfile.TemporaryDirectory(prefix="bytecoin-release-a-") as first_raw, tempfile.TemporaryDirectory(
        prefix="bytecoin-release-b-"
    ) as second_raw:
        first = pathlib.Path(first_raw)
        second = pathlib.Path(second_raw)
        archive_a, sbom_a = build_once(first, revision, epoch)
        archive_b, sbom_b = build_once(second, revision, epoch)
        for left, right in ((archive_a, archive_b), (sbom_a, sbom_b)):
            if sha256_file(left) != sha256_file(right):
                raise SystemExit(f"reproducibility failure: {left.name} differs across independent generation")
        archive = output / archive_a.name
        sbom = output / sbom_a.name
        shutil.copyfile(archive_a, archive)
        shutil.copyfile(sbom_a, sbom)

    created = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    provenance = {
        "schema": "bytecoin-release-provenance/v1",
        "revision": revision,
        "source_date_epoch": epoch,
        "created": created,
        "dirty_worktree": dirty,
        "dependencies_lock_sha256": sha256_file(LOCK_PATH),
        "materials": [
            {"name": archive.name, "sha256": sha256_file(archive)},
            {"name": sbom.name, "sha256": sha256_file(sbom)},
        ],
        "reproduction": {
            "independent_generations": 2,
            "source_archive_identical": True,
            "spdx_sbom_identical": True,
        },
        "binary_reproducibility_claimed": False,
    }
    provenance_path = output / f"bytecoin-{revision[:12]}.provenance.json"
    provenance_path.write_bytes(canonical_json_bytes(provenance))
    artifacts = sorted((archive, sbom, provenance_path), key=lambda path: path.name)
    checksums = "".join(f"{sha256_file(path)}  {path.name}\n" for path in artifacts)
    (output / "SHA256SUMS").write_text(checksums, encoding="ascii", newline="\n")
    print(f"release evidence generated for {revision} in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
