#!/usr/bin/env python3
"""Verify and independently regenerate tracked Onyx standard-program artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import tempfile

import compiler_v1
import verify_compiler_bundle_v1


ROOT = pathlib.Path(__file__).resolve().parents[2]
STANDARD_ROOT = ROOT / "programs" / "onyx-standard"
ARTIFACT_ROOT = STANDARD_ROOT / "artifacts"
PROGRAMS = {"multisig", "nft", "swap", "vesting"}


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(backend: pathlib.Path) -> None:
    raw = (ARTIFACT_ROOT / "manifest-v1.json").read_bytes()
    manifest = json.loads(raw)
    if raw != compiler_v1.canonical_json(manifest):
        raise RuntimeError("standard artifact manifest is not canonical JSON")
    if set(manifest) != {"backend", "circuit_k", "compiler_build_digest", "format", "programs"}:
        raise RuntimeError("standard artifact manifest fields changed")
    if (
        manifest["format"] != 1
        or manifest["backend"] != "halo2-ipa-pasta-onyx-compiler-v1"
        or manifest["compiler_build_digest"] != compiler_v1.compiler_digest()
        or not 8 <= manifest["circuit_k"] <= 20
        or set(manifest["programs"]) != PROGRAMS
    ):
        raise RuntimeError("standard artifact manifest identity is invalid")

    with tempfile.TemporaryDirectory() as temporary:
        temporary = pathlib.Path(temporary)
        for name in sorted(PROGRAMS):
            entry = manifest["programs"][name]
            if set(entry) != {
                "descriptor_sha256", "export", "ir_sha256", "package_manifest_sha256", "schema_hash"
            }:
                raise RuntimeError(f"{name} artifact fields changed")
            package_root = STANDARD_ROOT / name
            tracked_root = ARTIFACT_ROOT / name
            ir = tracked_root / "program.onxir"
            descriptor = tracked_root / "descriptor-v2.bin"
            if (
                digest(package_root / "onyx-package.json") != entry["package_manifest_sha256"]
                or digest(ir) != entry["ir_sha256"]
                or digest(descriptor) != entry["descriptor_sha256"]
                or len(bytes.fromhex(entry["schema_hash"])) != 32
                or descriptor.stat().st_size != 133
            ):
                raise RuntimeError(f"{name} tracked artifact digest or size mismatch")
            bundle = temporary / name
            compiler_v1.write_bundle(
                compiler_v1.load_package(package_root),
                bundle,
                backend,
                manifest["circuit_k"],
            )
            verify_compiler_bundle_v1.verify_bundle(bundle, backend)
            if (bundle / "program.onxir").read_bytes() != ir.read_bytes():
                raise RuntimeError(f"{name} canonical IR did not reproduce")
            generated_descriptor = bundle / "halo2-vk-descriptors" / f"{entry['export']}.bin"
            if generated_descriptor.read_bytes() != descriptor.read_bytes():
                raise RuntimeError(f"{name} descriptor did not reproduce")
    print("Onyx standard program IR and descriptors verified and reproduced")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-executable", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    verify(arguments.backend_executable.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
