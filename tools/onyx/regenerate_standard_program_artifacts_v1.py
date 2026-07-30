#!/usr/bin/env python3
"""Stage, verify, and regenerate pinned Onyx standard-program artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import tempfile

import compiler_v1
import verify_compiler_bundle_v1


ROOT = pathlib.Path(__file__).resolve().parents[2]
STANDARD_ROOT = ROOT / "programs" / "onyx-standard"
ARTIFACT_ROOT = STANDARD_ROOT / "artifacts"
PROGRAMS = {
    "multisig": "authorize",
    "nft": "transfer",
    "swap": "settle",
    "vesting": "release",
}
CIRCUIT_K = 16


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regenerate(backend: pathlib.Path) -> None:
    backend = backend.resolve()
    compiler_digest = compiler_v1.compiler_digest()
    profile_digest = digest(compiler_v1.canonical_json(compiler_v1.target_profile()))
    staged: dict[str, tuple[bytes, bytes, bytes, str]] = {}

    with tempfile.TemporaryDirectory(prefix="onyx-standard-regenerate-") as temporary:
        temporary = pathlib.Path(temporary)
        for name, export in sorted(PROGRAMS.items()):
            package_root = temporary / "packages" / name
            shutil.copytree(STANDARD_ROOT / name, package_root)
            manifest_path = package_root / "onyx-package.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["compiler_build_digest"] = compiler_digest
            manifest["target_profile_digest"] = profile_digest
            manifest_bytes = compiler_v1.canonical_json(manifest)
            manifest_path.write_bytes(manifest_bytes)

            bundle = temporary / "bundles" / name
            compiler_v1.write_bundle(
                compiler_v1.load_package(package_root), bundle, backend, CIRCUIT_K
            )
            verify_compiler_bundle_v1.verify_bundle(bundle, backend)
            ir = (bundle / "program.onxir").read_bytes()
            descriptor = (bundle / "halo2-vk-descriptors" / f"{export}.bin").read_bytes()
            schema = json.loads((bundle / "schemas" / f"{export}.json").read_bytes())
            if len(descriptor) != 133 or not isinstance(schema.get("schema_hash"), str):
                raise RuntimeError(f"{name}: generated descriptor or schema is invalid")
            staged[name] = (manifest_bytes, ir, descriptor, schema["schema_hash"])

        entries = {}
        for name, export in sorted(PROGRAMS.items()):
            manifest_bytes, ir, descriptor, schema_hash = staged[name]
            entries[name] = {
                "descriptor_sha256": digest(descriptor),
                "export": export,
                "ir_sha256": digest(ir),
                "package_manifest_sha256": digest(manifest_bytes),
                "schema_hash": schema_hash,
            }
        artifact_manifest = compiler_v1.canonical_json({
            "backend": "halo2-ipa-pasta-onyx-compiler-v1",
            "circuit_k": CIRCUIT_K,
            "compiler_build_digest": compiler_digest,
            "format": 1,
            "programs": entries,
        })

        # Publish only after every package has compiled and independently verified.
        for name in sorted(PROGRAMS):
            manifest_bytes, ir, descriptor, _ = staged[name]
            (STANDARD_ROOT / name / "onyx-package.json").write_bytes(manifest_bytes)
            output = ARTIFACT_ROOT / name
            output.mkdir(parents=True, exist_ok=True)
            (output / "program.onxir").write_bytes(ir)
            (output / "descriptor-v2.bin").write_bytes(descriptor)
        (ARTIFACT_ROOT / "manifest-v1.json").write_bytes(artifact_manifest)

    print(f"regenerated {len(PROGRAMS)} standard programs for compiler {compiler_digest}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-executable", required=True, type=pathlib.Path)
    arguments = parser.parse_args()
    regenerate(arguments.backend_executable)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
