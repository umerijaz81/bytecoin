#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "onyx"))
import compiler_v1  # noqa: E402
import verify_compiler_bundle_v1 as verifier  # noqa: E402


SOURCE = b"""export fn balance(public network: u32, private amount: u64) -> u64 {
  let one: u64 = 1;
  let output: u64 = amount - one;
  assert(output <= amount);
  for i in 0..3 {
    assert(i < 3);
  }
  if true {
    assert(output <= amount);
  } else {
    assert(false);
  }
  return output;
}
"""


def write_json(path: pathlib.Path, value: object) -> bytes:
    data = compiler_v1.canonical_json(value)
    path.write_bytes(data)
    return data


def create_package(root: pathlib.Path, source: bytes = SOURCE, vectors=None, **manifest_changes) -> pathlib.Path:
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "main.onx").write_bytes(source)
    lock_bytes = write_json(root / "onyx.lock", {"dependencies": [], "format": 1})
    manifest = {
        "compiler_build_digest": compiler_v1.compiler_digest(),
        "compiler_version": compiler_v1.COMPILER_VERSION,
        "dependency_lock_digest": hashlib.sha256(lock_bytes).hexdigest(),
        "exports": ["balance"],
        "format": 1,
        "language_edition": compiler_v1.LANGUAGE_EDITION,
        "limits": {
            "max_advice_columns": 16,
            "max_fixed_columns": 8,
            "max_instance_columns": 4,
            "max_loop_iterations": 64,
            "max_proof_bytes": 4096,
            "max_rows": 4096,
        },
        "name": "compiler-test",
        "sources": [{"path": "src/main.onx", "sha256": hashlib.sha256(source).hexdigest()}],
        "target_profile": "halo2-ipa-pasta-onyx-compiler-v1",
        "target_profile_digest": hashlib.sha256(compiler_v1.canonical_json(compiler_v1.target_profile())).hexdigest(),
        "version": "1.0.0",
        "vectors": ([{"function": "balance", "inputs": [7, 10], "expected": 9},
                     {"function": "balance", "inputs": [7, 0], "expect_failure": True}]
                    if vectors is None else vectors),
    }
    manifest.update(manifest_changes)
    write_json(root / "onyx-package.json", manifest)
    return root


class CompilerV1Tests(unittest.TestCase):
    def test_bundle_is_reproducible_and_independently_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first_package = create_package(root / "first" / "package")
            second_package = create_package(root / "second" / "different-absolute-path" / "package")
            first_bundle = root / "first-bundle"
            second_bundle = root / "second-bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(first_package), first_bundle)
            compiler_v1.write_bundle(compiler_v1.load_package(second_package), second_bundle)
            verifier.compare_directories(first_bundle, second_bundle)
            verifier.verify_bundle(first_bundle)
            profile = json.loads((first_bundle / "target-profile.json").read_text("utf-8"))
            provenance = json.loads((first_bundle / "provenance.json").read_text("utf-8"))
            resources = json.loads((first_bundle / "resources.json").read_text("utf-8"))
            vectors = json.loads((first_bundle / "vectors.json").read_text("utf-8"))
            self.assertEqual(profile["backend_status"], "frontend-only-not-registrable")
            self.assertFalse(provenance["registrable"])
            self.assertGreater(resources["expanded_instructions"], 10)
            self.assertEqual(resources["public_inputs"], 1)
            self.assertEqual(resources["private_inputs"], 1)
            self.assertEqual([vector["outcome"] for vector in vectors["vectors"]], ["accepted", "rejected"])
            golden = json.loads((ROOT / "tests" / "onyx_compiler" / "golden-v1.json").read_text("utf-8"))
            self.assertEqual(compiler_v1.compiler_digest(), golden["compiler_build_digest"])
            self.assertEqual(hashlib.sha256(compiler_v1.canonical_json(profile)).hexdigest(),
                golden["target_profile_digest"])
            self.assertEqual((first_bundle / "ir-id.txt").read_text("ascii").strip(), golden["ir_id"])
            self.assertEqual(hashlib.sha256((first_bundle / "SHA256MANIFEST.json").read_bytes()).hexdigest(),
                golden["artifact_manifest_sha256"])

    def test_mutated_ir_is_rejected_before_recompilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package")
            bundle = root / "bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(package), bundle)
            ir = bytearray((bundle / "program.onxir").read_bytes())
            ir[-1] ^= 1
            (bundle / "program.onxir").write_bytes(ir)
            manifest = json.loads((bundle / "SHA256MANIFEST.json").read_text("utf-8"))
            for entry in manifest["files"]:
                if entry["path"] == "program.onxir":
                    entry["sha256"] = hashlib.sha256(ir).hexdigest()
                    entry["size"] = len(ir)
            write_json(bundle / "SHA256MANIFEST.json", manifest)
            with self.assertRaises(verifier.VerificationError):
                verifier.verify_bundle(bundle)

    def test_noncanonical_manifest_and_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package")
            manifest = json.loads((package / "onyx-package.json").read_text("utf-8"))
            (package / "onyx-package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(compiler_v1.CompileError, "E_PACKAGE_CANONICAL"):
                compiler_v1.load_package(package)
            shutil.rmtree(package)
            package = create_package(root / "package", SOURCE.replace(b"\n", b"\r\n"))
            with self.assertRaisesRegex(compiler_v1.CompileError, "E_SOURCE_TEXT"):
                compiler_v1.load_package(package)

    def test_undeclared_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = create_package(pathlib.Path(temporary) / "package")
            (package / "ambient-secret.txt").write_text("not declared", encoding="utf-8")
            with self.assertRaisesRegex(compiler_v1.CompileError, "E_PACKAGE_UNDECLARED"):
                compiler_v1.load_package(package)

    def test_acyclic_direct_calls_are_encoded_and_resource_expanded(self):
        source = b"""fn add_one(private value: u64) -> u64 {
  let one: u64 = 1;
  let result: u64 = value + one;
  return result;
}
export fn balance(public network: u32, private amount: u64) -> u64 {
  let output: u64 = add_one(amount);
  return output;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package", source,
                vectors=[{"function": "balance", "inputs": [7, 10], "expected": 11}])
            bundle = root / "bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(package), bundle)
            verifier.verify_bundle(bundle)
            resources = json.loads((bundle / "resources.json").read_text("utf-8"))
            self.assertGreater(resources["expanded_instructions"], resources["ir_instructions"])

    def test_fixed_array_construction_and_bounded_index_are_verified(self):
        source = b"""export fn balance(public network: u32, private amount: u64) -> u64 {
  let values: [u64; 3] = [amount, amount, amount];
  let index: u64 = 1;
  let output: u64 = values[index];
  return output;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package", source,
                vectors=[{"function": "balance", "inputs": [7, 10], "expected": 10}])
            bundle = root / "bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(package), bundle)
            verifier.verify_bundle(bundle)

    def test_nonrecursive_record_construction_and_field_access_are_verified(self):
        source = b"""record Pair {
  left: u64;
  right: u64;
}
export fn balance(public network: u32, private amount: u64) -> u64 {
  let pair: Pair = Pair { left: amount, right: amount };
  let output: u64 = pair.right;
  return output;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package", source,
                vectors=[{"function": "balance", "inputs": [7, 10], "expected": 10}])
            bundle = root / "bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(package), bundle)
            verifier.verify_bundle(bundle)

    def test_fixed_byte_string_literals_are_canonical_and_verified(self):
        source = b"""export fn balance(public network: u32, private payload: bytes<4>) -> bytes<4> {
  let output: bytes<4> = hex\"0102a0ff\";
  return output;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package", source,
                vectors=[{"function": "balance", "inputs": [7, "00000000"], "expected": "0102a0ff"}])
            bundle = root / "bundle"
            compiler_v1.write_bundle(compiler_v1.load_package(package), bundle)
            verifier.verify_bundle(bundle)

    def test_unbounded_and_unsafe_language_constructs_fail_closed(self):
        bad_sources = (
            SOURCE.replace(b"for i in 0..3", b"while true"),
            SOURCE.replace(b"0..3", b"0..2048"),
            SOURCE.replace(b"amount - one", b"unknown(amount)"),
            SOURCE.replace(b"return output;", b"return 18446744073709551616;"),
        )
        for index, source in enumerate(bad_sources):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                package = create_package(pathlib.Path(temporary) / "package", source)
                loaded = compiler_v1.load_package(package)
                with self.assertRaises(compiler_v1.CompileError):
                    compiler_v1.compile_sources(loaded)

    def test_resource_limit_is_enforced_after_loop_expansion(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = create_package(pathlib.Path(temporary) / "package")
            manifest = json.loads((package / "onyx-package.json").read_text("utf-8"))
            manifest["limits"]["max_rows"] = 8
            write_json(package / "onyx-package.json", manifest)
            with self.assertRaisesRegex(compiler_v1.CompileError, "E_INSTRUCTION_LIMIT|E_RESOURCE_LIMIT"):
                compiler_v1.compile_sources(compiler_v1.load_package(package))

    def test_negative_vector_cannot_hide_an_unsupported_intrinsic_evaluator(self):
        source = b"""export fn balance(public left: field, private right: field) -> field {
  let output: field = poseidon_hash(left, right);
  return output;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = create_package(root / "package", source,
                vectors=[{"function": "balance", "inputs": [1, 2], "expect_failure": True}])
            with self.assertRaisesRegex(compiler_v1.CompileError, "E_VECTOR_UNSUPPORTED"):
                compiler_v1.write_bundle(compiler_v1.load_package(package), root / "bundle")


if __name__ == "__main__":
    unittest.main()
