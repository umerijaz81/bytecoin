#!/usr/bin/env python3
"""Deterministic grammar-directed differential campaign for the Onyx v1 compiler."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import pathlib
import random
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "onyx"))
import compiler_v1  # noqa: E402
import verify_compiler_bundle_v1 as verifier  # noqa: E402


DEFAULT_SEED = 0x4F4E5958
INTEGER_KINDS = (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64))


@dataclasses.dataclass(frozen=True)
class StructuredCase:
    number: int
    kind: str
    operator: str
    left: int | bool
    right: int | bool
    return_kind: str
    expected: int | bool

    @property
    def export(self) -> str:
        return f"fuzz_{self.number:04d}"

    def source(self) -> bytes:
        return (
            f"export fn {self.export}(public left: {self.kind}, private right: {self.kind}) -> {self.return_kind} {{\n"
            f"  let output: {self.return_kind} = left {self.operator} right;\n"
            "  return output;\n"
            "}\n"
        ).encode("ascii")


def _integer_case(rng: random.Random, number: int) -> StructuredCase:
    kind, bits = rng.choice(INTEGER_KINDS)
    maximum = (1 << bits) - 1
    operator = rng.choice(("+", "-", "*", "/", "%", "<<", ">>", "<", "<=", ">", ">=", "==", "!="))
    edges = (0, 1, 2, maximum // 2, max(0, maximum - 1), maximum)
    if operator == "+":
        left = rng.choice(edges)
        right = rng.randrange(maximum - left + 1)
        expected = left + right
    elif operator == "-":
        left = rng.choice(edges)
        right = rng.randrange(left + 1)
        expected = left - right
    elif operator == "*":
        left = rng.randrange(1 << min(bits // 2, 16))
        right = rng.randrange(maximum // max(left, 1) + 1) if left else rng.choice(edges)
        expected = left * right
    elif operator in ("/", "%"):
        left = rng.choice(edges)
        right = rng.randrange(1, min(maximum, 1 << 16) + 1)
        expected = left // right if operator == "/" else left % right
    elif operator in ("<<", ">>"):
        right = rng.randrange(bits)
        left = rng.randrange((maximum >> right) + 1) if operator == "<<" else rng.choice(edges)
        expected = left << right if operator == "<<" else left >> right
    else:
        left, right = rng.choice(edges), rng.choice(edges)
        expected = {
            "<": left < right, "<=": left <= right, ">": left > right,
            ">=": left >= right, "==": left == right, "!=": left != right,
        }[operator]
    return_kind = "bool" if isinstance(expected, bool) else kind
    return StructuredCase(number, kind, operator, left, right, return_kind, expected)


def _field_case(rng: random.Random, number: int) -> StructuredCase:
    modulus = compiler_v1.PASTA_FP_MODULUS
    operator = rng.choice(("+", "-", "*", "/", "==", "!="))
    left = rng.randrange(1 << 32)
    right = rng.randrange(1, 1 << 32) if operator == "/" else rng.randrange(1 << 32)
    if operator == "+": expected = (left + right) % modulus
    elif operator == "-": expected = (left - right) % modulus
    elif operator == "*": expected = (left * right) % modulus
    elif operator == "/": expected = left * pow(right, -1, modulus) % modulus
    elif operator == "==": expected = left == right
    else: expected = left != right
    return StructuredCase(number, "field", operator, left, right,
                          "bool" if isinstance(expected, bool) else "field", expected)


def _boolean_case(rng: random.Random, number: int) -> StructuredCase:
    operator = rng.choice(("&&", "||", "==", "!="))
    left, right = bool(rng.getrandbits(1)), bool(rng.getrandbits(1))
    if operator == "&&": expected = left and right
    elif operator == "||": expected = left or right
    elif operator == "==": expected = left == right
    else: expected = left != right
    return StructuredCase(number, "bool", operator, left, right, "bool", expected)


def generate_cases(count: int, seed: int = DEFAULT_SEED) -> list[StructuredCase]:
    if count < 1 or count > 10_000:
        raise ValueError("case count is outside the bounded campaign range")
    rng = random.Random(seed)
    generators = (_integer_case, _field_case, _boolean_case)
    return [generators[number % len(generators)](rng, number) for number in range(count)]


def _write_package(root: pathlib.Path, case: StructuredCase) -> pathlib.Path:
    root.mkdir(parents=True)
    (root / "src").mkdir()
    source = case.source()
    (root / "src" / "main.onx").write_bytes(source)
    lock = compiler_v1.canonical_json({"dependencies": [], "format": 1})
    (root / "onyx.lock").write_bytes(lock)
    profile_digest = hashlib.sha256(compiler_v1.canonical_json(compiler_v1.target_profile())).hexdigest()
    manifest = {
        "compiler_build_digest": compiler_v1.compiler_digest(),
        "compiler_version": compiler_v1.COMPILER_VERSION,
        "dependency_lock_digest": hashlib.sha256(lock).hexdigest(),
        "exports": [case.export], "format": 1,
        "language_edition": compiler_v1.LANGUAGE_EDITION,
        "limits": {"max_advice_columns": 16, "max_fixed_columns": 8,
                   "max_instance_columns": 4, "max_loop_iterations": 64,
                   "max_proof_bytes": 4096, "max_rows": 4096},
        "name": "structured-fuzz", "sources": [{"path": "src/main.onx",
            "sha256": hashlib.sha256(source).hexdigest()}],
        "target_profile": "halo2-ipa-pasta-onyx-compiler-v1",
        "target_profile_digest": profile_digest, "version": "1.0.0",
        "vectors": [{"function": case.export, "inputs": [case.left, case.right],
                     "expected": case.expected}],
    }
    (root / "onyx-package.json").write_bytes(compiler_v1.canonical_json(manifest))
    return root


def _must_reject_ir(data: bytes, profile: dict, resources: dict) -> None:
    try:
        verifier.verify_ir(data, profile, resources)
    except verifier.VerificationError:
        return
    raise AssertionError("independent decoder accepted a noncanonical IR mutation")


def run_campaign(count: int, seed: int = DEFAULT_SEED,
                 backend: pathlib.Path | None = None, backend_cases: int = 8) -> None:
    cases = generate_cases(count, seed)
    with tempfile.TemporaryDirectory(prefix="onyx-structured-fuzz-") as temporary:
        root = pathlib.Path(temporary)
        for case in cases:
            package = compiler_v1.load_package(_write_package(root / f"case-{case.number}", case))
            compiled, ir, metadata, _ = compiler_v1.compile_sources(package)
            repeated = compiler_v1.compile_sources(package)[1]
            if repeated != ir:
                raise AssertionError("compiler output changed across identical structured inputs")
            vectors = compiler_v1.evaluate_vectors(package, compiled)
            observed = vectors["vectors"][0]
            if observed.get("outcome") != "accepted" or observed.get("result") != case.expected:
                raise AssertionError("compiler evaluator differs from the independent structured oracle")
            verifier.verify_ir(ir, metadata["profile"], metadata["resources"])
            function_count = len(compiler_v1.IR_DOMAIN) + 32
            _must_reject_ir(ir[:-1], metadata["profile"], metadata["resources"])
            _must_reject_ir(ir + b"\x00", metadata["profile"], metadata["resources"])
            _must_reject_ir(ir[:function_count] + b"\x81\x00" + ir[function_count + 1:],
                            metadata["profile"], metadata["resources"])
            if backend is not None and case.number < min(count, backend_cases):
                descriptor = compiler_v1.backend_descriptor(backend, ir, 12, case.export)
                if len(descriptor) != 133:
                    raise AssertionError("unexpected compiler backend descriptor length")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=48)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    parser.add_argument("--backend", type=pathlib.Path)
    parser.add_argument("--backend-cases", type=int, default=8)
    args = parser.parse_args()
    run_campaign(args.cases, args.seed, args.backend, args.backend_cases)
    print(f"structured Onyx campaign passed: cases={args.cases} seed={args.seed:#x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
