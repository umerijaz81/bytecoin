#!/usr/bin/env python3
"""Run a complete, non-overlapping shard of the locked Onyx Rust test suite."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "vendor" / "onyx-zk" / "Cargo.toml"
SHARDS = {
    "core": (
        "authorization",
        "bridge",
        "compiler_backend",
        "keys",
        "note_commitment_circuit",
        "program",
        "program_context",
        "spend_auth_circuit",
        "state",
        "state_model_tests",
        "tests",
        "transaction",
        "types",
        "value_commitment_circuit",
    ),
    "transfer": (
        "bundle_circuit",
        "linked_transfer_circuit",
        "membership_circuit",
        "multi_transfer_circuit",
        "transfer_circuit",
    ),
    "programs": (
        "program_deployment",
        "proof",
        "standard_programs",
        "token_program",
    ),
    "assets-wallet": (
        "bridge_circuit",
        "token_issuance",
        "token_issuance_circuit",
        "wallet",
    ),
}


def cargo_command() -> list[str]:
    return [
        "cargo",
        "test",
        "--release",
        "--locked",
        "--offline",
        "--manifest-path",
        str(MANIFEST),
    ]


def list_tests() -> list[str]:
    output = subprocess.check_output([*cargo_command(), "--", "--list"], cwd=ROOT, text=True)
    return sorted(line.removesuffix(": test") for line in output.splitlines() if line.endswith(": test"))


def assignments(tests: list[str]) -> dict[str, list[str]]:
    result = {name: [] for name in SHARDS}
    errors = []
    for test in tests:
        module = test.split("::", 1)[0]
        owners = [name for name, modules in SHARDS.items() if module in modules]
        if len(owners) != 1:
            errors.append(f"{test}: expected exactly one shard, found {owners}")
        else:
            result[owners[0]].append(test)
    if errors:
        raise RuntimeError("invalid Onyx test shard map:\n" + "\n".join(errors))
    if sum(len(group) for group in result.values()) != len(tests):
        raise RuntimeError("Onyx test shard map does not cover the listed suite exactly once")
    return result


def module_commands(module: str, selected: list[str], all_tests: list[str]) -> list[list[str]]:
    """Return filters that cannot select tests outside the requested module."""
    module_tests = [test for test in selected if test.split("::", 1)[0] == module]
    if not module_tests:
        raise RuntimeError(f"Onyx shard module {module} no longer selects any tests")

    module_filter = f"{module}::tests::"
    filter_matches = [test for test in all_tests if module_filter in test]
    if set(filter_matches) == set(module_tests):
        return [[*cargo_command(), module_filter]]

    # Rust libtest uses substring filters. Generic or suffix-sharing module names
    # (for example tests/program/transfer_circuit) therefore require --exact.
    return [[*cargo_command(), test, "--", "--exact"] for test in module_tests]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("shard", choices=sorted(SHARDS))
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    tests = list_tests()
    if not tests:
        raise SystemExit("Onyx test listing is empty")
    groups = assignments(tests)
    selected = groups[args.shard]
    if not selected:
        raise SystemExit(f"Onyx shard {args.shard} is empty")
    plans = {
        module: module_commands(module, selected, tests)
        for module in SHARDS[args.shard]
    }
    print(
        f"Onyx shard map verified: {len(tests)} tests exactly once; "
        + ", ".join(f"{name}={len(group)}" for name, group in groups.items())
    )
    if args.verify_only:
        return 0

    executed = 0
    for module in SHARDS[args.shard]:
        for command in plans[module]:
            subprocess.run(command, cwd=ROOT, check=True)
        executed += sum(test.split("::", 1)[0] == module for test in selected)
    if executed != len(selected):
        raise SystemExit(f"Onyx shard {args.shard} executed {executed} mapped tests, expected {len(selected)}")
    print(f"Onyx shard {args.shard} passed ({executed} tests)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
