#!/usr/bin/env python3

from __future__ import annotations

import os
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "onyx"))
import compiler_v1  # noqa: E402
import verify_compiler_bundle_v1 as verifier  # noqa: E402


PACKAGES = {
    "nft": ("transfer", 31, 1),
    "vesting": ("release", 30, 1),
    "multisig": ("authorize", 30, 3),
    "swap": ("settle", 30, 1),
}


def encoded_field(value: int) -> str:
    return int(value).to_bytes(32, "little").hex()


def split_field(value: int) -> list[int]:
    encoded = int(value).to_bytes(32, "little")
    return [int.from_bytes(encoded[:31], "little"), encoded[31]]


def context_prefix(prior: int, following: int, valid_from: int = 50) -> list[int]:
    return [
        11, 12, valid_from, 100, 0, 0, 13, 0, 1, 14, 0, 15, 0, 16, 0, 1,
        *split_field(prior), *split_field(following), 17, 0,
    ]


def proof_vectors() -> dict[str, tuple[list[int], list[int], list[tuple[list[int], list[int]]]]]:
    poseidon = compiler_v1.poseidon_hash2
    collection = poseidon(21, 0)
    token = poseidon(22, 0)
    identity = poseidon(collection, token)
    instance = poseidon(identity, 33)
    owner_secret = 34
    nft_prior = poseidon(owner_secret, instance)
    nft_next = 901
    nft = context_prefix(nft_prior, nft_next) + [
        1, 21, 0, 22, 0, 33, 1, nft_prior, nft_next,
    ]

    schedule = poseidon(31, 0)
    beneficiary = poseidon(32, 0)
    beneficiary_secret = 33
    authority = poseidon(beneficiary_secret, schedule)
    vesting_prior = poseidon(authority, beneficiary)
    vesting_next = 902
    vesting = context_prefix(vesting_prior, vesting_next) + [
        2, 31, 0, 32, 0, 50, vesting_prior, vesting_next,
    ]
    early_vesting = context_prefix(vesting_prior, vesting_next, 49) + [
        2, 31, 0, 32, 0, 50, vesting_prior, vesting_next,
    ]

    action = poseidon(41, 0)
    secrets = [51, 52] + [0] * 14
    commitments = [poseidon(51, action), poseidon(52, action)] + [0] * 14
    approvals = [1, 1] + [0] * 14
    policy = poseidon(commitments[0], commitments[1])
    for commitment in commitments[2:]:
        policy = poseidon(policy, commitment)
    multisig_prior = poseidon(policy, action)
    multisig_next = 903
    multisig = context_prefix(multisig_prior, multisig_next) + [
        3, policy, 41, 0, 2, 2, multisig_prior, multisig_next,
    ]
    rejected_approvals = [1, 0] + [0] * 14
    rejected_secrets = [51, 0] + [0] * 14
    duplicate_commitments = [commitments[0], commitments[0]] + [0] * 14
    duplicate_policy = poseidon(duplicate_commitments[0], duplicate_commitments[1])
    for commitment in duplicate_commitments[2:]:
        duplicate_policy = poseidon(duplicate_policy, commitment)
    duplicate_prior = poseidon(duplicate_policy, action)
    duplicate_public = context_prefix(duplicate_prior, multisig_next) + [
        3, duplicate_policy, 41, 0, 2, 2, duplicate_prior, multisig_next,
    ]

    swap = poseidon(61, 0)
    preimage = 62
    hashlock = poseidon(preimage, swap)
    swap_prior = poseidon(swap, hashlock)
    swap_next = 904
    swap_public = context_prefix(swap_prior, swap_next) + [
        4, 61, 0, hashlock, 70, 0, swap_prior, swap_next,
    ]

    return {
        "nft": (nft, [owner_secret], [(nft, [owner_secret + 1])]),
        "vesting": (vesting, [beneficiary_secret], [(early_vesting, [beneficiary_secret])]),
        "multisig": (
            multisig,
            commitments + approvals + secrets,
            [
                (multisig, commitments + rejected_approvals + rejected_secrets),
                (duplicate_public, duplicate_commitments + approvals + [51, 51] + [0] * 14),
            ],
        ),
        "swap": (swap_public, [preimage], [(swap_public, [preimage + 1])]),
    }


class StandardProgramTests(unittest.TestCase):
    def test_packages_reproduce_and_have_exact_public_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = pathlib.Path(temporary)
            for name, (_, public_count, private_count) in PACKAGES.items():
                package = compiler_v1.load_package(ROOT / "programs" / "onyx-standard" / name)
                first = temporary / f"{name}-first"
                second = temporary / f"{name}-second"
                compiler_v1.write_bundle(package, first)
                compiler_v1.write_bundle(package, second)
                verifier.compare_directories(first, second)
                verifier.verify_bundle(first)
                resources = json.loads((first / "resources.json").read_text("utf-8"))
                self.assertEqual(resources["public_inputs"], public_count)
                self.assertEqual(resources["private_inputs"], private_count)

    @unittest.skipUnless(os.environ.get("ONYX_COMPILER_BACKEND"), "Halo2 backend executable not supplied")
    def test_real_proofs_accept_valid_and_reject_policy_mutations(self):
        backend = pathlib.Path(os.environ["ONYX_COMPILER_BACKEND"])
        vectors = proof_vectors()
        with tempfile.TemporaryDirectory() as temporary:
            temporary = pathlib.Path(temporary)
            for name, (export, _, _) in PACKAGES.items():
                bundle = temporary / name
                package = compiler_v1.load_package(ROOT / "programs" / "onyx-standard" / name)
                compiler_v1.write_bundle(package, bundle, backend, 16)
                verifier.verify_bundle(bundle, backend)
                valid_public, valid_private, rejected_vectors = vectors[name]
                ir = (bundle / "program.onxir").read_bytes()
                accepted = subprocess.run(
                    [str(backend), "prove", "16",
                     ",".join(encoded_field(value) for value in valid_public + valid_private),
                     ",".join(encoded_field(value) for value in valid_public + [1]), export],
                    input=ir, capture_output=True, timeout=300,
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr.decode("utf-8", "replace"))
                self.assertRegex(accepted.stdout.decode().strip(), r"^[0-9a-f]+$")
                for bad_public, bad_private in rejected_vectors:
                    rejected = subprocess.run(
                        [str(backend), "prove", "16",
                         ",".join(encoded_field(value) for value in bad_public + bad_private),
                         ",".join(encoded_field(value) for value in bad_public + [1]), export],
                        input=ir, capture_output=True, timeout=300,
                    )
                    self.assertNotEqual(rejected.returncode, 0, f"{name} mutation unexpectedly proved")


if __name__ == "__main__":
    unittest.main()
