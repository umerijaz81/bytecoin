#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))

import build_release_evidence  # noqa: E402
import generate_spdx  # noqa: E402
import verify_dependencies  # noqa: E402
import verify_release_gates  # noqa: E402


class ReleaseToolsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gates = json.loads((ROOT / "release" / "activation-gates.json").read_text(encoding="utf-8"))
        cls.config = (ROOT / "src" / "CryptoNoteConfig.hpp").read_text(encoding="utf-8")

    def test_current_incomplete_gates_keep_placeholders(self) -> None:
        errors, incomplete = verify_release_gates.verify(self.gates, self.config)
        self.assertEqual([], errors)
        self.assertIn("independent-audits", incomplete)
        self.assertIn("governance-approval", incomplete)

    def test_activation_height_change_fails_closed(self) -> None:
        changed = self.config.replace(
            "const Height UPGRADE_HEIGHT_V5 = 9000000;", "const Height UPGRADE_HEIGHT_V5 = 42;"
        )
        self.assertNotEqual(changed, self.config)
        errors, _ = verify_release_gates.verify(self.gates, changed)
        self.assertTrue(any("UPGRADE_HEIGHT_V5 changed" in error for error in errors), errors)

    def test_audit_gate_cannot_pass_without_two_reports(self) -> None:
        gates = copy.deepcopy(self.gates)
        audit = next(gate for gate in gates["gates"] if gate["id"] == "independent-audits")
        audit["status"] = "passed"
        audit["evidence"] = ["docs/Release-Readiness.md"]
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(any("two distinct report" in error for error in errors), errors)
        self.assertTrue(any("release_revision" in error for error in errors), errors)

    def test_partial_binary_reproducibility_evidence_does_not_pass_gate(self) -> None:
        gate = next(
            gate for gate in self.gates["gates"] if gate["id"] == "reproducible-platform-binaries"
        )
        self.assertEqual("pending", gate["status"])
        self.assertGreaterEqual(len(gate["evidence"]), 2)
        errors, incomplete = verify_release_gates.verify(self.gates, self.config)
        self.assertEqual([], errors)
        self.assertIn("reproducible-platform-binaries", incomplete)

    def test_spdx_identifiers_are_unique_and_deterministic(self) -> None:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        first = generate_spdx.generate(revision, 0)
        second = generate_spdx.generate(revision, 0)
        self.assertEqual(first, second)
        identifiers = [package["SPDXID"] for package in first["packages"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual("SPDX-2.3", first["spdxVersion"])

    def test_cargo_vendor_is_complete_and_checksum_exact(self) -> None:
        self.assertEqual([], verify_dependencies.verify_cargo_vendor("vendor/onyx-zk"))

    def test_release_revision_must_equal_checked_out_head(self) -> None:
        def fake_git(*arguments: str, text: bool = True) -> str:
            del text
            if arguments == ("rev-parse", "candidate^{commit}"):
                return "1" * 40 + "\n"
            if arguments == ("rev-parse", "HEAD^{commit}"):
                return "2" * 40 + "\n"
            raise AssertionError(arguments)

        with mock.patch.object(build_release_evidence, "git", side_effect=fake_git):
            with self.assertRaisesRegex(ValueError, "must equal the checked-out HEAD"):
                build_release_evidence.resolve_checked_out_revision("candidate")

        with mock.patch.object(
            build_release_evidence, "git", return_value="3" * 40 + "\n"
        ):
            self.assertEqual(
                "3" * 40,
                build_release_evidence.resolve_checked_out_revision("HEAD"),
            )


if __name__ == "__main__":
    unittest.main()
