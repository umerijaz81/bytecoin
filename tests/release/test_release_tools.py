#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))

import generate_spdx  # noqa: E402
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

    def test_spdx_identifiers_are_unique_and_deterministic(self) -> None:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        first = generate_spdx.generate(revision, 0)
        second = generate_spdx.generate(revision, 0)
        self.assertEqual(first, second)
        identifiers = [package["SPDXID"] for package in first["packages"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertEqual("SPDX-2.3", first["spdxVersion"])


if __name__ == "__main__":
    unittest.main()
