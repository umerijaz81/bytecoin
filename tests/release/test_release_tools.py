#!/usr/bin/env python3

from __future__ import annotations

import copy
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))

import build_release_evidence  # noqa: E402
import create_source_archive  # noqa: E402
import generate_spdx  # noqa: E402
import release_common  # noqa: E402
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

    def test_release_gate_cli_rejects_uncommitted_tracked_evidence(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["git", "status"],
            returncode=0,
            stdout="M  release/evidence/source-provenance.json\n",
            stderr="",
        )
        with mock.patch.object(verify_release_gates.subprocess, "run", return_value=completed):
            self.assertEqual(
                ["M  release/evidence/source-provenance.json"],
                verify_release_gates.tracked_worktree_changes(ROOT),
            )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                verify_release_gates,
                "tracked_worktree_changes",
                return_value=["M  release/evidence/source-provenance.json"],
            ),
            mock.patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(1, verify_release_gates.main())
        self.assertIn("must be committed", stderr.getvalue())

    def test_release_output_directory_must_start_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary)
            build_release_evidence.require_empty_output(output)
            (output / "stale-unverified.bin").write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "stale or unverified artifacts"):
                build_release_evidence.require_empty_output(output)

    def test_release_json_rejects_duplicate_keys_at_every_depth(self) -> None:
        with self.assertRaisesRegex(release_common.DuplicateJsonKey, "duplicate JSON object key"):
            release_common.strict_json_loads(
                '{"gate_id":"independent-audits","artifact":{"path":"first","path":"second"}}'
            )
        self.assertEqual(
            {"outer": {"left": 1, "right": 2}},
            release_common.strict_json_loads('{"outer":{"left":1,"right":2}}'),
        )

    def test_activation_height_change_fails_closed(self) -> None:
        changed = self.config.replace(
            "const Height UPGRADE_HEIGHT_V5 = 9000000;", "const Height UPGRADE_HEIGHT_V5 = 42;"
        )
        self.assertNotEqual(changed, self.config)
        errors, _ = verify_release_gates.verify(self.gates, changed)
        self.assertTrue(any("UPGRADE_HEIGHT_V5 changed" in error for error in errors), errors)

    def test_placeholder_manifest_requires_exact_activation_height_set(self) -> None:
        gates = copy.deepcopy(self.gates)
        del gates["placeholder_heights"]["UPGRADE_HEIGHT_ONYX"]
        gates["placeholder_heights"]["UNREVIEWED_HEIGHT"] = 42
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(
            any("placeholder_heights must contain exactly" in error for error in errors),
            errors,
        )

    def test_required_gate_cannot_opt_out_of_activation(self) -> None:
        gates = copy.deepcopy(self.gates)
        audit = next(gate for gate in gates["gates"] if gate["id"] == "independent-audits")
        audit["required_for_activation"] = False
        errors, incomplete = verify_release_gates.verify(gates, self.config)
        self.assertTrue(
            any("independent-audits: required_for_activation must be true" in error for error in errors),
            errors,
        )
        self.assertIn("independent-audits", incomplete)

    def test_governance_cannot_pre_authorize_incomplete_qualification(self) -> None:
        gates = copy.deepcopy(self.gates["gates"])
        governance = next(gate for gate in gates if gate["id"] == "governance-approval")
        governance["status"] = "passed"
        errors = verify_release_gates.governance_order_errors(gates)
        self.assertTrue(any("cannot pass before prerequisite gates" in error for error in errors))

    def test_governance_vote_must_follow_qualification_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            gates = []
            for gate_id in sorted(
                verify_release_gates.REQUIRED_GATES - {"governance-approval"}
            ):
                relative = f"{gate_id}.json"
                (root / relative).write_text(
                    json.dumps(
                        {
                            "gate_id": gate_id,
                            "completed_at": "2026-07-20T00:00:00Z",
                        }
                    ),
                    encoding="utf-8",
                )
                gates.append(
                    {
                        "id": gate_id,
                        "status": "passed",
                        "evidence": [relative],
                    }
                )
            (root / "governance.json").write_text(
                json.dumps(
                    {
                        "gate_id": "governance-approval",
                        "started_at": "2026-07-19T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            gates.append(
                {
                    "id": "governance-approval",
                    "status": "passed",
                    "evidence": ["governance.json"],
                }
            )
            errors = verify_release_gates.governance_order_errors(gates, root)
            self.assertTrue(
                any("vote must start after all prerequisite" in error for error in errors),
                errors,
            )

    def test_activation_gate_schema_rejects_unknown_gate(self) -> None:
        gates = copy.deepcopy(self.gates)
        gates["gates"].append(
            {
                "id": "unreviewed-gate",
                "required_for_activation": False,
                "status": "passed",
                "evidence": ["docs/Release-Readiness.md"],
            }
        )
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(any("unknown activation gates" in error for error in errors), errors)

    def test_activation_manifest_type_confusion_fails_without_exception(self) -> None:
        errors, _ = verify_release_gates.verify([], self.config)
        self.assertEqual(["activation gates document must be an object"], errors)

        gates = copy.deepcopy(self.gates)
        gates["gates"][0]["id"] = ["unhashable-id"]
        gates["gates"][1]["status"] = ["unhashable-status"]
        audit = next(
            gate for gate in gates["gates"] if gate.get("id") == "independent-audits"
        )
        audit["minimum_independent_reports"] = ["not-an-integer"]
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(any("identifiers must be present and unique" in error for error in errors))
        self.assertTrue(any("invalid status" in error for error in errors))
        self.assertTrue(any("minimum_independent_reports must equal 2" in error for error in errors))

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

    def test_source_provenance_cannot_pass_without_typed_attestation(self) -> None:
        gates = copy.deepcopy(self.gates)
        gates["release_revision"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        source = next(gate for gate in gates["gates"] if gate["id"] == "source-provenance")
        source["status"] = "passed"
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(
            any("source-provenance: passed status requires 1 typed JSON attestation" in error for error in errors),
            errors,
        )

    def test_activation_evidence_must_be_contained_and_tracked(self) -> None:
        gates = copy.deepcopy(self.gates)
        source = next(gate for gate in gates["gates"] if gate["id"] == "source-provenance")
        source["evidence"] = ["../outside"]
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(any("invalid repository evidence '../outside'" in error for error in errors), errors)
        source["evidence"] = ["docs/Release-Readiness.md"]
        with mock.patch.object(verify_release_gates, "tracked_files", return_value=[]):
            errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(any("evidence is not Git-tracked" in error for error in errors), errors)

    def test_frozen_release_revision_must_exist_in_repository_history(self) -> None:
        gates = copy.deepcopy(self.gates)
        gates["release_revision"] = "0" * 40
        governance = next(gate for gate in gates["gates"] if gate["id"] == "governance-approval")
        governance["status"] = "passed"
        errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(
            any("existing commit that is an ancestor of HEAD" in error for error in errors),
            errors,
        )

    def test_post_freeze_code_changes_cannot_inherit_qualification(self) -> None:
        gates = copy.deepcopy(self.gates)
        gates["release_revision"] = "1" * 40
        governance = next(gate for gate in gates["gates"] if gate["id"] == "governance-approval")
        governance["status"] = "passed"
        with (
            mock.patch.object(verify_release_gates, "frozen_revision_is_ancestor", return_value=True),
            mock.patch.object(
                verify_release_gates,
                "changed_paths_since",
                return_value={
                    "release/activation-gates.json",
                    "src/CryptoNoteConfig.hpp",
                    "src/Core/BlockChain.cpp",
                },
            ),
            mock.patch.object(
                verify_release_gates,
                "revision_file_sha256",
                return_value="2" * 64,
            ),
            mock.patch.object(
                verify_release_gates,
                "source_date_epoch",
                return_value=0,
            ),
            mock.patch.object(
                verify_release_gates,
                "governance_digests_at_revision",
                return_value=("3" * 64, "4" * 64),
            ),
            mock.patch.object(
                verify_release_gates,
                "config_changed_only_at_activation_heights",
                return_value=True,
            ),
        ):
            errors, _ = verify_release_gates.verify(gates, self.config)
        self.assertTrue(
            any(
                "post-freeze changes" in error and "src/Core/BlockChain.cpp" in error
                for error in errors
            ),
            errors,
        )

    def test_post_freeze_declared_evidence_artifacts_are_allowed(self) -> None:
        gates = [
            {
                "id": "independent-audits",
                "evidence": ["release/evidence/audit.json"],
            }
        ]
        document = {
            "gate_id": "independent-audits",
            "artifact": {
                "path": "release/evidence/audit-report.pdf",
                "sha256": "2" * 64,
            }
        }
        with (
            mock.patch.object(
                verify_release_gates,
                "_repository_file",
                side_effect=lambda _root, relative: pathlib.Path(ROOT, relative),
            ),
            mock.patch.object(pathlib.Path, "read_text", return_value=json.dumps(document)),
        ):
            allowed = verify_release_gates.qualification_paths(
                gates,
                {
                    "release/evidence/audit.json",
                    "release/evidence/audit-report.pdf",
                },
            )
        self.assertIn("release/evidence/audit.json", allowed)
        self.assertIn("release/evidence/audit-report.pdf", allowed)

    def test_post_freeze_implementation_files_and_source_artifacts_are_not_allowed(self) -> None:
        gates = [
            {
                "id": "independent-audits",
                "evidence": [
                    "tools/release/verify_release_gates.py",
                    "release/evidence/audit.json",
                ],
            }
        ]
        document = {
            "gate_id": "independent-audits",
            "artifact": {
                "path": "src/Core/BlockChain.cpp",
                "sha256": "2" * 64,
            },
        }
        tracked = {
            "tools/release/verify_release_gates.py",
            "release/evidence/audit.json",
            "src/Core/BlockChain.cpp",
        }
        with (
            mock.patch.object(
                verify_release_gates,
                "_repository_file",
                side_effect=lambda _root, relative: pathlib.Path(ROOT, relative),
            ),
            mock.patch.object(pathlib.Path, "read_text", return_value=json.dumps(document)),
        ):
            allowed = verify_release_gates.qualification_paths(gates, tracked)
        self.assertIn("release/evidence/audit.json", allowed)
        self.assertNotIn("tools/release/verify_release_gates.py", allowed)
        self.assertNotIn("src/Core/BlockChain.cpp", allowed)

    def test_post_freeze_config_allows_only_activation_height_values(self) -> None:
        frozen = (
            "const Height UPGRADE_HEIGHT_V5 = 9000000;\n"
            "const size_t MAX_BLOCK_SIZE = 100;\n"
        )
        activated = (
            "const Height UPGRADE_HEIGHT_V5 = 123456;\n"
            "const size_t MAX_BLOCK_SIZE = 100;\n"
        )
        modified_consensus = (
            "const Height UPGRADE_HEIGHT_V5 = 123456;\n"
            "const size_t MAX_BLOCK_SIZE = 1000000;\n"
        )
        with mock.patch.object(
            verify_release_gates,
            "revision_file",
            return_value=frozen.encode("utf-8"),
        ):
            self.assertTrue(
                verify_release_gates.config_changed_only_at_activation_heights(
                    "1" * 40,
                    activated,
                    {"UPGRADE_HEIGHT_V5"},
                )
            )
            self.assertFalse(
                verify_release_gates.config_changed_only_at_activation_heights(
                    "1" * 40,
                    modified_consensus,
                    {"UPGRADE_HEIGHT_V5"},
                )
            )

    def test_governance_digests_are_derived_from_frozen_revision(self) -> None:
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        compiler_digest, target_profile_digest = (
            verify_release_gates.governance_digests_at_revision(revision)
        )
        self.assertRegex(compiler_digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            "41072cc660e01367910e3fdba37fd683f7738ad6888683037f501b35e0ebb82c",
            target_profile_digest,
        )

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

    def test_source_archive_rejects_escaping_symlinks(self) -> None:
        self.assertEqual(
            "../shared/header.hpp",
            create_source_archive.safe_symlink_target(
                "src/platform/header.hpp", b"../shared/header.hpp"
            ),
        )
        for target in (
            b"/etc/passwd",
            b"C:/Windows/System32",
            b"..\\outside",
            b"../../../outside",
            b"",
        ):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "unsafe|escapes"):
                    create_source_archive.safe_symlink_target("src/link", target)

    def test_source_archive_rejects_non_blob_tree_entries(self) -> None:
        raw = b"160000 commit " + b"1" * 40 + b"\tvendor/external\0"
        with mock.patch.object(release_common, "git", return_value=raw):
            with self.assertRaisesRegex(ValueError, "unsupported Git tree entry type commit"):
                release_common.revision_entries("HEAD")


if __name__ == "__main__":
    unittest.main()
