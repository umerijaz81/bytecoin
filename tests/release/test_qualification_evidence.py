#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))

import qualification_evidence  # noqa: E402


REVISION = "1" * 40
DIGEST = "2" * 64
ACTIVATION_HEIGHTS = {
    "UPGRADE_HEIGHT_V5": 1_000_000,
    "RANDOMX_SWITCH_HEIGHT": 1_000_100,
    "UPGRADE_HEIGHT_RESERVED_V6": 1_000_200,
    "UPGRADE_HEIGHT_ONYX": 1_000_300,
}


class QualificationEvidenceTest(unittest.TestCase):
    def write_artifact(self, root: pathlib.Path, name: str = "report.txt") -> dict:
        path = root / name
        path.write_text("independent evidence\n", encoding="utf-8")
        return {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def write_document(self, root: pathlib.Path, name: str, document: dict) -> str:
        path = root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return name

    def audit(self, root: pathlib.Path, organization: str, report: str) -> dict:
        return {
            "schema_version": 1,
            "gate_id": "independent-audits",
            "revision": REVISION,
            "started_at": "2026-07-10T00:00:00Z",
            "completed_at": "2026-07-17T00:00:00Z",
            "auditor": {"organization": organization},
            "independence_statement": True,
            "methodology": "manual review, adversarial tests and independent reproduction",
            "remediation_verified": True,
            "scope": sorted(qualification_evidence.REQUIRED_AUDIT_SCOPES),
            "unresolved_findings": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "artifact": self.write_artifact(root, report),
        }

    def source_provenance(self, root: pathlib.Path) -> dict:
        short = REVISION[:12]
        archive_name = f"bytecoin-{short}-source.tar.gz"
        sbom_name = f"bytecoin-{short}.spdx.json"
        provenance_name = f"bytecoin-{short}.provenance.json"
        (root / archive_name).write_bytes(b"canonical source archive")
        (root / sbom_name).write_text(
            json.dumps(
                {
                    "spdxVersion": "SPDX-2.3",
                    "name": f"bytecoin-{REVISION}",
                    "packages": [
                        {
                            "SPDXID": "SPDXRef-Package-bytecoin",
                            "versionInfo": REVISION,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        archive_digest = hashlib.sha256((root / archive_name).read_bytes()).hexdigest()
        sbom_digest = hashlib.sha256((root / sbom_name).read_bytes()).hexdigest()
        (root / provenance_name).write_text(
            json.dumps(
                {
                    "schema": "bytecoin-release-provenance/v1",
                    "revision": REVISION,
                    "dirty_worktree": False,
                    "dependencies_lock_sha256": DIGEST,
                    "materials": [
                        {"name": archive_name, "sha256": archive_digest},
                        {"name": sbom_name, "sha256": sbom_digest},
                    ],
                    "reproduction": {
                        "independent_generations": 2,
                        "source_archive_identical": True,
                        "spdx_sbom_identical": True,
                    },
                }
            ),
            encoding="utf-8",
        )
        provenance_digest = hashlib.sha256((root / provenance_name).read_bytes()).hexdigest()
        (root / "SHA256SUMS").write_text(
            "".join(
                f"{digest}  {name}\n"
                for digest, name in (
                    (archive_digest, archive_name),
                    (sbom_digest, sbom_name),
                    (provenance_digest, provenance_name),
                )
            ),
            encoding="ascii",
        )
        artifacts = {
            key: {
                "path": name,
                "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
            }
            for key, name in {
                "source_archive": archive_name,
                "spdx_sbom": sbom_name,
                "provenance": provenance_name,
                "checksums": "SHA256SUMS",
            }.items()
        }
        builders = [
            {
                "builder_id": builder_id,
                "environment_sha256": environment,
                "revision": REVISION,
                "source_archive_sha256": artifacts["source_archive"]["sha256"],
                "spdx_sbom_sha256": artifacts["spdx_sbom"]["sha256"],
                "archive_tool": "bytecoin create_source_archive.py v1",
                "sbom_tool": "bytecoin generate_spdx.py v1",
            }
            for builder_id, environment in (
                ("builder-a", "3" * 64),
                ("builder-b", "4" * 64),
            )
        ]
        return {
            "schema_version": 1,
            "gate_id": "source-provenance",
            "revision": REVISION,
            "completed_at": "2026-07-17T00:00:00Z",
            "independent_builders": 2,
            "builder_ids": ["builder-a", "builder-b"],
            "builders": builders,
            "source_archive_identical": True,
            "spdx_sbom_identical": True,
            "dependencies_lock_sha256": DIGEST,
            "artifacts": artifacts,
        }

    def test_source_provenance_binds_independent_builders_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = self.source_provenance(root)
            evidence = self.write_document(root, "source-evidence.json", document)
            tracked = {evidence}
            tracked.update(binding["path"] for binding in document["artifacts"].values())
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "source-provenance",
                    [evidence],
                    root,
                    tracked_paths=tracked,
                    dependencies_lock_digest=DIGEST,
                    authoritative_source_digests=(
                        document["artifacts"]["source_archive"]["sha256"],
                        document["artifacts"]["spdx_sbom"]["sha256"],
                    ),
                ),
            )

            document["builder_ids"] = ["same builder", " Same  Builder "]
            document["builders"][1]["environment_sha256"] = document["builders"][0][
                "environment_sha256"
            ]
            document["builders"][1]["source_archive_sha256"] = "4" * 64
            document["artifacts"]["checksums"] = document["artifacts"]["provenance"]
            document["dependencies_lock_sha256"] = "3" * 64
            evidence = self.write_document(root, "source-evidence.json", document)
            errors = qualification_evidence.verify_gate(
                "source-provenance",
                [evidence],
                root,
                tracked_paths=tracked,
                dependencies_lock_digest=DIGEST,
            )
            self.assertTrue(any("distinct normalized identities" in error for error in errors), errors)
            self.assertTrue(any("distinct environment identities" in error for error in errors), errors)
            self.assertTrue(any("source archive hash must match" in error for error in errors), errors)
            self.assertTrue(any("artifact paths must be distinct" in error for error in errors), errors)
            self.assertTrue(
                any("does not match frozen release revision" in error for error in errors), errors
            )

    def test_source_provenance_rejects_internally_consistent_wrong_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = self.source_provenance(root)
            provenance_binding = document["artifacts"]["provenance"]
            provenance_path = root / provenance_binding["path"]
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            provenance["revision"] = "3" * 40
            provenance["reproduction"]["independent_generations"] = "two"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            provenance_binding["sha256"] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

            checksums_binding = document["artifacts"]["checksums"]
            checksums_path = root / checksums_binding["path"]
            checksums_path.write_text(
                "".join(
                    f"{document['artifacts'][name]['sha256']}  "
                    f"{pathlib.Path(document['artifacts'][name]['path']).name}\n"
                    for name in ("source_archive", "spdx_sbom", "provenance")
                ),
                encoding="ascii",
            )
            checksums_binding["sha256"] = hashlib.sha256(checksums_path.read_bytes()).hexdigest()

            evidence = self.write_document(root, "source-evidence.json", document)
            tracked = {evidence}
            tracked.update(binding["path"] for binding in document["artifacts"].values())
            errors = qualification_evidence.verify_gate(
                "source-provenance",
                [evidence],
                root,
                tracked_paths=tracked,
                dependencies_lock_digest=DIGEST,
            )
            self.assertTrue(
                any("provenance revision must equal attested revision" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("two identical independent generations" in error for error in errors),
                errors,
            )

    def test_two_distinct_clean_audits_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = self.write_document(root, "audit-a.json", self.audit(root, "A Labs", "a.txt"))
            second = self.write_document(root, "audit-b.json", self.audit(root, "B Labs", "b.txt"))
            self.assertEqual(
                [],
                qualification_evidence.verify_gate("independent-audits", [first, second], root),
            )
            errors = qualification_evidence.verify_gate(
                "independent-audits",
                [first, second],
                root,
                tracked_paths={first, second},
            )
            self.assertTrue(any("artifact is not Git-tracked" in error for error in errors), errors)
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "independent-audits",
                    [first, second],
                    root,
                    tracked_paths={first, second, "a.txt", "b.txt"},
                ),
            )

    def test_duplicate_auditor_and_unresolved_high_finding_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first_doc = self.audit(root, "Same Labs", "a.txt")
            second_doc = self.audit(root, "same labs", "b.txt")
            second_doc["unresolved_findings"]["high"] = 1
            first = self.write_document(root, "audit-a.json", first_doc)
            second = self.write_document(root, "audit-b.json", second_doc)
            errors = qualification_evidence.verify_gate(
                "independent-audits", [first, second], root
            )
            self.assertTrue(any("distinct organizations" in error for error in errors), errors)
            self.assertTrue(any("critical and high" in error for error in errors), errors)

    def test_audits_must_collectively_cover_full_security_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            scopes = sorted(qualification_evidence.REQUIRED_AUDIT_SCOPES)
            first_document = self.audit(root, "A Labs", "a.txt")
            second_document = self.audit(root, "B Labs", "b.txt")
            first_document["scope"] = scopes[:2]
            second_document["scope"] = scopes[2:-1]
            second_document["independence_statement"] = False
            first = self.write_document(root, "audit-a.json", first_document)
            second = self.write_document(root, "audit-b.json", second_document)
            errors = qualification_evidence.verify_gate(
                "independent-audits",
                [first, second],
                root,
            )
            self.assertTrue(any("collectively cover every required audit scope" in error for error in errors))
            self.assertTrue(any("independence_statement must be true" in error for error in errors))

    def test_audit_cannot_start_before_frozen_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = self.write_document(root, "audit-a.json", self.audit(root, "A Labs", "a.txt"))
            second = self.write_document(root, "audit-b.json", self.audit(root, "B Labs", "b.txt"))
            errors = qualification_evidence.verify_gate(
                "independent-audits",
                [first, second],
                root,
                revision_committed_at=datetime(2026, 7, 11, tzinfo=timezone.utc),
            )
            self.assertEqual(
                2,
                sum("audit started before the frozen release revision" in error for error in errors),
                errors,
            )

    def test_short_testnet_soak_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "public-testnet-soak",
                "revision": REVISION,
                "started_at": "2026-07-01T00:00:00Z",
                "completed_at": "2026-07-02T00:00:00Z",
                "public_endpoint": "https://testnet.example",
                "independent_nodes": 3,
                "node_ids": ["node-a", "node-b", "node-c"],
                "observed_blocks": 10_000,
                "reorg_scenarios": 1,
                "malformed_bundle_cases": 1,
                "dos_scenarios": 1,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "soak.json", document)
            errors = qualification_evidence.verify_gate("public-testnet-soak", [evidence], root)
            self.assertTrue(any("at least 14 days" in error for error in errors), errors)

    def test_testnet_soak_cannot_start_before_frozen_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "public-testnet-soak",
                "revision": REVISION,
                "started_at": "2026-07-01T00:00:00Z",
                "completed_at": "2026-07-20T00:00:00Z",
                "public_endpoint": "https://testnet.example",
                "independent_nodes": 3,
                "node_ids": ["node-a", "node-b", "node-c"],
                "observed_blocks": 10_000,
                "reorg_scenarios": 1,
                "malformed_bundle_cases": 1,
                "dos_scenarios": 1,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "soak.json", document)
            errors = qualification_evidence.verify_gate(
                "public-testnet-soak",
                [evidence],
                root,
                revision_committed_at=datetime(2026, 7, 2, tzinfo=timezone.utc),
            )
            self.assertTrue(
                any("started before the frozen release revision" in error for error in errors),
                errors,
            )

    def test_public_testnet_binds_multi_node_consensus_and_supply_convergence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            node_ids = ["node-a", "node-b", "node-c"]
            supply_audit = {
                "total_bridged": 500,
                "total_fees": 25,
                "circulating_supply": 475,
                "commitment_count": 200,
                "program_count": 4,
                "current_block_program_cost": 10,
                "commitment_root": "6" * 64,
                "block_height": 11_000,
            }
            document = {
                "schema_version": 1,
                "gate_id": "public-testnet-soak",
                "revision": REVISION,
                "started_at": "2026-07-01T00:00:00Z",
                "completed_at": "2026-07-16T00:00:00Z",
                "public_endpoint": "https://testnet.example",
                "network": "onyx-public-testnet-v1",
                "genesis_hash": "3" * 64,
                "start_height": 1_000,
                "start_block_hash": "4" * 64,
                "end_height": 11_000,
                "end_block_hash": "5" * 64,
                "supply_audit": supply_audit,
                "independent_nodes": 3,
                "node_ids": node_ids,
                "node_results": [
                    {
                        "node_id": node_id,
                        "revision": REVISION,
                        "final_height": 11_000,
                        "final_block_hash": "5" * 64,
                        "supply_audit": dict(supply_audit),
                    }
                    for node_id in node_ids
                ],
                "observed_blocks": 10_000,
                "reorg_scenarios": 1,
                "malformed_bundle_cases": 1,
                "dos_scenarios": 1,
                "migration_supply_reconciled": True,
                "unresolved_consensus_divergences": 0,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "soak.json", document)
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "public-testnet-soak",
                    [evidence],
                    root,
                ),
            )

            document["node_results"][1]["final_block_hash"] = "7" * 64
            document["node_results"][2]["supply_audit"]["circulating_supply"] += 1
            document["unresolved_consensus_divergences"] = 1
            evidence = self.write_document(root, "soak.json", document)
            errors = qualification_evidence.verify_gate(
                "public-testnet-soak",
                [evidence],
                root,
            )
            self.assertTrue(any("converge on end_block_hash" in error for error in errors))
            self.assertTrue(any("converge on the complete supply_audit" in error for error in errors))
            self.assertTrue(any("divergences must be zero" in error for error in errors))

    def test_attestation_cannot_complete_before_frozen_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = self.write_document(root, "audit-a.json", self.audit(root, "A Labs", "a.txt"))
            second = self.write_document(root, "audit-b.json", self.audit(root, "B Labs", "b.txt"))
            errors = qualification_evidence.verify_gate(
                "independent-audits",
                [first, second],
                root,
                revision_committed_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
            )
            self.assertEqual(
                2,
                sum("completed_at predates the frozen release revision" in error for error in errors),
                errors,
            )

    def test_public_endpoint_must_be_a_credential_free_https_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "public-testnet-soak",
                "revision": REVISION,
                "started_at": "2026-07-01T00:00:00Z",
                "completed_at": "2026-07-15T00:00:00Z",
                "public_endpoint": "https://user:secret@example.test",
                "independent_nodes": 3,
                "node_ids": ["node-a", "node-b", "node-c"],
                "observed_blocks": 10_000,
                "reorg_scenarios": 1,
                "malformed_bundle_cases": 1,
                "dos_scenarios": 1,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "soak.json", document)
            errors = qualification_evidence.verify_gate("public-testnet-soak", [evidence], root)
            self.assertTrue(any("public_endpoint must be HTTPS" in error for error in errors), errors)

    def test_incident_drill_requires_operational_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            scenarios = []
            for index, scenario_id in enumerate(("consensus-stall", "reorg", "proof-dos")):
                hour = 10 + index
                scenarios.append(
                    {
                        "id": scenario_id,
                        "detected_at": f"2026-07-17T{hour:02d}:00:00Z",
                        "triaged_at": f"2026-07-17T{hour:02d}:05:00Z",
                        "recovered_at": f"2026-07-17T{hour:02d}:30:00Z",
                        "artifacts_preserved": True,
                        "clean_room_reproduced": True,
                        "recovery_verified": True,
                    }
                )
            document = {
                "schema_version": 1,
                "gate_id": "incident-response-drill",
                "revision": REVISION,
                "started_at": "2026-07-17T09:00:00Z",
                "completed_at": "2026-07-17T14:00:00Z",
                "participants": 2,
                "participant_ids": ["operator-a", "operator-b"],
                "independent_observers": 1,
                "observer_ids": ["observer-a"],
                "decision_authority": "release incident commander",
                "communications_recorded": True,
                "migration_supply_reconciled": True,
                "unresolved_actions": [],
                "scenarios": scenarios,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "incident.json", document)
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "incident-response-drill",
                    [evidence],
                    root,
                ),
            )

            document["communications_recorded"] = False
            document["observer_ids"] = ["operator-a"]
            document["scenarios"][1]["clean_room_reproduced"] = False
            document["scenarios"][2]["triaged_at"] = "2026-07-17T13:00:00Z"
            evidence = self.write_document(root, "incident.json", document)
            errors = qualification_evidence.verify_gate(
                "incident-response-drill",
                [evidence],
                root,
            )
            self.assertTrue(any("communications_recorded must be true" in error for error in errors))
            self.assertTrue(any("must not be drill participants" in error for error in errors))
            self.assertTrue(any("clean_room_reproduced must be true" in error for error in errors))
            self.assertTrue(any("timestamps must be ordered" in error for error in errors))

    def test_incident_drill_cannot_start_before_frozen_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "incident-response-drill",
                "revision": REVISION,
                "started_at": "2026-07-17T09:00:00Z",
                "completed_at": "2026-07-17T14:00:00Z",
                "participants": 2,
                "participant_ids": ["operator-a", "operator-b"],
                "independent_observers": 1,
                "observer_ids": ["observer-a"],
                "decision_authority": "release incident commander",
                "communications_recorded": True,
                "migration_supply_reconciled": True,
                "unresolved_actions": [],
                "scenarios": [],
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "incident.json", document)
            errors = qualification_evidence.verify_gate(
                "incident-response-drill",
                [evidence],
                root,
                revision_committed_at=datetime(2026, 7, 17, 10, tzinfo=timezone.utc),
            )
            self.assertTrue(
                any("drill started before the frozen release revision" in error for error in errors),
                errors,
            )

    def test_governance_requires_exact_revision_quorum_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "governance-approval",
                "revision": REVISION,
                "approved_revision": REVISION,
                "proposal_id": "jade-onyx-activation-v1",
                "started_at": "2026-07-16T00:00:00Z",
                "completed_at": "2026-07-17T00:00:00Z",
                "compiler_digest": DIGEST,
                "target_profile_digest": DIGEST,
                "activation_heights": ACTIVATION_HEIGHTS,
                "quorum_met": True,
                "eligible_approvers": 3,
                "eligible_approver_ids": ["alice", "bob", "carol"],
                "required_approvals": 2,
                "approvals": 2,
                "approver_ids": ["alice", "bob"],
                "unresolved_blocking_objections": 0,
                "objections": [],
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "governance.json", document)
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "governance-approval",
                    [evidence],
                    root,
                    governance_digests=(DIGEST, DIGEST),
                    governance_activation_heights=ACTIVATION_HEIGHTS,
                ),
            )
            errors = qualification_evidence.verify_gate(
                "governance-approval",
                [evidence],
                root,
                governance_digests=("3" * 64, "4" * 64),
                governance_activation_heights=ACTIVATION_HEIGHTS,
            )
            self.assertTrue(any("does not match frozen release revision" in error for error in errors))
            document["approved_revision"] = "3" * 40
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate("governance-approval", [evidence], root)
            self.assertTrue(any("approved_revision" in error for error in errors), errors)
            document["approved_revision"] = REVISION
            document["required_approvals"] = 4
            document["approver_ids"] = ["alice", "mallory"]
            document["unresolved_blocking_objections"] = 1
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate(
                "governance-approval",
                [evidence],
                root,
                revision_committed_at=datetime(2026, 7, 16, 12, tzinfo=timezone.utc),
            )
            self.assertTrue(any("cannot exceed eligible_approvers" in error for error in errors))
            self.assertTrue(any("approvals must meet the threshold" in error for error in errors))
            self.assertTrue(any("eligible electorate" in error for error in errors))
            self.assertTrue(any("blocking_objections must be zero" in error for error in errors))
            self.assertTrue(
                any("vote started before the frozen release revision" in error for error in errors)
            )

    def test_governance_rejects_duplicate_normalized_approvers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "governance-approval",
                "revision": REVISION,
                "approved_revision": REVISION,
                "proposal_id": "jade-onyx-activation-v1",
                "started_at": "2026-07-16T00:00:00Z",
                "completed_at": "2026-07-17T00:00:00Z",
                "compiler_digest": DIGEST,
                "target_profile_digest": DIGEST,
                "activation_heights": ACTIVATION_HEIGHTS,
                "quorum_met": True,
                "eligible_approvers": 3,
                "eligible_approver_ids": ["alice", "bob", "carol"],
                "required_approvals": 2,
                "approvals": 2,
                "approver_ids": ["Alice", "  alice  "],
                "unresolved_blocking_objections": 0,
                "objections": [],
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate(
                "governance-approval", [evidence], root
            )
            self.assertTrue(any("distinct normalized identities" in error for error in errors), errors)

    def test_governance_must_approve_exact_activation_heights(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "governance-approval",
                "revision": REVISION,
                "approved_revision": REVISION,
                "proposal_id": "jade-onyx-activation-v1",
                "started_at": "2026-07-16T00:00:00Z",
                "completed_at": "2026-07-17T00:00:00Z",
                "compiler_digest": DIGEST,
                "target_profile_digest": DIGEST,
                "activation_heights": {
                    **ACTIVATION_HEIGHTS,
                    "UPGRADE_HEIGHT_ONYX": ACTIVATION_HEIGHTS["UPGRADE_HEIGHT_ONYX"] + 1,
                },
                "quorum_met": True,
                "eligible_approvers": 3,
                "eligible_approver_ids": ["alice", "bob", "carol"],
                "required_approvals": 2,
                "approvals": 2,
                "approver_ids": ["alice", "bob"],
                "unresolved_blocking_objections": 0,
                "objections": [],
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate(
                "governance-approval",
                [evidence],
                root,
                governance_activation_heights=ACTIVATION_HEIGHTS,
            )
            self.assertTrue(
                any("do not match activation configuration" in error for error in errors),
                errors,
            )

    def test_reproducibility_binds_every_program_and_independent_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            platforms = []
            for name in sorted(qualification_evidence.REQUIRED_PLATFORMS):
                builder_ids = [f"{name}-a", f"{name}-b"]
                platforms.append(
                    {
                        "name": name,
                        "independent_builders": 2,
                        "builder_ids": builder_ids,
                        "hashes_match": True,
                        "builders": [
                            {
                                "builder_id": builder_id,
                                "revision": REVISION,
                                "environment_sha256": str(index + 3) * 64,
                                "compiler": "pinned compiler",
                                "sdk": "pinned sdk",
                                "linker": "pinned linker",
                                "dependencies_lock_sha256": DIGEST,
                            }
                            for index, builder_id in enumerate(builder_ids)
                        ],
                        "artifacts": [
                            {
                                "name": program,
                                "binary_sha256": "5" * 64,
                                "debug_symbols_sha256": "6" * 64,
                                "sbom_sha256": "7" * 64,
                                "builds": [
                                    {
                                        "builder_id": builder_id,
                                        "binary_sha256": "5" * 64,
                                        "debug_symbols_sha256": "6" * 64,
                                        "sbom_sha256": "7" * 64,
                                    }
                                    for builder_id in builder_ids
                                ],
                            }
                            for program in sorted(
                                qualification_evidence.REQUIRED_RELEASE_PROGRAMS
                            )
                        ],
                    }
                )
            document = {
                "schema_version": 1,
                "gate_id": "reproducible-platform-binaries",
                "revision": REVISION,
                "completed_at": "2026-07-17T00:00:00Z",
                "platforms": platforms,
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "reproducibility.json", document)
            self.assertEqual(
                [],
                qualification_evidence.verify_gate(
                    "reproducible-platform-binaries",
                    [evidence],
                    root,
                    dependencies_lock_digest=DIGEST,
                ),
            )
            platforms[0]["builders"][1]["environment_sha256"] = platforms[0]["builders"][0][
                "environment_sha256"
            ]
            platforms[0]["artifacts"][0]["builds"][1]["binary_sha256"] = "8" * 64
            evidence = self.write_document(root, "reproducibility.json", document)
            errors = qualification_evidence.verify_gate(
                "reproducible-platform-binaries",
                [evidence],
                root,
                dependencies_lock_digest=DIGEST,
            )
            self.assertTrue(
                any("distinct environment identities" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("every builder binary_sha256 must match" in error for error in errors),
                errors,
            )

    def test_attestation_and_artifact_paths_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            root = parent / "repository"
            root.mkdir()
            outside = parent / "outside.json"
            document = self.audit(root, "A Labs", "report.txt")
            outside.write_text(json.dumps(document), encoding="utf-8")
            errors = qualification_evidence.verify_gate(
                "independent-audits", ["../outside.json", "../outside.json"], root
            )
            self.assertTrue(any("invalid repository evidence path" in error for error in errors))

            document["artifact"]["path"] = "../outside-report.txt"
            first = self.write_document(root, "audit-a.json", document)
            second = self.write_document(root, "audit-b.json", self.audit(root, "B Labs", "b.txt"))
            errors = qualification_evidence.verify_gate(
                "independent-audits", [first, second], root
            )
            self.assertTrue(
                any("artifact.path must be a contained repository file" in error for error in errors),
                errors,
            )

    def test_auditor_identity_normalization_prevents_whitespace_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first = self.write_document(root, "audit-a.json", self.audit(root, "A Labs", "a.txt"))
            second = self.write_document(
                root, "audit-b.json", self.audit(root, "  a   labs  ", "b.txt")
            )
            errors = qualification_evidence.verify_gate(
                "independent-audits", [first, second], root
            )
            self.assertTrue(any("distinct organizations" in error for error in errors), errors)

    def test_future_dated_attestation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            first_document = self.audit(root, "A Labs", "a.txt")
            first_document["completed_at"] = "2999-01-01T00:00:00Z"
            first = self.write_document(root, "audit-a.json", first_document)
            second = self.write_document(root, "audit-b.json", self.audit(root, "B Labs", "b.txt"))
            errors = qualification_evidence.verify_gate(
                "independent-audits", [first, second], root
            )
            self.assertTrue(any("completed_at cannot be in the future" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
