#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "release"))

import qualification_evidence  # noqa: E402


REVISION = "1" * 40
DIGEST = "2" * 64


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
            "completed_at": "2026-07-17T00:00:00Z",
            "auditor": {"organization": organization},
            "unresolved_findings": {"critical": 0, "high": 0},
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
        return {
            "schema_version": 1,
            "gate_id": "source-provenance",
            "revision": REVISION,
            "completed_at": "2026-07-17T00:00:00Z",
            "independent_builders": 2,
            "builder_ids": ["builder-a", "builder-b"],
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
                ),
            )

            document["builder_ids"] = ["same builder", " Same  Builder "]
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

    def test_governance_requires_exact_revision_quorum_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "governance-approval",
                "revision": REVISION,
                "approved_revision": REVISION,
                "completed_at": "2026-07-17T00:00:00Z",
                "compiler_digest": DIGEST,
                "target_profile_digest": DIGEST,
                "quorum_met": True,
                "approvals": 2,
                "approver_ids": ["alice", "bob"],
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
                ),
            )
            errors = qualification_evidence.verify_gate(
                "governance-approval",
                [evidence],
                root,
                governance_digests=("3" * 64, "4" * 64),
            )
            self.assertTrue(any("does not match frozen release revision" in error for error in errors))
            document["approved_revision"] = "3" * 40
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate("governance-approval", [evidence], root)
            self.assertTrue(any("approved_revision" in error for error in errors), errors)

    def test_governance_rejects_duplicate_normalized_approvers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            document = {
                "schema_version": 1,
                "gate_id": "governance-approval",
                "revision": REVISION,
                "approved_revision": REVISION,
                "completed_at": "2026-07-17T00:00:00Z",
                "compiler_digest": DIGEST,
                "target_profile_digest": DIGEST,
                "quorum_met": True,
                "approvals": 2,
                "approver_ids": ["Alice", "  alice  "],
                "artifact": self.write_artifact(root),
            }
            evidence = self.write_document(root, "governance.json", document)
            errors = qualification_evidence.verify_gate(
                "governance-approval", [evidence], root
            )
            self.assertTrue(any("distinct normalized identities" in error for error in errors), errors)

    def test_reproducibility_binds_each_builder_to_identical_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            platforms = []
            for name in sorted(qualification_evidence.REQUIRED_PLATFORMS):
                platforms.append(
                    {
                        "name": name,
                        "independent_builders": 2,
                        "builder_ids": [f"{name}-a", f"{name}-b"],
                        "hashes_match": True,
                        "normalized_sha256": DIGEST,
                        "builds": [
                            {"builder_id": f"{name}-a", "sha256": DIGEST},
                            {"builder_id": f"{name}-b", "sha256": DIGEST},
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
                    "reproducible-platform-binaries", [evidence], root
                ),
            )
            platforms[0]["builds"][1]["sha256"] = "3" * 64
            evidence = self.write_document(root, "reproducibility.json", document)
            errors = qualification_evidence.verify_gate(
                "reproducible-platform-binaries", [evidence], root
            )
            self.assertTrue(
                any("every builder hash must equal normalized_sha256" in error for error in errors),
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
