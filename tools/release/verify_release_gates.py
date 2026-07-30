#!/usr/bin/env python3
"""Prevent activation-height changes while mandatory release evidence is incomplete."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys

from release_common import ROOT, revision_file, revision_file_sha256, tracked_files
from qualification_evidence import _repository_file, verify_gate


REQUIRED_GATES = {
    "source-provenance",
    "independent-audits",
    "public-testnet-soak",
    "reproducible-platform-binaries",
    "incident-response-drill",
    "governance-approval",
}
ALLOWED_STATUS = {"pending", "implemented", "passed"}
STANDARD_PROGRAMS = ("nft", "vesting", "multisig", "swap")


def frozen_revision_is_ancestor(revision: str) -> bool:
    commit = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if commit.returncode != 0:
        return False
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", revision, "HEAD"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return ancestor.returncode == 0


def governance_digests_at_revision(revision: str) -> tuple[str, str]:
    compiler = revision_file(revision, "tools/onyx/compiler_v1.py").replace(b"\r\n", b"\n")
    compiler_digest = hashlib.sha256(compiler).hexdigest()
    target_digests: set[str] = set()
    for program in STANDARD_PROGRAMS:
        manifest = json.loads(
            revision_file(
                revision, f"programs/onyx-standard/{program}/onyx-package.json"
            )
        )
        if manifest.get("compiler_build_digest") != compiler_digest:
            raise ValueError(f"{program} compiler digest does not match compiler source")
        target_digest = manifest.get("target_profile_digest")
        if not isinstance(target_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", target_digest):
            raise ValueError(f"{program} target profile digest is invalid")
        target_digests.add(target_digest)
    if len(target_digests) != 1:
        raise ValueError("standard programs do not share one target profile digest")
    return compiler_digest, next(iter(target_digests))


def verify(gates_document: dict, config: str) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    tracked = set(tracked_files())
    if gates_document.get("schema_version") != 1:
        errors.append("activation gate schema_version must be 1")
    gates = gates_document.get("gates", [])
    if not isinstance(gates, list):
        return ["activation gates must be an array"], []
    by_id = {gate.get("id"): gate for gate in gates if isinstance(gate, dict)}
    if len(by_id) != len(gates):
        errors.append("activation gate identifiers must be present and unique")
    if missing := REQUIRED_GATES - by_id.keys():
        errors.append(f"missing activation gates: {sorted(missing)}")
    if unknown := by_id.keys() - REQUIRED_GATES:
        errors.append(f"unknown activation gates: {sorted(unknown)}")
    for gate_id in REQUIRED_GATES & by_id.keys():
        if by_id[gate_id].get("required_for_activation") is not True:
            errors.append(f"{gate_id}: required_for_activation must be true")
    passed_external = [
        gate_id
        for gate_id, gate in by_id.items()
        if gate_id
        in {
            "source-provenance",
            "independent-audits",
            "public-testnet-soak",
            "reproducible-platform-binaries",
            "incident-response-drill",
            "governance-approval",
        }
        and gate.get("status") == "passed"
    ]
    release_revision = gates_document.get("release_revision")
    if passed_external and (
        not isinstance(release_revision, str)
        or not re.fullmatch(r"[0-9a-f]{40}", release_revision)
    ):
        errors.append("passed external gates require one frozen lowercase 40-character release_revision")
    elif passed_external and not frozen_revision_is_ancestor(release_revision):
        errors.append(
            "frozen release_revision must name an existing commit that is an ancestor of HEAD"
        )
    governance_digests = None
    dependencies_lock_digest = None
    if (
        passed_external
        and isinstance(release_revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", release_revision)
        and frozen_revision_is_ancestor(release_revision)
    ):
        try:
            dependencies_lock_digest = revision_file_sha256(
                release_revision, "release/dependencies.lock.json"
            )
        except (OSError, subprocess.CalledProcessError) as error:
            errors.append(f"cannot derive frozen dependency-lock digest: {error}")
    if (
        by_id.get("governance-approval", {}).get("status") == "passed"
        and isinstance(release_revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", release_revision)
        and frozen_revision_is_ancestor(release_revision)
    ):
        try:
            governance_digests = governance_digests_at_revision(release_revision)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
            errors.append(f"cannot derive frozen governance digests: {error}")
    for gate_id, gate in by_id.items():
        status = gate.get("status")
        evidence = gate.get("evidence")
        if status not in ALLOWED_STATUS:
            errors.append(f"{gate_id}: invalid status {status}")
        if not isinstance(evidence, list):
            errors.append(f"{gate_id}: evidence must be an array")
            continue
        for relative in evidence:
            path = _repository_file(ROOT, relative)
            if path is None:
                errors.append(f"{gate_id}: invalid repository evidence {relative!r}")
            elif relative not in tracked:
                errors.append(f"{gate_id}: evidence is not Git-tracked: {relative!r}")
        if status == "passed" and not evidence:
            errors.append(f"{gate_id}: passed status requires concrete evidence")
        if status == "passed":
            errors.extend(
                verify_gate(
                    gate_id,
                    evidence,
                    ROOT,
                    release_revision if isinstance(release_revision, str) else None,
                    tracked,
                    governance_digests,
                    dependencies_lock_digest,
                )
            )
    audit_gate = by_id.get("independent-audits", {})
    if audit_gate.get("status") == "passed" and len(audit_gate.get("evidence", [])) < int(
        audit_gate.get("minimum_independent_reports", 2)
    ):
        errors.append("independent-audits: passed status requires two distinct report paths")

    placeholders = gates_document.get("placeholder_heights", {})
    current: dict[str, int] = {}
    for name, expected in placeholders.items():
        match = re.search(rf"\b{name}\s*=\s*(\d+)\s*;", config)
        if not match:
            errors.append(f"activation constant not found: {name}")
            continue
        current[name] = int(match.group(1))
        if not isinstance(expected, int) or expected <= 0:
            errors.append(f"invalid placeholder height for {name}")

    incomplete = [
        gate_id
        for gate_id in sorted(REQUIRED_GATES)
        if by_id.get(gate_id, {}).get("status") != "passed"
    ]
    if incomplete:
        for name, expected in placeholders.items():
            if current.get(name) != expected:
                errors.append(
                    f"{name} changed from fail-closed placeholder {expected} while gates remain incomplete: {incomplete}"
                )
    return errors, incomplete


def main() -> int:
    gate_path = ROOT / "release" / "activation-gates.json"
    gates_document = json.loads(gate_path.read_text(encoding="utf-8"))
    config = (ROOT / "src" / "CryptoNoteConfig.hpp").read_text(encoding="utf-8")
    errors, incomplete = verify(gates_document, config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"release gates verified; incomplete activation gates: {', '.join(incomplete) if incomplete else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
