#!/usr/bin/env python3
"""Prevent activation-height changes while mandatory release evidence is incomplete."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from create_source_archive import create as create_source_archive
from generate_spdx import generate as generate_spdx
from release_common import (
    ROOT,
    canonical_json_bytes,
    revision_file,
    revision_file_sha256,
    sha256_file,
    source_date_epoch,
    strict_json_loads,
    tracked_files,
)
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
REQUIRED_ACTIVATION_HEIGHTS = {
    "UPGRADE_HEIGHT_V5",
    "RANDOMX_SWITCH_HEIGHT",
    "UPGRADE_HEIGHT_RESERVED_V6",
    "UPGRADE_HEIGHT_ONYX",
}


def tracked_worktree_changes(root: Path = ROOT) -> list[str]:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )
    return [line for line in result.stdout.splitlines() if line]


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


def changed_paths_since(revision: str) -> set[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACDMRTUXB", revision, "HEAD", "--"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, result.args, output=result.stdout, stderr=result.stderr
        )
    return {line for line in result.stdout.splitlines() if line}


def qualification_paths(gates: list[dict], tracked: set[str]) -> set[str]:
    allowed = {
        "release/activation-gates.json",
        "src/CryptoNoteConfig.hpp",
    }
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        evidence = gate.get("evidence")
        if not isinstance(evidence, list):
            continue
        gate_id = gate.get("id")
        for relative in evidence:
            if (
                not isinstance(relative, str)
                or not relative.startswith("release/evidence/")
                or not relative.endswith(".json")
            ):
                continue
            path = _repository_file(ROOT, relative)
            if path is None or relative not in tracked:
                continue
            try:
                document = strict_json_loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                continue
            if not isinstance(document, dict) or document.get("gate_id") != gate_id:
                continue
            allowed.add(relative)
            bindings = []
            if isinstance(document.get("artifact"), dict):
                bindings.append(document["artifact"])
            artifacts = document.get("artifacts")
            if isinstance(artifacts, dict):
                bindings.extend(binding for binding in artifacts.values() if isinstance(binding, dict))
            for binding in bindings:
                artifact_path = binding.get("path")
                if (
                    isinstance(artifact_path, str)
                    and artifact_path.startswith("release/evidence/")
                    and artifact_path in tracked
                    and _repository_file(ROOT, artifact_path) is not None
                ):
                    allowed.add(artifact_path)
    return allowed


def config_changed_only_at_activation_heights(
    revision: str, current_config: str, height_names: set[str]
) -> bool:
    frozen = revision_file(revision, "src/CryptoNoteConfig.hpp").decode("utf-8")

    def normalize(config: str) -> str:
        config = config.replace("\r\n", "\n")
        for name in sorted(height_names):
            config, count = re.subn(
                rf"(\b{re.escape(name)}\s*=\s*)\d+(\s*;)",
                rf"\g<1><ACTIVATION_HEIGHT:{name}>\g<2>",
                config,
            )
            if count != 1:
                raise ValueError(f"activation constant must occur exactly once: {name}")
        return config

    return normalize(frozen) == normalize(current_config)


def governance_digests_at_revision(revision: str) -> tuple[str, str]:
    compiler = revision_file(revision, "tools/onyx/compiler_v1.py").replace(b"\r\n", b"\n")
    compiler_digest = hashlib.sha256(compiler).hexdigest()
    target_digests: set[str] = set()
    for program in STANDARD_PROGRAMS:
        manifest = strict_json_loads(
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


def source_digests_at_revision(revision: str) -> tuple[str, str]:
    epoch = source_date_epoch(revision)
    with tempfile.TemporaryDirectory(prefix="bytecoin-gate-source-") as temporary:
        archive = Path(temporary) / f"bytecoin-{revision[:12]}-source.tar.gz"
        create_source_archive(archive, revision, epoch)
        archive_digest = sha256_file(archive)
    sbom_digest = hashlib.sha256(
        canonical_json_bytes(generate_spdx(revision, epoch))
    ).hexdigest()
    return archive_digest, sbom_digest


def governance_order_errors(gates: list[dict], root: Path = ROOT) -> list[str]:
    by_id = {
        gate.get("id"): gate
        for gate in gates
        if isinstance(gate, dict) and isinstance(gate.get("id"), str)
    }
    governance = by_id.get("governance-approval")
    if not isinstance(governance, dict) or governance.get("status") != "passed":
        return []
    prerequisites = REQUIRED_GATES - {"governance-approval"}
    incomplete = sorted(
        gate_id
        for gate_id in prerequisites
        if by_id.get(gate_id, {}).get("status") != "passed"
    )
    errors = []
    if incomplete:
        errors.append(
            "governance-approval: vote cannot pass before prerequisite gates: "
            f"{incomplete}"
        )
        return errors

    def timestamps(gate: dict, field: str) -> list[datetime]:
        values = []
        for relative in gate.get("evidence", []):
            if not isinstance(relative, str) or not relative.endswith(".json"):
                continue
            path = _repository_file(root, relative)
            if path is None:
                continue
            try:
                document = strict_json_loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                continue
            value = document.get(field) if isinstance(document, dict) else None
            if (
                not isinstance(document, dict)
                or document.get("gate_id") != gate.get("id")
                or not isinstance(value, str)
                or not value.endswith("Z")
            ):
                continue
            try:
                values.append(
                    datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
                )
            except ValueError:
                continue
        return values

    prerequisite_completions = [
        completed
        for gate_id in prerequisites
        for completed in timestamps(by_id[gate_id], "completed_at")
    ]
    governance_starts = timestamps(governance, "started_at")
    if (
        prerequisite_completions
        and governance_starts
        and min(governance_starts) < max(prerequisite_completions)
    ):
        errors.append(
            "governance-approval: vote must start after all prerequisite qualification completes"
        )
    return errors


def verify(gates_document: dict, config: str) -> tuple[list[str], list[str]]:
    if not isinstance(gates_document, dict):
        return ["activation gates document must be an object"], []
    errors: list[str] = []
    tracked = set(tracked_files())
    if gates_document.get("schema_version") != 1:
        errors.append("activation gate schema_version must be 1")
    gates = gates_document.get("gates", [])
    if not isinstance(gates, list):
        return ["activation gates must be an array"], []
    by_id = {
        gate.get("id"): gate
        for gate in gates
        if isinstance(gate, dict) and isinstance(gate.get("id"), str)
    }
    if len(by_id) != len(gates):
        errors.append("activation gate identifiers must be present and unique")
    if missing := REQUIRED_GATES - by_id.keys():
        errors.append(f"missing activation gates: {sorted(missing)}")
    if unknown := by_id.keys() - REQUIRED_GATES:
        errors.append(f"unknown activation gates: {sorted(unknown)}")
    for gate_id in REQUIRED_GATES & by_id.keys():
        if by_id[gate_id].get("required_for_activation") is not True:
            errors.append(f"{gate_id}: required_for_activation must be true")
    placeholders = gates_document.get("placeholder_heights")
    if not isinstance(placeholders, dict) or set(placeholders) != REQUIRED_ACTIVATION_HEIGHTS:
        errors.append(
            f"placeholder_heights must contain exactly {sorted(REQUIRED_ACTIVATION_HEIGHTS)}"
        )
        placeholders = {}
    current: dict[str, int] = {}
    for name, expected in placeholders.items():
        match = re.search(rf"\b{name}\s*=\s*(\d+)\s*;", config)
        if not match:
            errors.append(f"activation constant not found: {name}")
            continue
        current[name] = int(match.group(1))
        if not isinstance(expected, int) or isinstance(expected, bool) or expected <= 0:
            errors.append(f"invalid placeholder height for {name}")
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
    revision_committed_at = None
    authoritative_source_digests = None
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
            revision_committed_at = datetime.fromtimestamp(
                source_date_epoch(release_revision), timezone.utc
            )
        except (OSError, OverflowError, ValueError, subprocess.CalledProcessError) as error:
            errors.append(f"cannot derive frozen revision metadata: {error}")
        try:
            allowed = qualification_paths(gates, tracked)
            unexpected = changed_paths_since(release_revision) - allowed
            if unexpected:
                errors.append(
                    "post-freeze changes outside qualification evidence and activation configuration: "
                    f"{sorted(unexpected)}"
                )
        except subprocess.CalledProcessError as error:
            errors.append(f"cannot inspect post-freeze changes: {error}")
        try:
            if not config_changed_only_at_activation_heights(
                release_revision, config, set(gates_document.get("placeholder_heights", {}))
            ):
                errors.append(
                    "post-freeze CryptoNoteConfig changes must be limited to declared activation heights"
                )
        except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
            errors.append(f"cannot validate post-freeze activation configuration: {error}")
    if (
        by_id.get("source-provenance", {}).get("status") == "passed"
        and isinstance(release_revision, str)
        and re.fullmatch(r"[0-9a-f]{40}", release_revision)
        and frozen_revision_is_ancestor(release_revision)
    ):
        try:
            authoritative_source_digests = source_digests_at_revision(release_revision)
        except (
            OSError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
            subprocess.CalledProcessError,
        ) as error:
            errors.append(f"cannot regenerate frozen source evidence: {error}")
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
        if not isinstance(status, str) or status not in ALLOWED_STATUS:
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
                    revision_committed_at,
                    current,
                    authoritative_source_digests,
                )
            )
    audit_gate = by_id.get("independent-audits", {})
    minimum_reports = audit_gate.get("minimum_independent_reports", 2)
    if (
        not isinstance(minimum_reports, int)
        or isinstance(minimum_reports, bool)
        or minimum_reports != 2
    ):
        errors.append("independent-audits: minimum_independent_reports must equal 2")
    elif (
        audit_gate.get("status") == "passed"
        and isinstance(audit_gate.get("evidence"), list)
        and len(audit_gate["evidence"]) < minimum_reports
    ):
        errors.append("independent-audits: passed status requires two distinct report paths")
    errors.extend(governance_order_errors(gates))

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
    try:
        dirty = tracked_worktree_changes()
    except subprocess.CalledProcessError as error:
        print(f"ERROR: cannot inspect tracked worktree state: {error}", file=sys.stderr)
        return 1
    if dirty:
        print(
            "ERROR: release-gate evidence and activation configuration must be committed; "
            f"tracked worktree changes: {dirty}",
            file=sys.stderr,
        )
        return 1
    gate_path = ROOT / "release" / "activation-gates.json"
    try:
        gates_document = strict_json_loads(gate_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"ERROR: invalid activation-gate JSON: {error}", file=sys.stderr)
        return 1
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
