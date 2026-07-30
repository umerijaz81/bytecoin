#!/usr/bin/env python3
"""Validate typed evidence before an external release gate may pass."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import pathlib
import re
import urllib.parse


EXTERNAL_GATES = {
    "source-provenance",
    "independent-audits",
    "public-testnet-soak",
    "reproducible-platform-binaries",
    "incident-response-drill",
    "governance-approval",
}
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PLATFORMS = {"linux-x86_64", "macos-arm64", "windows-x86_64"}


def _repository_file(root: pathlib.Path, relative: object) -> pathlib.Path | None:
    if (
        not isinstance(relative, str)
        or not relative
        or "\\" in relative
        or pathlib.PurePosixPath(relative).is_absolute()
        or any(part in ("", ".", "..") for part in pathlib.PurePosixPath(relative).parts)
    ):
        return None
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    return path if path.is_file() else None


def _integer(document: dict, key: str, minimum: int, errors: list[str], label: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        errors.append(f"{label}: {key} must be an integer >= {minimum}")
        return 0
    return value


def _distinct_identities(
    document: dict,
    count_key: str,
    identities_key: str,
    minimum: int,
    errors: list[str],
    label: str,
) -> list[str] | None:
    count = _integer(document, count_key, minimum, errors, label)
    identities = document.get(identities_key)
    if not isinstance(identities, list):
        errors.append(f"{label}: {identities_key} must be an array of distinct identities")
        return None
    normalized = []
    for identity in identities:
        if not isinstance(identity, str) or not identity.strip():
            errors.append(f"{label}: {identities_key} contains an invalid identity")
            continue
        normalized.append(" ".join(identity.split()).casefold())
    if len(normalized) != count or len(set(normalized)) != count:
        errors.append(
            f"{label}: {identities_key} must contain exactly {count} distinct normalized identities"
        )
        return None
    return normalized


def _utc(value: object, key: str, errors: list[str], label: str) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        errors.append(f"{label}: {key} must be an ISO-8601 UTC timestamp")
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        errors.append(f"{label}: invalid {key}")
        return None


def _valid_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        return None


def _common(document: dict, gate_id: str, label: str) -> list[str]:
    errors: list[str] = []
    if document.get("schema_version") != 1:
        errors.append(f"{label}: schema_version must be 1")
    if document.get("gate_id") != gate_id:
        errors.append(f"{label}: gate_id must be {gate_id}")
    if not isinstance(document.get("revision"), str) or not REVISION.fullmatch(document["revision"]):
        errors.append(f"{label}: revision must be a lowercase 40-character Git object id")
    completed = _utc(document.get("completed_at"), "completed_at", errors, label)
    if completed and completed > datetime.now(timezone.utc) + timedelta(minutes=5):
        errors.append(f"{label}: completed_at cannot be in the future")
    return errors


def _artifact(
    document: dict,
    root: pathlib.Path,
    errors: list[str],
    label: str,
    tracked_paths: set[str] | None,
) -> None:
    artifact = document.get("artifact")
    if not isinstance(artifact, dict):
        errors.append(f"{label}: artifact must bind a repository file and SHA-256")
        return
    relative, expected = artifact.get("path"), artifact.get("sha256")
    if not isinstance(expected, str) or not HEX_32.fullmatch(expected):
        errors.append(f"{label}: artifact.sha256 must be lowercase SHA-256")
        return
    path = _repository_file(root, relative)
    if path is None:
        errors.append(f"{label}: artifact.path must be a contained repository file")
    elif tracked_paths is not None and relative not in tracked_paths:
        errors.append(f"{label}: artifact is not Git-tracked: {relative}")
    elif hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        errors.append(f"{label}: artifact digest mismatch: {relative}")


def _source_provenance(
    document: dict,
    root: pathlib.Path,
    label: str,
    tracked_paths: set[str] | None,
    dependencies_lock_digest: str | None,
) -> list[str]:
    errors = _common(document, "source-provenance", label)
    _distinct_identities(
        document, "independent_builders", "builder_ids", 2, errors, label
    )
    if document.get("source_archive_identical") is not True:
        errors.append(f"{label}: source_archive_identical must be true")
    if document.get("spdx_sbom_identical") is not True:
        errors.append(f"{label}: spdx_sbom_identical must be true")
    lock_digest = document.get("dependencies_lock_sha256")
    if not isinstance(lock_digest, str) or not HEX_32.fullmatch(lock_digest):
        errors.append(f"{label}: dependencies_lock_sha256 must be lowercase SHA-256")
    elif dependencies_lock_digest is not None and lock_digest != dependencies_lock_digest:
        errors.append(
            f"{label}: dependencies_lock_sha256 does not match frozen release revision"
        )

    artifacts = document.get("artifacts")
    required = {"source_archive", "spdx_sbom", "provenance", "checksums"}
    if not isinstance(artifacts, dict) or set(artifacts) != required:
        errors.append(f"{label}: artifacts must bind exactly {sorted(required)}")
        return errors
    paths: list[str] = []
    for name in sorted(required):
        binding = artifacts.get(name)
        _artifact({"artifact": binding}, root, errors, f"{label}:{name}", tracked_paths)
        if isinstance(binding, dict) and isinstance(binding.get("path"), str):
            paths.append(binding["path"])
    if any(
        not isinstance(artifacts[name], dict)
        or not isinstance(artifacts[name].get("sha256"), str)
        or not HEX_32.fullmatch(artifacts[name]["sha256"])
        for name in required
    ):
        return errors
    if len(paths) != len(set(paths)):
        errors.append(f"{label}: artifact paths must be distinct")
        return errors

    resolved = {
        name: _repository_file(root, artifacts[name].get("path"))
        for name in required
        if isinstance(artifacts[name], dict)
    }
    if len(resolved) != len(required) or any(path is None for path in resolved.values()):
        return errors

    revision = document.get("revision")
    if not isinstance(revision, str) or not REVISION.fullmatch(revision):
        return errors
    expected_names = {
        "source_archive": f"bytecoin-{revision[:12]}-source.tar.gz",
        "spdx_sbom": f"bytecoin-{revision[:12]}.spdx.json",
        "provenance": f"bytecoin-{revision[:12]}.provenance.json",
        "checksums": "SHA256SUMS",
    }
    for name, expected_name in expected_names.items():
        if resolved[name].name != expected_name:
            errors.append(f"{label}:{name}: filename must be {expected_name}")

    try:
        provenance = json.loads(resolved["provenance"].read_text(encoding="utf-8"))
        sbom = json.loads(resolved["spdx_sbom"].read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"{label}: invalid provenance or SPDX JSON: {error}")
        return errors
    if not isinstance(provenance, dict):
        errors.append(f"{label}: provenance artifact must contain a JSON object")
    else:
        if provenance.get("schema") != "bytecoin-release-provenance/v1":
            errors.append(f"{label}: provenance schema must be bytecoin-release-provenance/v1")
        if provenance.get("revision") != revision:
            errors.append(f"{label}: provenance revision must equal attested revision")
        if provenance.get("dirty_worktree") is not False:
            errors.append(f"{label}: provenance dirty_worktree must be false")
        if provenance.get("dependencies_lock_sha256") != lock_digest:
            errors.append(f"{label}: provenance dependency-lock digest mismatch")
        reproduction = provenance.get("reproduction")
        generations = (
            reproduction.get("independent_generations")
            if isinstance(reproduction, dict)
            else None
        )
        if (
            not isinstance(reproduction, dict)
            or not isinstance(generations, int)
            or isinstance(generations, bool)
            or generations < 2
            or reproduction.get("source_archive_identical") is not True
            or reproduction.get("spdx_sbom_identical") is not True
        ):
            errors.append(f"{label}: provenance must record two identical independent generations")
        expected_materials = {
            resolved[name].name: artifacts[name]["sha256"]
            for name in ("source_archive", "spdx_sbom")
        }
        materials = provenance.get("materials")
        actual_materials = {}
        if isinstance(materials, list):
            for material in materials:
                if (
                    isinstance(material, dict)
                    and isinstance(material.get("name"), str)
                    and isinstance(material.get("sha256"), str)
                ):
                    actual_materials[material["name"]] = material["sha256"]
        if (
            not isinstance(materials, list)
            or len(materials) != 2
            or actual_materials != expected_materials
        ):
            errors.append(f"{label}: provenance materials do not bind the source archive and SPDX SBOM")

    root_package = None
    if isinstance(sbom, dict):
        packages = sbom.get("packages")
        if isinstance(packages, list):
            root_package = next(
                (
                    package
                    for package in packages
                    if isinstance(package, dict)
                    and package.get("SPDXID") == "SPDXRef-Package-bytecoin"
                ),
                None,
            )
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("name") != f"bytecoin-{revision}"
        or not isinstance(root_package, dict)
        or root_package.get("versionInfo") != revision
    ):
        errors.append(f"{label}: SPDX SBOM does not describe the attested revision")

    expected_checksums = {
        resolved[name].name: artifacts[name]["sha256"]
        for name in ("source_archive", "spdx_sbom", "provenance")
    }
    actual_checksums: dict[str, str] = {}
    try:
        lines = resolved["checksums"].read_text(encoding="ascii").splitlines()
    except UnicodeError as error:
        errors.append(f"{label}: invalid SHA256SUMS encoding: {error}")
        return errors
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\\]+)", line)
        if match is None or match.group(2) in actual_checksums:
            errors.append(f"{label}: SHA256SUMS must use canonical unique entries")
            break
        actual_checksums[match.group(2)] = match.group(1)
    if actual_checksums != expected_checksums:
        errors.append(f"{label}: SHA256SUMS does not bind the generated evidence artifacts")
    return errors


def _audit(
    document: dict, root: pathlib.Path, label: str, tracked_paths: set[str] | None
) -> tuple[list[str], str | None]:
    errors = _common(document, "independent-audits", label)
    auditor = document.get("auditor")
    organization = auditor.get("organization") if isinstance(auditor, dict) else None
    if not isinstance(organization, str) or not organization.strip():
        errors.append(f"{label}: auditor.organization is required")
        organization = None
    findings = document.get("unresolved_findings")
    if not isinstance(findings, dict) or findings.get("critical") != 0 or findings.get("high") != 0:
        errors.append(f"{label}: unresolved critical and high findings must both be zero")
    _artifact(document, root, errors, label, tracked_paths)
    normalized = " ".join(organization.split()).casefold() if organization else None
    return errors, normalized


def _testnet(
    document: dict, root: pathlib.Path, label: str, tracked_paths: set[str] | None
) -> list[str]:
    errors = _common(document, "public-testnet-soak", label)
    start = _utc(document.get("started_at"), "started_at", errors, label)
    end = _utc(document.get("completed_at"), "completed_at", errors, label)
    if start and end and (end - start).total_seconds() < 14 * 24 * 60 * 60:
        errors.append(f"{label}: public testnet soak must cover at least 14 days")
    endpoint = document.get("public_endpoint")
    endpoint_valid = False
    if isinstance(endpoint, str) and endpoint and not any(character.isspace() for character in endpoint):
        try:
            parsed = urllib.parse.urlsplit(endpoint)
            port_valid = parsed.port is None or 1 <= parsed.port <= 65535
            endpoint_valid = (
                parsed.scheme == "https"
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.fragment == ""
                and port_valid
            )
        except ValueError:
            endpoint_valid = False
    if not endpoint_valid:
        errors.append(f"{label}: public_endpoint must be HTTPS")
    _distinct_identities(
        document, "independent_nodes", "node_ids", 3, errors, label
    )
    for key, minimum in {
        "observed_blocks": 10_000,
        "reorg_scenarios": 1,
        "malformed_bundle_cases": 1,
        "dos_scenarios": 1,
    }.items():
        _integer(document, key, minimum, errors, label)
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _reproducibility(
    document: dict, root: pathlib.Path, label: str, tracked_paths: set[str] | None
) -> list[str]:
    errors = _common(document, "reproducible-platform-binaries", label)
    platforms = document.get("platforms")
    if not isinstance(platforms, list):
        errors.append(f"{label}: platforms must be an array")
    else:
        listed_names = [item.get("name") for item in platforms if isinstance(item, dict)]
        names = set(listed_names)
        if names != REQUIRED_PLATFORMS or len(listed_names) != len(REQUIRED_PLATFORMS):
            errors.append(
                f"{label}: platforms must contain each required platform exactly once"
            )
        for item in platforms:
            if not isinstance(item, dict):
                errors.append(f"{label}: invalid platform entry")
                continue
            name = item.get("name", "unknown")
            builder_ids = _distinct_identities(
                item,
                "independent_builders",
                "builder_ids",
                2,
                errors,
                f"{label}:{name}",
            )
            if item.get("hashes_match") is not True:
                errors.append(f"{label}:{name}: hashes_match must be true")
            normalized_sha256 = item.get("normalized_sha256")
            if not isinstance(normalized_sha256, str) or not HEX_32.fullmatch(normalized_sha256):
                errors.append(f"{label}:{name}: normalized_sha256 must be lowercase SHA-256")
            builds = item.get("builds")
            if not isinstance(builds, list):
                errors.append(f"{label}:{name}: builds must bind each builder identity and hash")
                continue
            build_ids: list[str] = []
            build_hashes: list[str] = []
            for build in builds:
                if not isinstance(build, dict):
                    errors.append(f"{label}:{name}: invalid build entry")
                    continue
                builder_id = build.get("builder_id")
                digest = build.get("sha256")
                if not isinstance(builder_id, str) or not builder_id.strip():
                    errors.append(f"{label}:{name}: build builder_id is invalid")
                else:
                    build_ids.append(" ".join(builder_id.split()).casefold())
                if not isinstance(digest, str) or not HEX_32.fullmatch(digest):
                    errors.append(f"{label}:{name}: build sha256 must be lowercase SHA-256")
                else:
                    build_hashes.append(digest)
            if (
                builder_ids is None
                or len(build_ids) != len(builder_ids)
                or set(build_ids) != set(builder_ids)
            ):
                errors.append(f"{label}:{name}: builds must cover every declared builder exactly once")
            if (
                not isinstance(normalized_sha256, str)
                or len(build_hashes) != len(builds)
                or any(digest != normalized_sha256 for digest in build_hashes)
            ):
                errors.append(f"{label}:{name}: every builder hash must equal normalized_sha256")
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _incident(
    document: dict, root: pathlib.Path, label: str, tracked_paths: set[str] | None
) -> list[str]:
    errors = _common(document, "incident-response-drill", label)
    _distinct_identities(
        document, "participants", "participant_ids", 2, errors, label
    )
    scenarios = document.get("scenarios")
    required = {"consensus-stall", "reorg", "proof-dos"}
    if not isinstance(scenarios, list) or not required.issubset(set(scenarios)):
        errors.append(f"{label}: scenarios must cover {sorted(required)}")
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _governance(
    document: dict,
    root: pathlib.Path,
    label: str,
    tracked_paths: set[str] | None,
    authoritative_digests: tuple[str, str] | None,
) -> list[str]:
    errors = _common(document, "governance-approval", label)
    if document.get("approved_revision") != document.get("revision"):
        errors.append(f"{label}: approved_revision must equal revision")
    for key in ("compiler_digest", "target_profile_digest"):
        value = document.get(key)
        if not isinstance(value, str) or not HEX_32.fullmatch(value):
            errors.append(f"{label}: {key} must be lowercase SHA-256")
    if authoritative_digests is not None:
        compiler_digest, target_profile_digest = authoritative_digests
        if document.get("compiler_digest") != compiler_digest:
            errors.append(f"{label}: compiler_digest does not match frozen release revision")
        if document.get("target_profile_digest") != target_profile_digest:
            errors.append(f"{label}: target_profile_digest does not match frozen release revision")
    if document.get("quorum_met") is not True:
        errors.append(f"{label}: quorum_met must be true")
    _distinct_identities(
        document, "approvals", "approver_ids", 2, errors, label
    )
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def verify_gate(
    gate_id: str,
    evidence: list[str],
    root: pathlib.Path,
    expected_revision: str | None = None,
    tracked_paths: set[str] | None = None,
    governance_digests: tuple[str, str] | None = None,
    dependencies_lock_digest: str | None = None,
    revision_committed_at: datetime | None = None,
) -> list[str]:
    """Validate JSON attestations for one gate already marked passed."""
    if gate_id not in EXTERNAL_GATES:
        return []
    errors: list[str] = []
    documents: list[tuple[pathlib.Path, dict]] = []
    for relative in evidence:
        if not isinstance(relative, str) or not relative.endswith(".json"):
            continue
        path = _repository_file(root, relative)
        if path is None:
            errors.append(f"{gate_id}: invalid repository evidence path {relative!r}")
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            errors.append(f"{gate_id}: invalid JSON evidence {relative}: {error}")
            continue
        if isinstance(document, dict) and document.get("gate_id") == gate_id:
            documents.append((path, document))
    minimum = 2 if gate_id == "independent-audits" else 1
    if len(documents) < minimum:
        errors.append(f"{gate_id}: passed status requires {minimum} typed JSON attestation(s)")
        return errors

    organizations: list[str] = []
    for path, document in documents:
        label = path.relative_to(root.resolve()).as_posix()
        if expected_revision is not None and document.get("revision") != expected_revision:
            errors.append(f"{label}: revision does not match frozen release_revision")
        if revision_committed_at is not None:
            completed = _valid_utc(document.get("completed_at"))
            if completed is not None and completed < revision_committed_at:
                errors.append(f"{label}: completed_at predates the frozen release revision")
            if gate_id == "public-testnet-soak":
                started = _valid_utc(document.get("started_at"))
                if started is not None and started < revision_committed_at:
                    errors.append(
                        f"{label}: public testnet soak started before the frozen release revision"
                    )
        if gate_id == "source-provenance":
            errors.extend(
                _source_provenance(
                    document,
                    root,
                    label,
                    tracked_paths,
                    dependencies_lock_digest,
                )
            )
        elif gate_id == "independent-audits":
            document_errors, organization = _audit(document, root, label, tracked_paths)
            errors.extend(document_errors)
            if organization:
                organizations.append(organization)
        elif gate_id == "public-testnet-soak":
            errors.extend(_testnet(document, root, label, tracked_paths))
        elif gate_id == "reproducible-platform-binaries":
            errors.extend(_reproducibility(document, root, label, tracked_paths))
        elif gate_id == "incident-response-drill":
            errors.extend(_incident(document, root, label, tracked_paths))
        elif gate_id == "governance-approval":
            errors.extend(
                _governance(
                    document,
                    root,
                    label,
                    tracked_paths,
                    governance_digests,
                )
            )
    if gate_id == "independent-audits" and len(set(organizations)) < 2:
        errors.append("independent-audits: reports must come from distinct organizations")
    return errors
