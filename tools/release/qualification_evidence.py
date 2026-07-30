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
REQUIRED_RELEASE_PROGRAMS = {"bytecoind", "walletd", "minerd"}
REQUIRED_AUDIT_SCOPES = {
    "zk-circuits-and-cryptography",
    "consensus-and-state-transition",
    "wallet-key-management-and-privacy",
    "network-and-denial-of-service",
    "migration-and-supply-invariants",
    "compiler-and-reproducibility",
}


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
    authoritative_source_digests: tuple[str, str] | None,
) -> list[str]:
    errors = _common(document, "source-provenance", label)
    builder_ids = _distinct_identities(
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
    if authoritative_source_digests is not None:
        archive_digest, sbom_digest = authoritative_source_digests
        if artifacts["source_archive"]["sha256"] != archive_digest:
            errors.append(f"{label}: source archive does not match frozen Git tree")
        if artifacts["spdx_sbom"]["sha256"] != sbom_digest:
            errors.append(f"{label}: SPDX SBOM does not match frozen Git tree")

    builders = document.get("builders")
    builder_records: list[str] = []
    environment_digests: list[str] = []
    if not isinstance(builders, list):
        errors.append(f"{label}: builders must bind each independent generation")
    else:
        for builder in builders:
            if not isinstance(builder, dict):
                errors.append(f"{label}: invalid source builder")
                continue
            builder_id = builder.get("builder_id")
            if not isinstance(builder_id, str) or not builder_id.strip():
                errors.append(f"{label}: source builder_id is invalid")
            else:
                builder_records.append(" ".join(builder_id.split()).casefold())
            environment_digest = builder.get("environment_sha256")
            if not isinstance(environment_digest, str) or not HEX_32.fullmatch(
                environment_digest
            ):
                errors.append(f"{label}: builder environment_sha256 must be lowercase SHA-256")
            else:
                environment_digests.append(environment_digest)
            if builder.get("revision") != document.get("revision"):
                errors.append(f"{label}: every source builder must use the attested revision")
            if builder.get("source_archive_sha256") != artifacts["source_archive"]["sha256"]:
                errors.append(f"{label}: every builder source archive hash must match")
            if builder.get("spdx_sbom_sha256") != artifacts["spdx_sbom"]["sha256"]:
                errors.append(f"{label}: every builder SPDX SBOM hash must match")
            for key in ("archive_tool", "sbom_tool"):
                value = builder.get(key)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{label}: source builder {key} identity is required")
    if (
        builder_ids is None
        or len(builder_records) != len(builder_ids)
        or set(builder_records) != set(builder_ids)
    ):
        errors.append(f"{label}: builders must cover every source builder exactly once")
    expected_environments = len(builders) if isinstance(builders, list) else 0
    if (
        expected_environments < 2
        or len(environment_digests) != expected_environments
        or len(set(environment_digests)) != expected_environments
    ):
        errors.append(f"{label}: source builders must use distinct environment identities")

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
) -> tuple[list[str], str | None, set[str]]:
    errors = _common(document, "independent-audits", label)
    started = _utc(document.get("started_at"), "started_at", errors, label)
    completed = _utc(document.get("completed_at"), "completed_at", errors, label)
    if started is not None and completed is not None and started > completed:
        errors.append(f"{label}: started_at must not follow completed_at")
    auditor = document.get("auditor")
    organization = auditor.get("organization") if isinstance(auditor, dict) else None
    if not isinstance(organization, str) or not organization.strip():
        errors.append(f"{label}: auditor.organization is required")
        organization = None
    if document.get("independence_statement") is not True:
        errors.append(f"{label}: independence_statement must be true")
    methodology = document.get("methodology")
    if not isinstance(methodology, str) or not methodology.strip():
        errors.append(f"{label}: methodology is required")
    if document.get("remediation_verified") is not True:
        errors.append(f"{label}: remediation_verified must be true")

    scope = document.get("scope")
    scopes: set[str] = set()
    if (
        not isinstance(scope, list)
        or any(not isinstance(item, str) for item in scope)
        or len(scope) != len(set(scope))
        or not scope
    ):
        errors.append(f"{label}: scope must be a non-empty array of unique domains")
    else:
        scopes = set(scope)
        unknown = scopes - REQUIRED_AUDIT_SCOPES
        if unknown:
            errors.append(f"{label}: unknown audit scope domains: {sorted(unknown)}")

    findings = document.get("unresolved_findings")
    finding_levels = {"critical", "high", "medium", "low"}
    if not isinstance(findings, dict) or set(findings) != finding_levels:
        errors.append(f"{label}: unresolved_findings must contain exactly {sorted(finding_levels)}")
    elif any(
        not isinstance(findings[level], int)
        or isinstance(findings[level], bool)
        or findings[level] < 0
        for level in finding_levels
    ):
        errors.append(f"{label}: unresolved finding counts must be non-negative integers")
    elif findings["critical"] != 0 or findings["high"] != 0:
        errors.append(f"{label}: unresolved critical and high findings must both be zero")
    _artifact(document, root, errors, label, tracked_paths)
    normalized = " ".join(organization.split()).casefold() if organization else None
    return errors, normalized, scopes


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
    node_ids = _distinct_identities(
        document, "independent_nodes", "node_ids", 3, errors, label
    )
    network = document.get("network")
    if not isinstance(network, str) or not network.strip():
        errors.append(f"{label}: network is required")
    for key in ("genesis_hash", "start_block_hash", "end_block_hash"):
        value = document.get(key)
        if not isinstance(value, str) or not HEX_32.fullmatch(value):
            errors.append(f"{label}: {key} must be a lowercase 32-byte hash")
    start_height = _integer(document, "start_height", 0, errors, label)
    end_height = _integer(document, "end_height", 1, errors, label)
    observed_blocks = _integer(document, "observed_blocks", 10_000, errors, label)
    if end_height <= start_height:
        errors.append(f"{label}: end_height must follow start_height")
    elif end_height - start_height < observed_blocks:
        errors.append(f"{label}: height span must cover every observed block")
    if document.get("migration_supply_reconciled") is not True:
        errors.append(f"{label}: migration_supply_reconciled must be true")
    divergences = document.get("unresolved_consensus_divergences")
    if not isinstance(divergences, int) or isinstance(divergences, bool) or divergences != 0:
        errors.append(f"{label}: unresolved_consensus_divergences must be zero")

    supply_audit = document.get("supply_audit")
    supply_keys = {
        "total_bridged",
        "total_fees",
        "circulating_supply",
        "commitment_count",
        "program_count",
        "current_block_program_cost",
        "commitment_root",
        "block_height",
    }
    if not isinstance(supply_audit, dict) or set(supply_audit) != supply_keys:
        errors.append(f"{label}: supply_audit must bind the complete daemon audit response")
    else:
        for key in supply_keys - {"commitment_root"}:
            value = supply_audit.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append(f"{label}: supply_audit.{key} must be a non-negative integer")
        commitment_root = supply_audit.get("commitment_root")
        if not isinstance(commitment_root, str) or not HEX_32.fullmatch(commitment_root):
            errors.append(f"{label}: supply_audit.commitment_root must be a lowercase 32-byte hash")
        if supply_audit.get("block_height") != end_height:
            errors.append(f"{label}: supply_audit.block_height must equal end_height")

    node_results = document.get("node_results")
    if not isinstance(node_results, list):
        errors.append(f"{label}: node_results must bind every independent node")
    else:
        result_ids: list[str] = []
        for result in node_results:
            if not isinstance(result, dict):
                errors.append(f"{label}: invalid node result")
                continue
            node_id = result.get("node_id")
            if not isinstance(node_id, str) or not node_id.strip():
                errors.append(f"{label}: node result has an invalid node_id")
            else:
                result_ids.append(" ".join(node_id.split()).casefold())
            if result.get("revision") != document.get("revision"):
                errors.append(f"{label}: node result revision must equal the attested revision")
            if result.get("final_height") != end_height:
                errors.append(f"{label}: every node must report the attested end_height")
            if result.get("final_block_hash") != document.get("end_block_hash"):
                errors.append(f"{label}: every node must converge on end_block_hash")
            if result.get("supply_audit") != supply_audit:
                errors.append(f"{label}: every node must converge on the complete supply_audit")
        if (
            node_ids is None
            or len(result_ids) != len(node_ids)
            or set(result_ids) != set(node_ids)
        ):
            errors.append(f"{label}: node_results must cover every independent node exactly once")
    for key, minimum in {
        "reorg_scenarios": 1,
        "malformed_bundle_cases": 1,
        "dos_scenarios": 1,
    }.items():
        _integer(document, key, minimum, errors, label)
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _reproducibility(
    document: dict,
    root: pathlib.Path,
    label: str,
    tracked_paths: set[str] | None,
    dependencies_lock_digest: str | None,
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
            builders = item.get("builders")
            builder_records: list[str] = []
            environment_digests: list[str] = []
            if not isinstance(builders, list):
                errors.append(f"{label}:{name}: builders must describe each independent environment")
            else:
                for builder in builders:
                    if not isinstance(builder, dict):
                        errors.append(f"{label}:{name}: invalid builder environment")
                        continue
                    builder_id = builder.get("builder_id")
                    if not isinstance(builder_id, str) or not builder_id.strip():
                        errors.append(f"{label}:{name}: builder_id is invalid")
                    else:
                        builder_records.append(" ".join(builder_id.split()).casefold())
                    environment_digest = builder.get("environment_sha256")
                    if not isinstance(environment_digest, str) or not HEX_32.fullmatch(
                        environment_digest
                    ):
                        errors.append(
                            f"{label}:{name}: environment_sha256 must be lowercase SHA-256"
                        )
                    else:
                        environment_digests.append(environment_digest)
                    if builder.get("revision") != document.get("revision"):
                        errors.append(
                            f"{label}:{name}: every builder must use the attested revision"
                        )
                    for key in ("compiler", "sdk", "linker"):
                        value = builder.get(key)
                        if not isinstance(value, str) or not value.strip():
                            errors.append(f"{label}:{name}: builder {key} identity is required")
                    lock_digest = builder.get("dependencies_lock_sha256")
                    if not isinstance(lock_digest, str) or not HEX_32.fullmatch(lock_digest):
                        errors.append(
                            f"{label}:{name}: dependencies_lock_sha256 must be lowercase SHA-256"
                        )
                    elif (
                        dependencies_lock_digest is not None
                        and lock_digest != dependencies_lock_digest
                    ):
                        errors.append(
                            f"{label}:{name}: dependency lock does not match frozen revision"
                        )
            if (
                builder_ids is None
                or len(builder_records) != len(builder_ids)
                or set(builder_records) != set(builder_ids)
            ):
                errors.append(
                    f"{label}:{name}: builder environments must cover every builder exactly once"
                )
            if builder_ids is not None and (
                len(environment_digests) != len(builder_ids)
                or len(set(environment_digests)) != len(builder_ids)
            ):
                errors.append(f"{label}:{name}: builders must use distinct environment identities")

            artifacts = item.get("artifacts")
            if not isinstance(artifacts, list):
                errors.append(f"{label}:{name}: artifacts must bind every release program")
                continue
            artifact_names = [
                artifact.get("name")
                for artifact in artifacts
                if isinstance(artifact, dict) and isinstance(artifact.get("name"), str)
            ]
            if (
                set(artifact_names) != REQUIRED_RELEASE_PROGRAMS
                or len(artifact_names) != len(REQUIRED_RELEASE_PROGRAMS)
            ):
                errors.append(
                    f"{label}:{name}: artifacts must contain every release program exactly once"
                )
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    errors.append(f"{label}:{name}: invalid release artifact")
                    continue
                program = artifact.get("name", "unknown")
                expected_hashes = {}
                for key in (
                    "binary_sha256",
                    "debug_symbols_sha256",
                    "sbom_sha256",
                ):
                    digest = artifact.get(key)
                    if not isinstance(digest, str) or not HEX_32.fullmatch(digest):
                        errors.append(f"{label}:{name}:{program}: {key} must be lowercase SHA-256")
                    else:
                        expected_hashes[key] = digest
                builds = artifact.get("builds")
                if not isinstance(builds, list):
                    errors.append(
                        f"{label}:{name}:{program}: builds must bind every builder"
                    )
                    continue
                build_ids: list[str] = []
                for build in builds:
                    if not isinstance(build, dict):
                        errors.append(f"{label}:{name}:{program}: invalid build result")
                        continue
                    builder_id = build.get("builder_id")
                    if not isinstance(builder_id, str) or not builder_id.strip():
                        errors.append(f"{label}:{name}:{program}: build builder_id is invalid")
                    else:
                        build_ids.append(" ".join(builder_id.split()).casefold())
                    for key, expected in expected_hashes.items():
                        if build.get(key) != expected:
                            errors.append(
                                f"{label}:{name}:{program}: every builder {key} must match"
                            )
                if (
                    builder_ids is None
                    or len(build_ids) != len(builder_ids)
                    or set(build_ids) != set(builder_ids)
                ):
                    errors.append(
                        f"{label}:{name}:{program}: builds must cover every builder exactly once"
                    )
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _incident(
    document: dict, root: pathlib.Path, label: str, tracked_paths: set[str] | None
) -> list[str]:
    errors = _common(document, "incident-response-drill", label)
    participants = _distinct_identities(
        document, "participants", "participant_ids", 2, errors, label
    )
    observers = _distinct_identities(
        document, "independent_observers", "observer_ids", 1, errors, label
    )
    if participants is not None and observers is not None and set(participants) & set(observers):
        errors.append(f"{label}: independent observers must not be drill participants")
    started = _utc(document.get("started_at"), "started_at", errors, label)
    completed = _utc(document.get("completed_at"), "completed_at", errors, label)
    if started is not None and completed is not None and started > completed:
        errors.append(f"{label}: started_at must not follow completed_at")
    authority = document.get("decision_authority")
    if not isinstance(authority, str) or not authority.strip():
        errors.append(f"{label}: decision_authority is required")
    if document.get("communications_recorded") is not True:
        errors.append(f"{label}: communications_recorded must be true")
    if document.get("migration_supply_reconciled") is not True:
        errors.append(f"{label}: migration_supply_reconciled must be true")
    unresolved = document.get("unresolved_actions")
    if not isinstance(unresolved, list) or any(
        not isinstance(action, str) or not action.strip() for action in unresolved
    ):
        errors.append(f"{label}: unresolved_actions must be an array of non-empty descriptions")

    scenarios = document.get("scenarios")
    required = {"consensus-stall", "reorg", "proof-dos"}
    if not isinstance(scenarios, list):
        errors.append(f"{label}: scenarios must contain structured drill results")
    else:
        identifiers = [
            scenario.get("id")
            for scenario in scenarios
            if isinstance(scenario, dict) and isinstance(scenario.get("id"), str)
        ]
        if set(identifiers) != required or len(identifiers) != len(required):
            errors.append(f"{label}: scenarios must cover each of {sorted(required)} exactly once")
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                errors.append(f"{label}: invalid scenario result")
                continue
            scenario_id = scenario.get("id", "unknown")
            scenario_label = f"{label}:{scenario_id}"
            detected = _utc(
                scenario.get("detected_at"), "detected_at", errors, scenario_label
            )
            triaged = _utc(
                scenario.get("triaged_at"), "triaged_at", errors, scenario_label
            )
            recovered = _utc(
                scenario.get("recovered_at"), "recovered_at", errors, scenario_label
            )
            if (
                detected is not None
                and triaged is not None
                and recovered is not None
                and not (detected <= triaged <= recovered)
            ):
                errors.append(
                    f"{scenario_label}: detection, triage and recovery timestamps must be ordered"
                )
            if (
                started is not None
                and completed is not None
                and detected is not None
                and recovered is not None
                and not (started <= detected <= recovered <= completed)
            ):
                errors.append(f"{scenario_label}: scenario timestamps must fall within the drill")
            for key in (
                "artifacts_preserved",
                "clean_room_reproduced",
                "recovery_verified",
            ):
                if scenario.get(key) is not True:
                    errors.append(f"{scenario_label}: {key} must be true")
    _artifact(document, root, errors, label, tracked_paths)
    return errors


def _governance(
    document: dict,
    root: pathlib.Path,
    label: str,
    tracked_paths: set[str] | None,
    authoritative_digests: tuple[str, str] | None,
    authoritative_activation_heights: dict[str, int] | None,
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
    activation_heights = document.get("activation_heights")
    if (
        not isinstance(activation_heights, dict)
        or not activation_heights
        or any(
            not isinstance(name, str)
            or not isinstance(height, int)
            or isinstance(height, bool)
            or height <= 0
            for name, height in activation_heights.items()
        )
    ):
        errors.append(f"{label}: activation_heights must contain positive integer heights")
    elif (
        authoritative_activation_heights is not None
        and activation_heights != authoritative_activation_heights
    ):
        errors.append(f"{label}: activation_heights do not match activation configuration")
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
    governance_activation_heights: dict[str, int] | None = None,
    authoritative_source_digests: tuple[str, str] | None = None,
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
    audited_scopes: set[str] = set()
    for path, document in documents:
        label = path.relative_to(root.resolve()).as_posix()
        if expected_revision is not None and document.get("revision") != expected_revision:
            errors.append(f"{label}: revision does not match frozen release_revision")
        if revision_committed_at is not None:
            completed = _valid_utc(document.get("completed_at"))
            if completed is not None and completed < revision_committed_at:
                errors.append(f"{label}: completed_at predates the frozen release revision")
            if gate_id in {
                "public-testnet-soak",
                "incident-response-drill",
                "independent-audits",
            }:
                started = _valid_utc(document.get("started_at"))
                if started is not None and started < revision_committed_at:
                    activity = {
                        "public-testnet-soak": "public testnet soak",
                        "incident-response-drill": "incident-response drill",
                        "independent-audits": "independent audit",
                    }[gate_id]
                    errors.append(f"{label}: {activity} started before the frozen release revision")
        if gate_id == "source-provenance":
            errors.extend(
                _source_provenance(
                    document,
                    root,
                    label,
                    tracked_paths,
                    dependencies_lock_digest,
                    authoritative_source_digests,
                )
            )
        elif gate_id == "independent-audits":
            document_errors, organization, scopes = _audit(
                document, root, label, tracked_paths
            )
            errors.extend(document_errors)
            if organization:
                organizations.append(organization)
            audited_scopes.update(scopes)
        elif gate_id == "public-testnet-soak":
            errors.extend(_testnet(document, root, label, tracked_paths))
        elif gate_id == "reproducible-platform-binaries":
            errors.extend(
                _reproducibility(
                    document,
                    root,
                    label,
                    tracked_paths,
                    dependencies_lock_digest,
                )
            )
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
                    governance_activation_heights,
                )
            )
    if gate_id == "independent-audits" and len(set(organizations)) < 2:
        errors.append("independent-audits: reports must come from distinct organizations")
    if gate_id == "independent-audits" and audited_scopes != REQUIRED_AUDIT_SCOPES:
        errors.append(
            "independent-audits: reports must collectively cover every required audit scope"
        )
    return errors
