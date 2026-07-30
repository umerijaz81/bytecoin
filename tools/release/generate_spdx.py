#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 JSON SBOM from the release and Cargo locks."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import pathlib
import tomllib

from release_common import (
    canonical_json_bytes,
    revision_file,
    spdx_id,
    strict_json_loads,
)


def package_from_lock(dependency: dict) -> dict:
    package = {
        "name": dependency["name"],
        "SPDXID": spdx_id(f"Package-{dependency['name']}-{dependency['version']}"),
        "versionInfo": dependency["version"],
        "downloadLocation": dependency.get("url", "NOASSERTION"),
        "filesAnalyzed": False,
        "licenseConcluded": dependency.get("license", "NOASSERTION"),
        "licenseDeclared": dependency.get("license", "NOASSERTION"),
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": dependency["purl"],
            }
        ],
    }
    checksum = dependency.get("sha256") or dependency.get("tree_sha256")
    if checksum:
        package["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
    return package


def cargo_packages(revision: str) -> list[dict]:
    with io.BytesIO(revision_file(revision, "vendor/onyx-zk/Cargo.lock")) as stream:
        cargo_lock = tomllib.load(stream)
    result = []
    for crate in cargo_lock.get("package", []):
        checksum = crate.get("checksum")
        source = crate.get("source", "")
        if not checksum or not source.startswith("registry+"):
            continue
        name = crate["name"]
        version = crate["version"]
        result.append(
            {
                "name": name,
                "SPDXID": spdx_id(f"Cargo-{name}-{version}-{checksum[:12]}"),
                "versionInfo": version,
                "downloadLocation": f"https://crates.io/api/v1/crates/{name}/{version}/download",
                "filesAnalyzed": False,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:cargo/{name}@{version}",
                    }
                ],
            }
        )
    return sorted(result, key=lambda item: (item["name"], item["versionInfo"], item["SPDXID"]))


def generate(revision: str, epoch: int) -> dict:
    lock_bytes = revision_file(revision, "release/dependencies.lock.json")
    lock = strict_json_loads(lock_bytes)
    root_id = "SPDXRef-Package-bytecoin"
    dependencies = [package_from_lock(item) for item in lock["dependencies"]]
    dependencies.extend(cargo_packages(revision))
    dependencies.sort(key=lambda item: (item["name"], item["versionInfo"], item["SPDXID"]))
    root_package = {
        "name": "bytecoin",
        "SPDXID": root_id,
        "versionInfo": revision,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "LGPL-3.0-only",
        "licenseDeclared": "LGPL-3.0-only",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:github/umerijaz81/bytecoin@{revision}",
            }
        ],
    }
    created = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    namespace_suffix = hashlib.sha256(lock_bytes).hexdigest()[:16]
    packages = [root_package, *dependencies]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}
    ]
    relationships.extend(
        {
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in dependencies
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"bytecoin-{revision}",
        "documentNamespace": f"https://bytecoin.org/spdx/bytecoin/{revision}/{namespace_suffix}",
        "creationInfo": {"created": created, "creators": ["Tool: bytecoin-release/1"]},
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json_bytes(generate(args.revision, args.epoch)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
