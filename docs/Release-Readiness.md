# Release readiness and reproducibility

This repository produces deterministic **source evidence** before it produces or publishes any
release binary. The evidence is deliberately narrower than a binary reproducibility claim: compiler,
linker, operating-system SDK and packaging differences must still be eliminated and independently
reproduced for every supported binary platform before the corresponding activation gate can pass.

## Evidence generated from a clean commit

`tools/release/build_release_evidence.py` performs two independent generations and rejects any byte
difference. It emits:

- a gzip-compressed tar archive containing only Git-tracked files, with sorted paths, normalized
  ownership/modes and the commit timestamp as `SOURCE_DATE_EPOCH`;
- an SPDX 2.3 JSON SBOM covering the release lock and every checksummed Cargo package;
- a provenance statement binding the commit, dependency-lock digest, source archive and SBOM;
- `SHA256SUMS` for the three artifacts.

The release lock fails closed on missing hashes, floating Git revisions, altered vendored RandomX or
Onyx trees, toolchain drift and missing lockfiles:

```sh
python3 tools/release/verify_dependencies.py
python3 tools/release/verify_dependencies.py --verify-upstream  # release ceremony/networked CI
python3 tools/release/verify_release_gates.py
python3 tools/release/build_release_evidence.py --output-dir dist --revision HEAD
(cd dist && sha256sum --check SHA256SUMS)
```

`--allow-dirty` exists only to test the generator while developing it. Provenance records the dirty
state, and the GitHub workflow never enables that option. A dirty artifact is not releasable.

## CI trust boundary

`.github/workflows/release-evidence.yml` pins each third-party action to a full commit, disables
checkout credentials, runs the lock and activation verifiers, independently reproduces the evidence,
and uploads it without a second compression layer. A `v*` tag also receives GitHub build-provenance
attestations. The workflow does not create or publish a GitHub release: publication remains a gated,
two-person operation after audit, testnet and governance evidence is attached.

The old Azure pipeline is intentionally disabled. It used retired runner images, dead Bintray URLs,
floating dependency clones, an unsupported OpenSSL 1.1.1b snapshot and a long-lived PAT embedded in a
remote URL. None of its artifacts meet the release boundary.

## Required release ceremony

1. Freeze a reviewed commit and run all consensus, ZK, migration, reorg, fuzz and platform tests.
2. Update `release/dependencies.lock.json` only from authenticated upstream releases; review every
   changed digest and vendored tree independently.
3. Obtain the CI source evidence and its tag attestation. A second operator checks out the tag in a
   separate environment, regenerates evidence and compares all SHA-256 values.
4. Build each supported binary twice in independent, pinned environments. Compare stripped binaries
   byte-for-byte (and debug symbols separately), generate per-binary SBOMs, and record compiler, SDK,
   linker and dependency identities. Until this succeeds, `reproducible-platform-binaries` stays
   `pending` and no binary may be described as reproducible.
5. Attach two independent audit reports with no unresolved critical/high findings, public testnet soak
   results, migration/supply reconciliation, and the completed incident drill to repository paths in
   `release/activation-gates.json`.
6. Obtain recorded governance approval. Only a dedicated reviewed commit may change activation
   heights and mark all required gates `passed`; the verifier rejects doing those out of order.
7. Create a draft release, have a second operator verify checksums/attestations, sign the final
   manifest with the offline release keys, and only then publish it. Release signing keys must never be
   stored in the repository or general-purpose CI secrets.

## Updating dependencies

Archive entries require an HTTPS URL and upstream SHA-256. Git entries require a full immutable commit.
Vendored entries use a deterministic digest over path names and file hashes:

```sh
python3 tools/release/verify_dependencies.py --print-tree vendor/randomx
python3 tools/release/verify_dependencies.py --print-tree vendor/onyx-zk
```

OpenSSL is pinned to the supported 3.5 LTS line rather than the obsolete 1.1.1b build used by the old
pipeline. A dependency update is security-sensitive and does not inherit approval from this document.
