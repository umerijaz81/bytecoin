# Release readiness and reproducibility

This repository produces deterministic **source evidence** before it produces or publishes any
release binary. The evidence is deliberately narrower than a binary reproducibility claim: compiler,
linker, operating-system SDK and packaging differences must still be eliminated and independently
reproduced for every supported binary platform before the corresponding activation gate can pass.

## Evidence generated from a clean commit

`tools/release/build_release_evidence.py` performs two independent generations and rejects any byte
difference. It emits:

- a gzip-compressed tar archive containing only Git-tracked files, with sorted paths, normalized
  ownership/modes and the commit timestamp as `SOURCE_DATE_EPOCH`; unsupported Git tree entries,
  unknown modes and symlinks that can escape the archive root are rejected;
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
The requested release revision must resolve to the checked-out `HEAD`; this prevents dependency
verification against the current index from being combined with source evidence for a different
historical tree.

## CI trust boundary

`.github/workflows/release-evidence.yml` pins each third-party action to a full commit, disables
checkout credentials, runs the lock and activation verifiers, independently reproduces the evidence,
and uploads it without a second compression layer. A `v*` tag also receives GitHub build-provenance
attestations. The workflow does not create or publish a GitHub release: publication remains a gated,
two-person operation after audit, testnet and governance evidence is attached.

The old Azure pipeline is intentionally disabled. It used retired runner images, dead Bintray URLs,
floating dependency clones, an unsupported OpenSSL 1.1.1b snapshot and a long-lived PAT embedded in a
remote URL. None of its artifacts meet the release boundary.

`.github/workflows/reproducible-binaries.yml` is the first executable reproducibility qualification
gate. It exports the same revision into two different absolute paths, requires `SOURCE_DATE_EPOCH`,
remaps C++ and Rust source paths, disables nondeterministic linker identifiers, strips both builds,
and compares `bytecoind`, `walletd` and `minerd` byte-for-byte on Linux x64, macOS ARM64 and Windows
x64. Each JSON manifest records hashes and exact compiler, SDK and dependency identities. All three
same-runner platform comparisons passed on 2026-07-16 in GitHub Actions run `29521526735` for commit
`87f0e5f2291bdb8abf0212e5ce566fc7ebc811c3`. The uploaded evidence artifacts are:

- Linux artifact `8385140911`, digest
  `sha256:0399ee89888a46eb3376a6262e2af0518e8f1278c94d73e7815c915277931c77`;
- macOS ARM64 artifact `8385134927`, digest
  `sha256:e720a135af9939c71c6e558b6b20fc149b66248d95c6f78a564cc395c040f381`;
- Windows x64 artifact `8385420466`, digest
  `sha256:174d9d84ab7dc557862080eb14e746608366cbe3d43e086f1928cb17cbe4f1b4`.

This closes the repository-controlled same-runner qualification, not the activation gate. The runners
currently use their platform package managers rather than the frozen production dependency lock, and
two independent operators/environments have not reproduced and signed the artifacts. The
`reproducible-platform-binaries` gate therefore remains `pending`.

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

## Typed qualification evidence

`tools/release/verify_release_gates.py` fails closed when an external gate is marked `passed` without
gate-specific JSON attestations. Every attestation binds a 40-character Git revision, a UTC completion
time, and a repository-relative artifact whose lowercase SHA-256 is recomputed by the verifier. The
completion time cannot be more than five minutes in the future, allowing limited clock skew without
letting evidence pre-authorize work that has not occurred. The
attestation and its referenced artifact must both be committed before the activation-gate change.
Every completion time must be at or after the frozen revision's Git commit time. For public-testnet
evidence, `started_at` must also be at or after that time, so a newly frozen revision cannot inherit
soak duration accumulated by different code.
The verifier requires canonical contained paths, rejects path and symlink escapes, and requires every
listed evidence file to be present in the Git index.
Before any external gate passes, `release/activation-gates.json` must freeze one lowercase
40-character `release_revision`; every typed attestation must bind that exact revision. It remains
`null` while qualification is still in progress. Once frozen, it must resolve to an existing commit
that is an ancestor of the evidence/activation commit.
The verifier compares that frozen tree with the activation commit and rejects every post-freeze path
except `release/activation-gates.json`, `src/CryptoNoteConfig.hpp`, and the tracked evidence and
artifact paths explicitly declared below `release/evidence/` by typed, gate-matching attestations.
Implementation references already listed on pending gates do not enter this allowlist. Qualification
therefore cannot silently carry over to modified consensus, wallet, network, compiler, dependency,
build, or release-tool code, nor disguise one of those files as a qualification artifact.
Within `src/CryptoNoteConfig.hpp`, the frozen and activation trees must be byte-identical after only
the numeric values of the four declared activation-height constants are normalized; changing another
consensus constant in the activation commit fails the gate.
The activation schema permits exactly the six declared gates, and each gate's
`required_for_activation` flag must remain `true`; a manifest edit cannot opt a pending gate out of
the activation decision.

The enforced minimums are release policy, not claims about the current branch:

- source provenance requires a committed typed attestation from two distinct independent builders,
  byte-identical source archives and SPDX SBOMs, the frozen revision's dependency-lock digest, and
  distinct digest-bound source archive, SBOM, provenance, and checksum artifacts. The verifier also
  cross-checks canonical filenames, the provenance schema/revision/materials/reproduction result, the
  SPDX root package revision, and every canonical `SHA256SUMS` entry;
- independent audits require two attestations from distinct normalized organization identities, each
  binding its report and declaring zero unresolved critical or high findings;
- public testnet requires at least 14 elapsed days, three independent nodes, 10,000 observed blocks,
  and recorded reorg, malformed-bundle, and denial-of-service scenarios at a credential-free public
  HTTPS endpoint with a valid host and optional valid port;
- binary reproducibility requires Linux x86-64, macOS ARM64, and Windows x86-64, with two independent
  builders and byte-identical normalized hashes for each platform; each platform must appear exactly
  once, and every named builder must bind its own SHA-256 to that platform's normalized SHA-256;
- an incident drill requires at least two participants and consensus-stall, reorg, and proof-DoS
  scenarios;
- governance must approve the exact revision plus compiler and target-profile SHA-256 digests, record
  quorum, contain at least two approvals, and bind the exact positive integer values of all four
  canonical activation heights. The verifier compares that map with the activation commit's
  `CryptoNoteConfig.hpp`; approval for one schedule cannot authorize another.

Every independent-node, builder, drill-participant, and governance-approval count must be accompanied
by an equally sized list of distinct normalized identities. Numeric counts alone cannot satisfy a
gate. Governance compiler and target-profile digests are recomputed from the frozen revision: the
compiler digest is the LF-canonicalized `tools/onyx/compiler_v1.py` hash, and all four approved
standard-program manifests must bind that compiler and one identical target-profile digest.

JSON alone is not treated as an audit, soak, drill, build, or governance record. Its `artifact` object
must name the committed primary record and its digest. Reviewers should additionally verify any
detached signatures or public transparency-log entries used by the participating organizations; those
trust roots deliberately remain outside this repository.

## Updating dependencies

Archive entries require an HTTPS URL and upstream SHA-256. Git entries require a full immutable commit.
Vendored entries use a deterministic digest over path names and file hashes:

```sh
python3 tools/release/verify_dependencies.py --print-tree vendor/randomx
python3 tools/release/verify_dependencies.py --print-tree vendor/onyx-zk
```

OpenSSL is pinned to the supported 3.5 LTS line rather than the obsolete 1.1.1b build used by the old
pipeline. A dependency update is security-sensitive and does not inherit approval from this document.
