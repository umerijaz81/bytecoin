# Onyx implementation status and completion plan

This file reconciles the original architecture roadmap with the code that is actually present. It is
an engineering status document, not an activation claim. Consensus activation heights remain
unreachable until the release gates below are independently satisfied.

## Implemented baseline

| Gate | Implemented evidence | Remaining exit condition |
|---|---|---|
| O0 proof foundation | Exact-pinned vendored Halo2/Pasta crate, bounded panic-contained C ABI, CMake integration, locked offline three-platform workflow, primitive vectors, malformed-input tests, and a sanitizer fuzzer target with restored C++ parser/Onyx envelope selectors. | External dependency/proof-boundary review, sustained sanitizer fuzz campaigns and reproducible release artifacts. |
| O1 state model | Canonical notes/envelopes, encryption, commitment tree, retained anchors, nullifier set, bounded snapshots, atomic apply/undo, replay and reorg tests. | Independent consensus-state audit and long-running randomized differential/fuzz campaigns. |
| O2 private transfer | Shape-bound Halo2 transfer circuits, spend and binding authorization, value conservation, expiry/network binding, negative mutation tests and cost limits. | Independent circuit audit and published laptop benchmarks at frozen release parameters. |
| O3 wallet | Seed/key hierarchy, Onyx addresses, full viewing keys, scanning, historical witnesses, proving, recovery snapshots, pending reservations, native/token balances and wallet RPC. | End-to-end multi-node devnet recovery, backup, hardware-wallet and operator acceptance tests. |
| O4 migration | One-way legacy-to-Onyx shield, legacy ownership signature, key-image replay prevention, atomic supply accounting, undo and supply-audit RPC. | Operational migration rehearsal, incident rollback procedure and independent supply-invariant audit. |
| O5 standard programs | Canonical registry, activation/deactivation, cost accounting, funded capped-token deployment, private issuance, mixed token/native-fee transfers, wallet-derived registry state, status RPC, versioned ABI profile and deterministic descriptor SDK/vector boundary. | Language bindings and additional audited standard programs if retained in scope; external audit. |

## Remaining implementation work

### O5 developer platform

1. Freeze a versioned public SDK package around the existing C ABI and wallet RPC, including language
   bindings, golden request/response fixtures, compatibility policy and semantic versioning.
2. Decide whether arbitrary private programs are still in scope. If yes, write a separate compiler
   specification (type system, bounded control flow, constraint semantics, canonical IR, verifier-key
   reproducibility and resource analysis) before implementing an ACIR/Leo-like frontend. Unknown or
   user-supplied circuits continue to fail closed until that compiler and verifier pipeline are audited.
3. Implement only approved standard circuits (the original architecture mentions NFT, vesting,
   multisignature custody and swaps), each with isolated value domains, canonical schemas, negative
   vectors, cost budgets and an independent circuit review.

### O6 network, scaling and crypto agility

1. The negotiated Dandelion++ relay now has epoch rotation, stem-loop prevention, randomized
   embargo/fluff recovery, hop limits, disconnect recovery, legacy-peer fallback, bounded delivery
   scoring/decay and weighted randomized peer rotation. A selected peer's own fluff reflection cannot
   cancel its embargo. Remaining: multi-node adversarial topology simulation, fuzz soak and independent
   network-privacy review.
2. Fail-closed no-auth SOCKS5 outbound transport is implemented with numeric proxy/peer addresses,
   bounded negotiation and no local destination lookup. Canonical v3 onion and I2P b32 destination
   framing is fail-closed, but the peer database/wire identity is still numeric. Remaining: persistent
   hidden-service peer identity integration, Tor/I2P process tests, leak testing and independent review.
3. A dormant, versioned RandomX v2.0.1 transition is integrated for node and bundled miner with
   delayed branch-derived seed epochs, explicit template negotiation and a repository KAT. Shared
   full-memory datasets, persistent multithread workers, strict light/large-page policy, native
   x86-64/ARM64 equality and an actual branch-seed epoch reorganization are CI-gated. Remaining:
   independent review, RISC-V gate stabilization, deeper randomized reorg/long-sync tests, published
   throughput/power benchmarks and public soak.
4. Proof aggregation/recursion only after profiling demonstrates a concrete need and the accumulation
   construction receives an independent cryptographic review.
5. Jade V5 now binds a stable explicit authorization-scheme identifier into its signed prefix and
   rejects unknown or inactive schemes; wallet construction follows the Jade transaction version at
   activation. V1-V4 and the Onyx envelope encoding remain unchanged. The reserved hybrid-PQ registry
   value is not an implementation: its algorithm/dependency selection, key migration, address/public-key
   commitments, proof/signature sizes, hybrid downgrade rules, vectors and audit remain required.

### Release readiness

Deterministic tracked-source archives, SPDX 2.3 SBOM generation, immutable dependency/vendored-tree
locks, duplicate-generation comparison, checksums, pinned CI actions and tag provenance attestations
are implemented in `tools/release`, `release/` and `.github/workflows/release-evidence.yml`. The legacy
Azure publisher is disabled because its runner images, dependency acquisition and OpenSSL release are
not a trustworthy or reproducible build boundary. `docs/Release-Readiness.md` defines the two-person
ceremony and `docs/Incident-Response.md` defines the consensus/privacy response and rollback boundary.
The activation-gate verifier keeps all placeholder heights unchanged while any mandatory evidence is
not passed.

### Release gates that cannot be completed by repository code alone

- Two independent cryptographic/consensus audits with no unresolved critical or high findings.
- Public testnet activation and soak under realistic proving, sync, reorg, spam and recovery load.
- Signed reproducible artifacts on supported platforms plus dependency provenance/SBOM verification.
- Published incident response, halt/rollback, migration and governance procedures.
- Explicit governance approval and only then replacement of placeholder activation heights.

## Security boundary

No implementation can honestly provide “foolproof,” “unbreakable,” or absolute trustlessness. The
target is a small fail-closed consensus surface, deterministic independently verifiable state, strong
privacy under documented assumptions, and operational controls that limit failures. Halo2/Pasta is
not post-quantum. External audits and public adversarial operation are mandatory parts of completion,
not documentation formalities.
