# Onyx implementation status and completion plan

This file reconciles the original architecture roadmap with the code that is actually present. It is
an engineering status document, not an activation claim. Consensus activation heights remain
unreachable until the release gates below are independently satisfied.

## Implemented baseline

| Gate | Implemented evidence | Remaining exit condition |
|---|---|---|
| O0 proof foundation | Exact-pinned vendored Halo2/Pasta crate, bounded panic-contained C ABI, CMake integration, locked offline three-platform workflow, primitive vectors and malformed-input tests. | External dependency/proof-boundary review and reproducible release artifacts. |
| O1 state model | Canonical notes/envelopes, encryption, commitment tree, retained anchors, nullifier set, bounded snapshots, atomic apply/undo, replay and reorg tests. | Independent consensus-state audit and long-running randomized differential/fuzz campaigns. |
| O2 private transfer | Shape-bound Halo2 transfer circuits, spend and binding authorization, value conservation, expiry/network binding, negative mutation tests and cost limits. | Independent circuit audit and published laptop benchmarks at frozen release parameters. |
| O3 wallet | Seed/key hierarchy, Onyx addresses, full viewing keys, scanning, historical witnesses, proving, recovery snapshots, pending reservations, native/token balances and wallet RPC. | End-to-end multi-node devnet recovery, backup, hardware-wallet and operator acceptance tests. |
| O4 migration | One-way legacy-to-Onyx shield, legacy ownership signature, key-image replay prevention, atomic supply accounting, undo and supply-audit RPC. | Operational migration rehearsal, incident rollback procedure and independent supply-invariant audit. |
| O5 standard programs | Canonical registry, activation/deactivation, cost accounting, funded capped-token deployment, private issuance, mixed token/native-fee transfers, wallet-derived registry state, status RPC and deterministic descriptor SDK/vector boundary. | Additional audited standard programs if retained in scope; SDK compatibility suite; external audit. |

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

1. Dandelion++ transaction relay with epoch rotation, stem-loop prevention, embargo/fluff recovery,
   peer scoring and adversarial topology simulation.
2. Explicit SOCKS5/Tor/I2P-capable outbound transport with DNS-leak prevention and integration tests.
3. A separately reviewed RandomX fork transition with deterministic vectors for node and miner,
   activation/reorg tests and multi-architecture benchmarks.
4. Proof aggregation/recursion only after profiling demonstrates a concrete need and the accumulation
   construction receives an independent cryptographic review.
5. Backend agility uses explicit versioned hard forks. A post-quantum backend is not considered
   implemented merely because an interface exists; key migration, address formats, proof/signature
   sizes and hybrid transition rules require their own specification and audit.

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
