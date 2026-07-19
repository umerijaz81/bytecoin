# Onyx implementation status and completion plan

This file reconciles the original architecture roadmap with the code that is actually present. It is
an engineering status document, not an activation claim. Consensus activation heights remain
unreachable until the release gates below are independently satisfied.

## Implemented baseline

| Gate | Implemented evidence | Remaining exit condition |
|---|---|---|
| O0 proof foundation | Exact-pinned vendored Halo2/Pasta crate, bounded panic-contained C ABI, CMake integration, locked offline three-platform workflow, primitive vectors, malformed-input tests, and an automated ASan/UBSan/libFuzzer gate with deterministic C++ parser/Onyx envelope seeds. | External dependency/proof-boundary review, sustained independently reviewed fuzz campaigns over valid proof envelopes and reproducible release artifacts. |
| O1 state model | Canonical notes/envelopes, encryption, commitment tree, retained anchors, nullifier set, bounded snapshots, atomic apply/undo, replay and reorg tests. | Independent consensus-state audit and long-running randomized differential/fuzz campaigns. |
| O2 private transfer | Shape-bound Halo2 transfer circuits, spend and binding authorization, value conservation, expiry/network binding, negative mutation tests and cost limits. | Independent circuit audit and published laptop benchmarks at frozen release parameters. |
| O3 wallet | Seed/key hierarchy, Onyx addresses, full viewing keys, scanning, historical witnesses, proving, recovery snapshots, pending reservations, native/token balances and wallet RPC. | End-to-end multi-node devnet recovery, backup, hardware-wallet and operator acceptance tests. |
| O4 migration | One-way legacy-to-Onyx shield, legacy ownership signature, key-image replay prevention, atomic supply accounting, undo and supply-audit RPC. | Operational migration rehearsal, incident rollback procedure and independent supply-invariant audit. |
| O5 standard programs | Canonical registry, activation/deactivation, cost accounting, funded capped-token deployment, private issuance, mixed token/native-fee transfers, and stateful NFT/vesting/multisig/swap calls. Type-4 calls compose native authorization with a pinned standard proof, apply atomically, reserve pending nullifiers/state keys, expose wallet construction and daemon state queries, and are represented in the versioned Python and JavaScript/TypeScript RPC profiles. | Additional native-language bindings, completion/audit of the arbitrary-program compiler pipeline, independent circuit/consensus review, and public testnet qualification. |

## Remaining implementation work

### O5 developer platform

1. Extend the frozen v1 SDK profile beyond the dependency-free Python and JavaScript/TypeScript
   packages where another native language has an identified maintainer. Both packages, golden
   request/response fixtures, compatibility policy, semantic versioning and byte-for-byte
   three-platform package reproduction are CI-gated.
2. The arbitrary-private-program boundary is frozen in `docs/Onyx-Compiler-Specification.md`. A
   non-registrable alpha frontend now implements strict source-package loading, a bounded typed parser,
   static loop/conditional lowering, acyclic direct calls, guarded canonical binary IR, conservative
   resource analysis, reproducible bundles and a strict independent decoder/recompiler with frozen
   cross-platform digests. Fixed arrays have canonical construction and bounded-index IR; records have
   canonical nonrecursive construction and field access; fixed byte strings use exact-length lowercase
   hex literals. Content-addressed libraries are lock/tree-digest verified, namespace isolated,
   deterministically topologically ordered and embedded for offline reproduction. Remaining:
   the Pasta-field/boolean/checked-unsigned-integer language has deterministic Halo2 gates, pinned verifying-key
   descriptor regeneration, real randomized proof creation/verification, IR/profile key binding and
   positive/negative proof vectors. Integer range, overflow/underflow, ordering, Euclidean division/remainder,
   dynamic shifts and field nonzero division are constraint-enforced. Acyclic direct helper calls are signature-checked
   and deterministically inlined into a single export. Guarded execution uses safe-operand selection, canonical
   inactive values, assertion implication and transitive call guards without disabling arithmetic constraints.
   Arrays, records and fixed bytes flatten across parameters, returns, calls, guards, constructors, projections and
   bounded dynamic indexing, with real multi-leaf proof vectors. Versioned Poseidon, domain-separated Merkle-node and
   position-bound nullifier intrinsics match an independent Grain/MDS evaluator and real proof vectors. Multi-export
   IR uses exact entry selection with export identity fixed into descriptor v2 and the circuit, and bundles regenerate
   one descriptor per declared export. A seeded 48-case structured campaign differentially checks scalar semantics,
   deterministic IR, malformed canonical encodings and bounded real-backend lowering on all CI platforms. Sustained
   coverage-guided fuzzing, independent audit and testnet gates still remain. Unknown or
   user-supplied circuits continue to fail closed until all of those gates pass.
3. Implement only approved standard circuits (the original architecture mentions NFT, vesting,
   multisignature custody and swaps), each with isolated value domains, canonical schemas, negative
   vectors, cost budgets and an independent circuit review. A canonical non-circular program-context v1
   now binds transaction projections, ordered call identity, inclusion windows, optional state commitments
   and application data into a frozen 22-field circuit ABI. A bounded canonical envelope now carries the
   authorized transaction and exactly one context and proof per ordered call; authorization covers the complete
   versioned proof bundle. The rollback-safe contextual state path validates every ordered context before mutation.
   Exact registered native/single-program-asset base dispatch and export-bound compiler proof composition are
   implemented through the consensus C ABI and C++ state adapter. A canonical native decoder now derives typed public
   suffixes for NFT, vesting, multisig and swap profiles and enforces state/timelock invariants. Four pinned source
   packages reproduce export-bound descriptors at `k=16`; real proof vectors
   cover NFT owner continuity, vesting timelocks, pairwise-distinct 1–16 threshold custody and swap claim/refund
   semantics, including insufficient-approval and duplicate-participant rejections. Canonical deployments, wallet
   proving, RPC/SDK profiles, state queries, reorg-safe application and mempool state-conflict eviction are wired;
   independent review remains. Python and TypeScript SDK 1.1.0 expose byte-identical canonical application-data builders and
   frozen schema hashes with strict uint64, identifier, threshold, boolean and Pasta-field validation; wallet/RPC
   proving flows remain. Canonical IR/descriptor artifacts are digest-pinned, reproducibly regenerated, embedded
   in Rust and used by a caller-artifact-free standard verifier and activation-bound registry-entry builder.

### O6 network, scaling and crypto agility

1. The negotiated Dandelion++ relay now has epoch rotation, stem-loop prevention, randomized
   embargo/fluff recovery, hop limits, disconnect recovery, legacy-peer fallback, bounded delivery
   scoring/decay and weighted randomized peer rotation. A selected peer's own fluff reflection cannot
   cancel its embargo. A deterministic 64-peer/20,000-transaction adversarial campaign is CI-gated
   across all three platforms. A four-daemon socket-level qualification now mines spendable funds
   through real miner/wallet processes and proves stem-only visibility, reflected-fluff loop resistance,
   embargo recovery, disconnect recovery and immediate negotiated-v4 compatibility diffusion. Its
   non-default v4 fixture shares the production parser/consensus/socket stack and exposes no runtime
   downgrade switch. Bounded epoch, embargo and fluff-probability controls fail closed on invalid input.
   Remaining: historical released-v4 binary matrix, fuzz soak, public testnet topology soak and independent
   network-privacy review.
2. Fail-closed no-auth SOCKS5 outbound transport is implemented with numeric proxy/peer addresses,
   bounded negotiation and no local destination lookup. Canonical v3 onion and I2P b32 destination
   framing is fail-closed, and protocol v6 carries canonical proxy-only onion/I2P identities through
   configuration, advertisement and peer-DB persistence without changing v1-v5 numeric encoding.
   The real Linux daemon is CI-qualified against an adversarial SOCKS5 process: successful relays are
   source-distinguished from direct connections, proxy rejection has no direct fallback, and an onion
   `getaddrinfo` tripwire proves there is no local destination lookup. Remaining: real Tor/I2P
   multi-node service tests, cross-platform packet capture and independent review.
3. A dormant, versioned RandomX v2.0.1 transition is integrated for node and bundled miner with
   delayed branch-derived seed epochs, explicit template negotiation and a repository KAT. Shared
   full-memory datasets, persistent multithread workers, strict light/large-page policy, native
   x86-64/ARM64 equality, RV64GC v2 vectors under QEMU and an actual branch-seed epoch reorganization
   are CI-gated. A fourteen-switch randomized multi-epoch campaign persists both branches, reopens the
   database and reorganizes onto the retained branch while checking every selected seed ancestor.
   The real daemon/miner process path accepts and submits a canonical template, while mock-daemon cases
   prove fail-closed retry without hashing/submission for malformed metadata, blobs, seeds, parent and
   coinbase-height bindings. Remaining: independent review, longer public long-sync/reorg soak,
   published throughput/power benchmarks on native qualification hardware and public soak.
4. Proof aggregation/recursion only after profiling demonstrates a concrete need and the accumulation
   construction receives an independent cryptographic review.
5. Jade V5 now binds a stable explicit authorization-scheme identifier into its signed prefix and
   rejects unknown or inactive schemes; wallet construction follows the Jade transaction version at
   activation. V1-V4 and the Onyx envelope encoding remain unchanged. The reserved hybrid-PQ registry
   value is not an implementation: its algorithm/dependency selection, key migration, address/public-key
   commitments, proof/signature sizes, hybrid downgrade rules, vectors and audit remain required.

### Cross-cutting RPC hardening

The shared bytecoind/walletd HTTP server now rejects request headers above 32 KiB, conflicting
`Content-Length` headers and declared bodies above 4 MiB before body allocation. It bounds live
clients at 128, requires headers within 5 seconds and an allowed body within 30 seconds, and resumes
accepting as soon as a slot is released. The JSON parser's existing
100-level array/object nesting bound is named and boundary-tested. A raw-socket real-daemon CI test
proves 413 rejection, streaming-header cutoff, duplicate-length rejection, connection-cap blocking,
accept recovery, slow-header eviction and daemon liveness. These are transport/resource limits, not
consensus rules.
Unhandled transport and JSON-RPC exceptions are logged generically and return stable generic errors
instead of internal exception strings. Wallet RPC credentials use content-independent comparison and
can be loaded from a size-bounded protected file; POSIX group/other access is rejected, the legacy
process-argument option is rejected, and TLS termination remains mandatory for non-local exposure.
The secret-bearing hardware-wallet emulator is excluded from default/release source lists, guarded by
an explicit non-release build option, rejected at runtime in normal walletd, and checked by artifact
marker scanning in CI. Zero-fee standard-call pool policy and supply-audit caching from the latest
static review remain separate hardening work.

### Release readiness

Deterministic tracked-source archives, SPDX 2.3 SBOM generation, immutable dependency/vendored-tree
locks, duplicate-generation comparison, checksums, pinned CI actions and tag provenance attestations
are implemented in `tools/release`, `release/` and `.github/workflows/release-evidence.yml`. The legacy
Azure publisher is disabled because its runner images, dependency acquisition and OpenSSL release are
not a trustworthy or reproducible build boundary. `docs/Release-Readiness.md` defines the two-person
ceremony and `docs/Incident-Response.md` defines the consensus/privacy response and rollback boundary.
Same-runner full daemon, wallet and miner builds now reproduce byte-for-byte on Linux x64, macOS ARM64
and Windows x64, with exact manifests retained by CI. Independent pinned-dependency builders and
signatures are still required. The activation-gate verifier keeps all placeholder heights unchanged
while any mandatory evidence is not passed.

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
