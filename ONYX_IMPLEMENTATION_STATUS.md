# Onyx implementation status and completion plan

This file reconciles the original architecture roadmap with the code that is actually present. It is
an engineering status document, not an activation claim. Consensus activation heights remain
unreachable until the release gates below are independently satisfied.

## Implemented baseline

| Gate | Implemented evidence | Remaining exit condition |
|---|---|---|
| O0 proof foundation | Exact-pinned vendored Halo2/Pasta crate, active fail-closed proof-system seam, bounded panic-contained C ABI, CMake integration, locked offline three-platform workflow, primitive vectors, malformed-input/batch-shape tests, and an automated ASan/UBSan/libFuzzer gate with deterministic C++ parser/Onyx envelope seeds. Structured consensus verification/extraction and deterministic key/hash/toy-prover entry points clear fixed caller outputs, allocation pairs and element counts before every post-validation failure; hash input/output aliasing is explicitly supported. | External dependency/proof-boundary review, sustained independently reviewed fuzz campaigns over valid proof envelopes and reproducible release artifacts. |
| O1 state model | Canonical notes/envelopes, encryption, commitment tree, retained anchors, nullifier set, bounded snapshots, atomic apply/undo, replay and reorg tests. Snapshot decoding rejects state the transition path cannot emit, including duplicate consecutive anchor roots, a final anchor height that differs from the persisted current height, and token issuance sequences greater than their strictly positive issued supply. Direct C ABI supply-audit and standard-state queries clear every caller-visible output before snapshot or application decoding can fail. | Independent consensus-state audit and long-running randomized differential/fuzz campaigns. |
| O2 private transfer | Shape-bound Halo2 transfer circuits, spend and binding authorization, value conservation, expiry/network binding, negative mutation tests and cost limits. | Independent circuit audit and published laptop benchmarks at frozen release parameters. |
| O3 wallet | Seed/key hierarchy, Onyx addresses, full viewing keys, scanning, historical witnesses, proving, recovery snapshots, pending reservations, native/token balances and wallet RPC. Encrypted native backup/password rotation and view-only recovery preserve keys, address count, labels and queued payments under automated qualification. A real four-daemon process test now backs up the SQLite wallet/cache, rotates its password, rejects the superseded password, reconnects through an alternate synchronized node, preserves addresses and balance, and spends from the recovered wallet. Legacy construction uses the overflow-checked next-block version, emits Jade at the exact boundary and fails closed one block before Onyx instead of producing a V5 transaction that V7 consensus rejects. Every transaction-producing Onyx RPC uses the same next-block boundary, rejecting premature construction and enabling it one block before activation for next-block admission. A shared overflow-safe wallet policy measures every explicit expiry from that expected inclusion height and matches consensus at both inclusive endpoints. | Hardware-wallet and operator acceptance tests. |
| O4 migration | One-way legacy-to-Onyx shield, legacy ownership signature, layered key-image replay prevention, atomic supply accounting, undo and supply-audit RPC. The Onyx snapshot now stores a domain-separated bridge replay marker in addition to the legacy consensus key-image database, so direct state replay cannot double-count bridged supply; rollback removes the marker. Wallet construction also rejects a second bridge for a legacy key image already present in its pending queue. Production C ABI/C++ qualification covers wallet proving, finalization, field preservation, state apply, exact supply reconciliation, replay rejection and fail-closed output clearing. The ASan/UBSan/libFuzzer campaign directly mutates the versioned state/supply-audit decoder from deterministic malformed v7 seeds. | Multi-node operational migration rehearsal, incident rollback drill and independent supply-invariant audit. |
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
   deterministically topologically ordered and embedded for offline reproduction. Bundle publication
   rejects existing and dangling output paths before compilation, maps backend launch failures/timeouts
   to stable diagnostics and atomically publishes only a completely staged directory. Standard-program
   pin rotation has an all-program regenerator that independently verifies every staged bundle before
   replacing tracked manifests, IR or descriptors. Remaining:
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
   independent review remains. The production depth-32 Rust C ABI/C++ adapter is positively qualified with a
   Rust-pinned deterministic wallet fixture that creates and verifies a funded NFT deployment and creates and
   authenticates a serial-bound NFT state transition; rejected proving requests must clear all caller-visible outputs.
   Python and TypeScript SDK 1.1.0 expose byte-identical canonical application-data builders and frozen schema hashes
   with strict uint64, identifier, threshold, boolean and Pasta-field validation. Canonical IR/descriptor artifacts
   are digest-pinned, reproducibly regenerated, embedded in Rust and used by a caller-artifact-free standard verifier
   and activation-bound registry-entry builder.

### O6 network, scaling and crypto agility

1. The negotiated Dandelion++ relay now has epoch rotation, stem-loop prevention, randomized
   embargo/fluff recovery, hop limits, disconnect recovery, legacy-peer fallback, bounded delivery
   scoring/decay and weighted randomized peer rotation. A selected peer's own fluff reflection cannot
   cancel its embargo. A deterministic 64-peer/20,000-transaction adversarial campaign is CI-gated
   across all three platforms. A four-daemon socket-level qualification now mines spendable funds
   through real miner/wallet processes and proves encrypted SQLite backup, password rotation,
   alternate-node wallet recovery, address/balance preservation and recovered-wallet spending before
   checking stem-only visibility, reflected-fluff loop resistance, embargo recovery, disconnect recovery
   and immediate negotiated-v4 compatibility diffusion. Its
   non-default v4 fixture shares the production parser/consensus/socket stack and exposes no runtime
   downgrade switch. Bounded epoch, embargo and fluff-probability controls fail closed on invalid input.
   Remaining: historical released-v4 binary matrix, fuzz soak, public testnet topology soak and independent
   network-privacy review.
2. Fail-closed no-auth SOCKS5 outbound transport is implemented with numeric proxy/peer addresses,
   bounded negotiation and no local destination lookup. Canonical v3 onion and I2P b32 destination
   framing is fail-closed, and protocol v6 carries canonical proxy-only onion/I2P identities through
   configuration, advertisement and peer-DB persistence without changing v1-v5 numeric encoding.
   Untrusted anonymity peer lists are graylisted and limited to 16 unresolved referrals per source.
   Only a validated outbound handshake clears referral provenance; eight consecutive unreachable
   referrals ban the source and remove its sole-source graylist entries. Proxy negotiation failures
   before destination selection do not blame the advertised destination.
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
100-level array/object nesting bound is named and boundary-tested. Decoded duplicate object names,
including escape-equivalent spellings, fail as parse errors before JSON-RPC method dispatch. Unicode
escapes produce shortest-form UTF-8 with strict surrogate-pair handling, and malformed raw or escaped
Unicode fails before dispatch. A raw-socket real-daemon CI test
proves 413 rejection, streaming-header cutoff, duplicate-length rejection, connection-cap blocking,
accept recovery, slow-header eviction and daemon liveness. These are transport/resource limits, not
consensus rules.
Unhandled transport and JSON-RPC exceptions are logged generically and return stable generic errors
instead of internal exception strings. Wallet RPC credentials use content-independent comparison and
can be loaded from a size-bounded protected file; POSIX group/other access is rejected, the legacy
process-argument option is rejected, and TLS termination remains mandatory for non-local exposure.
The secret-bearing hardware-wallet emulator is excluded from default/release source lists, guarded by
an explicit non-release build option, rejected at runtime in normal walletd, and checked by artifact
marker scanning in CI. The mempool admits at most 256 zero-fee standard-program calls and checks that
cap before Halo2 verification; insertion, eviction, removal and reorganization bookkeeping preserve
the bound. This is relay/admission policy, not block consensus. Supply-audit caching from the latest
static review is also implemented: the full snapshot audit is cached by exact tip hash, so repeated
unauthenticated calls at one tip copy a stable response while same-height reorganizations recompute.
Wallet and node documentation now states the legacy remote-decoy correlation limit prominently, the
privacy sync flag is visible in walletd help, and walletd's internal logs omit construction requests,
amount sets, decoy sets, hashes and raw transaction bodies. This prevents accidental hosted-service
logging but cannot make an untrusted remote operator cryptographically trustworthy.
The experimental Emscripten wallet no longer stores mnemonic-bearing JSON in plaintext. Its IndexedDB
record is a size-bounded, password-derived ChaCha20 envelope with a keyed authentication tag; empty
passwords, wrong passwords, malformed fields and modified ciphertext fail closed. Existing plaintext
records are rewritten before wallet-open succeeds, and password rotation is acknowledged only after
the replacement record is durably accepted by the browser storage API. A pinned Emscripten toolchain
compiles the browser-only wallet and IndexedDB branches against the locked Boost headers in CI.
Peer addresses are redacted from connection-level logs unless an explicit diagnostic option is set,
archive source-IP attribution has a clearly named opt-in and remains off by default, and PeerDB v3
to v4 replacement now tells operators that peer discovery will restart. Anonymity referrals remain
untrusted until an outbound handshake succeeds, with per-source admission and failure bounds limiting
peer-list poisoning.

### Release readiness

Deterministic tracked-source archives, SPDX 2.3 SBOM generation, immutable dependency/vendored-tree
locks, duplicate-generation comparison, checksums, pinned CI actions and tag provenance attestations
are implemented in `tools/release`, `release/` and `.github/workflows/release-evidence.yml`. The legacy
Azure publisher is disabled because its runner images, dependency acquisition and OpenSSL release are
not a trustworthy or reproducible build boundary. `docs/Release-Readiness.md` defines the two-person
ceremony and `docs/Incident-Response.md` defines the consensus/privacy response and rollback boundary.
The release lock and current build guidance now use Boost 1.91.0 and OpenSSL 3.5.7; networked
verification re-fetches their immutable archives and the pinned LMDB revision, while the Onyx lock
binds the exact tracked vendored/Cargo tree.
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
