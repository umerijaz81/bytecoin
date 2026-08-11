# Jade/Onyx Project Progress and Implementation Handoff

Last reviewed: 2026-08-11
Repository: `https://github.com/umerijaz81/bytecoin.git`  
Working branch: `kimiK3/jade-onyx-hardening`  
Last implementation revision reviewed: `5101111` (`Qualify Onyx rollback and recovery`)

## 1. Purpose and status vocabulary

This is the detailed engineering handoff for continuing the Bytecoin Jade/Onyx work with another
developer or AI tool. It records what is implemented, what is only present as uncommitted work, what
has been tested, and what still requires implementation or independent evidence.

The words below have precise meanings:

- **Implemented and committed** means the code is in the branch history at or before `5101111`.
- **In progress** means code exists only in the current working tree and must not be treated as
  finished, reviewed, or published.
- **Repository-complete** means the planned code and automated tests exist. It does not imply that
  cryptography or consensus is secure.
- **Release-complete** requires independent audits, public qualification, reproducible binaries,
  an incident drill, provenance, and governance approval. Those external gates are still incomplete.
- **Verified in the current work session** means the stated command was run against the current
  checkout. Historical claims in other status documents should be independently rerun before release.

No cryptocurrency implementation can honestly be described as "foolproof", "unbreakable", or
perfectly trustless. This branch materially hardens the code and implements a shielded protocol, but
its safety depends on correct code, frozen parameters, independent review, operational discipline,
and the release gates described below.

## 2. Important workspace instructions

Before changing anything, inspect the worktree:

```powershell
git status --short
git branch --show-current
git log --oneline -20
```

After the migration implementation commit, the unrelated worktree state still contained:

```text
A  Bytecoin_Onyx_Security_Review.md
 M .gitignore
```

`Bytecoin_Onyx_Security_Review.md` was already staged by the user. It is not part of the current
qualification-network implementation and must not be edited, unstaged, deleted, or accidentally
included in another commit. When committing other files, use an explicit path list or:

```powershell
git commit --only <paths...> -m "Commit message"
```

Do not use destructive cleanup commands, `git reset --hard`, or broad staging such as `git add -A`.
Preserve unrelated user changes.

## 3. Authoritative documents and precedence

Use these documents together:

1. `ONYX_PROTOCOL_SPEC.md` — consensus and protocol requirements; highest-level technical authority.
2. `ONYX_ARCHITECTURE.md` — component boundaries and architecture.
3. `ONYX_IMPLEMENTATION_STATUS.md` — detailed reconciliation between roadmap and code.
4. `SECURITY_PRIVACY_AUDIT.md` — threat findings and mitigations already applied.
5. `JADE_UPGRADE.md` — Jade-specific design and compatibility information.
6. `ONYX_MIGRATION.md` — legacy-to-Onyx bridge and supply rules.
7. `ONYX_PROGRAMS.md` — standard-program registry and state model.
8. `docs/Release-Readiness.md` — enforced release evidence and external exit gates.
9. This file — operational handoff and current worktree state.

If prose disagrees with consensus code or tests, stop and reconcile it. Never silently choose the
more permissive interpretation.

## 4. Consensus version and activation model

The production configuration currently uses these four equal placeholder heights:

```cpp
UPGRADE_HEIGHT_V5          = 10000000;
RANDOMX_SWITCH_HEIGHT      = 10000000;
UPGRADE_HEIGHT_RESERVED_V6 = 10000000;
UPGRADE_HEIGHT_ONYX        = 10000000;
```

`src/CryptoNoteConfig.hpp` contains a compile-time assertion requiring those values to remain
co-scheduled. The release verifier independently parses the constants and requires both equality and
the compile-time assertion.

The intended reachable production path is:

```text
legacy V1–V3 -> Amethyst V4 -> Onyx V7
```

The version selector jumps directly from V4 to V7 at the common activation height. It deliberately
does not expose a production V5 or V6 interval:

- **V5/Jade** remains isolated for compatibility and targeted tests. Its confidential-amount and
  large-membership roadmap was not completed, so it must not become independently reachable.
- **V6** is reserved.
- **V7/Onyx** is the shielded transaction/state protocol.
- **RandomX** switches at the same boundary as Onyx so there is no unintended separate fork interval.

Relevant commits:

- `f332647` — skip incomplete Jade consensus versions.
- `13f2d54` — align RandomX with Onyx activation.
- `8671803` — enforce activation co-scheduling at compile time.

Do not change one height by itself. A real activation proposal must update the complete schedule,
tests, release evidence, reference block, and governance record together.

## 5. Phase-by-phase implementation status

### O0 — Proof-system foundation

Status: **Repository implementation substantially complete; external review and sustained fuzzing
remain.**

Implemented:

- Exact-pinned, vendored Rust proof dependencies based on Halo2/Pasta.
- Offline Cargo configuration and committed vendor tree.
- A bounded, panic-contained C ABI between C++ consensus/wallet code and Rust.
- `cn::zk::IProofSystem` and the active `Halo2ProofSystem` adapter.
- Fail-closed behavior when ZK support is absent or malformed inputs are supplied.
- ABI versioning, deterministic hash/key entry points, typed proof extraction and verification.
- Fixed caller outputs, allocation pairs, and element counts are cleared on post-validation failure.
- Supported hash input/output aliasing is explicitly tested.
- Batch-shape validation and null verifying-key protections.
- CMake integration with recursive first-party Rust input tracking.
- Separate artifacts for ZK, non-ZK, sanitizer, and release build directories.
- Known-answer, malformed-input, sanitizer, and fuzz scaffolding.
- Deterministic seeds for the C++ parser and Onyx envelope fuzz targets.

Primary locations:

- `src/Core/zk/`
- `vendor/onyx-zk/`
- `tests/zk/`
- `docs/Onyx-Fuzzing.md`
- CMake files referencing `ONYX_ZK`

Still required:

- Independent cryptographic dependency and FFI-boundary review.
- Sustained coverage-guided fuzzing over valid and malformed proof envelopes.
- Reproducible release artifacts on all required platforms.
- Published proof-generation and verification benchmarks at frozen parameters.

### O1 — Canonical Onyx state

Status: **Repository implementation substantially complete; independent consensus audit and long
campaigns remain.**

Implemented:

- Canonical notes and versioned Onyx envelopes.
- Note encryption and network/domain binding.
- Commitment tree, retained anchors, nullifier set, and bounded snapshots.
- Atomic state application and rollback.
- Replay, duplicate-nullifier, stale-anchor, reorganization, and persistence coverage.
- Snapshot rejection for impossible or noncanonical state.
- Token issuance ledger validation: sorted unique entries, positive sequence/supply, registered
  mintable programs, and cap enforcement.
- Supply-audit and standard-state query paths that clear caller-visible outputs on failure.
- Tip-hash keyed supply-audit caching that recomputes on same-height reorganization.

Primary locations:

- `src/Core/Onyx*`
- `src/Core/zk/`
- `tests/zk/`
- `ONYX_PROTOCOL_SPEC.md`
- `ONYX_PROGRAMS.md`

Still required:

- Independent consensus-state audit.
- Long randomized differential apply/undo/reorg campaigns.
- Crash-recovery campaigns against real database interruption points.

### O2 — Private transfers and authorization

Status: **Core implementation complete in repository; independent circuit audit and frozen benchmarks
remain.**

Implemented:

- Shape-bound Halo2 transfer circuits.
- Spend authorization and binding authorization.
- Note commitment, nullifier, ciphertext, fee, network, and expiry bindings.
- Value conservation.
- Native asset and program-asset handling.
- Negative mutation tests for public inputs, proof data, signatures, commitments, and authorization.
- Consensus resource and cost limits.
- Toy O0 verifier kept away from production consensus paths.

Primary locations:

- `vendor/onyx-zk/src/`
- `src/Core/zk/`
- `tests/zk/`
- `ONYX_PROTOCOL_SPEC.md`

Still required:

- Two-party or equivalent independent circuit review as part of the audit gate.
- Public benchmark report on representative release hardware.
- Longer malformed-proof and proof-denial-of-service campaigns.

### O3 — Wallet, scanning, recovery, and RPC

Status: **Core repository implementation complete; hardware-wallet and operator acceptance remain.**

Implemented:

- Seed/key hierarchy, addresses, full viewing keys, scanning, witnesses, proving, and recovery.
- Native and token balances.
- Historical witness retention and Onyx-history synchronization.
- Pending note/nullifier/bridge reservations.
- Network-bound portable view-only format.
- Encrypted wallet persistence and portable/browser wallet migration.
- View-only scanning without seed or spend authority.
- Backup, password rotation, alternate-node recovery, address/balance preservation, and recovered
  spending in process-level qualification.
- Transaction construction aligned to the expected next-block version.
- Construction fails closed before Onyx and becomes available one block before activation for
  next-block admission.
- Overflow-safe expiry and fee arithmetic.
- RPC methods for transfers, bridge operations, programs, state, and supply queries.
- Remote-decoy anonymity downgrade rejection and full-width decoy-index arithmetic.
- Wallet logs avoid construction requests, amounts, decoys, hashes, and raw transaction bodies.

Primary locations:

- `src/Core/Wallet.cpp`
- wallet implementation and RPC files under `src/`
- `docs/Bytecoin-Wallet-Daemon-JSON-RPC-API.md`
- browser wallet sources and tests
- `tests/`

Still required:

- Hardware-wallet testing with a real supported device or independently maintained implementation.
- Operator acceptance runbook and signed results.
- Multi-operator recovery rehearsal on the frozen qualification revision.

### O4 — Legacy-to-Onyx migration and supply invariants

Status: **Core repository implementation and local three-node operational rehearsal complete;
independent supply audit and public evidence remain.**

Implemented:

- One-way legacy-output shielding into Onyx.
- Legacy ownership authorization.
- Legacy key-image replay prevention plus a domain-separated Onyx bridge replay marker.
- Atomic supply accounting and rollback.
- Supply-audit RPC.
- Pending-wallet bridge replay prevention.
- Authenticated `sign_onyx_bridge` software-wallet RPC that accepts only a verified, still-unsigned
  bridge for the exact wallet-owned unspent output; it re-derives the one-time key and key image,
  produces a one-member ring signature, verifies the result, and never exports the spend key.
- View-only and hardware wallets fail closed on the software signing path; hardware/offline signing
  remains supported through `ownership_sighash` plus `finalize_onyx_bridge`.
- Bridge-specific consensus/proving domain `ONYX_BRIDGE_CIRCUIT_K=13`, matching the committed bridge
  circuit tests instead of over-allocating the unrelated general `k=20` domain.
- Wallet mempool and confirmed-block processing consume the bridged legacy key image, update the
  exact legacy balance, and reject re-signing after either reservation or confirmation.
- State apply, exact supply reconciliation, replay rejection, and fail-closed output tests.
- Real three-node migration from a mined legacy output into the recovered wallet's shielded identity,
  including tamper rejection, relay, mining, audit convergence, exact wallet accounting, and replay
  rejection (`6ee5247`).
- Snapshot and supply decoder fuzz targets.

Primary locations:

- `ONYX_MIGRATION.md`
- bridge/state code under `src/Core/`
- ZK bridge implementation under `vendor/onyx-zk/`
- migration and wallet tests under `tests/`

Still required:

- Incident rollback drill using realistic snapshots.
- Independent supply-invariant audit.
- Public qualification evidence binding start/end supply snapshots and block hashes.

### O5 — Standard programs, compiler, and SDKs

Status: **Substantial implementation exists. Standard programs and the frozen compiler profile are
implemented; independent review and public qualification remain.**

Implemented:

- Canonical program registry with activation/deactivation and resource accounting.
- Funded capped-token deployment, private issuance, and token/native-fee transfers.
- Stateful NFT, vesting, multisignature custody, and swap profiles.
- Canonical application data, contexts, ordered-call bundles, and state conflict handling.
- Atomic program state application and rollback.
- Wallet construction, proof generation, RPC state queries, and mempool conflict eviction.
- Pinned source packages and reproducible export-bound descriptors.
- Deterministic Halo2 gates for the frozen scalar/array/record/fixed-byte language.
- Checked unsigned arithmetic, field/boolean operations, comparisons, division/remainder, shifts,
  guarded execution, bounded indexing, function inlining, and multi-export identity binding.
- Versioned Poseidon, Merkle-node, and nullifier intrinsics.
- Strict parser, type checker, canonical IR, resource analysis, package locking, independent decoder,
  deterministic bundles, and atomic publication.
- Dependency-free Python, TypeScript/JavaScript, and Rust SDK profiles.
- Golden cross-language request/response and canonical byte compatibility.
- Rust SDK network-bound portable keys and typed transport-independent JSON.
- Structured compiler campaign and real proof vectors for supported standard programs.
- Real three-node pinned NFT deployment from an independently funded encrypted wallet, with a
  program-specific `k=16` consensus domain, tamper/pending-spend/replay rejection, registry
  convergence, wallet accounting, and exact supply/fee reconciliation (`1a82773`).
- Real stateful NFT call after activation, with tamper/replay rejection, exact transaction-hash
  propagation, same-stable-key pending conflict rejection, state-query convergence, wallet accounting,
  and exact final supply/fee reconciliation (`060b691`).
- Committed, locally process-qualified capped-token lifecycle with a split deployment ABI: funding remains on the native
  `k=16` circuit, while the token artifact, issuance, and mixed token/native-fee transfer use the
  dedicated `ONYX_TOKEN_CIRCUIT_K=14` domain. The harness covers activation, issuer/sequence/cap,
  tamper, pending conflicts, replay, two-wallet balances, registry, commitments, and exact native
  supply. The exit-zero report is `build/codex-zk/onyx-private-token-qualification.json` and remains
  explicitly `local-ci-not-release-evidence` (`db044e5`).
- A wallet-side funding-availability precheck rejects a pending duplicate capped-token deployment
  before constructing expensive token artifacts. This is bounded-failure hardening, not a substitute
  for node admission backpressure and cold/warm performance qualification.
- Deployment wallet scanning and viewing-only scanning carry funding and program circuit domains
  independently. This was added after a real height-28 run showed all nodes accepting the token
  deployment while the receiver wallet refused to commit the block when it reconstructed the token
  artifact with funding `k=16` instead of token `k=14`.
- Authorized-transfer extraction and application select native `k=16` or token `k=14` from the
  authenticated backend id. This closes the mismatch found after a real issuance reached height 49
  and the subsequent wallet-created mixed token/native-fee transfer was routed to the native domain.
- Commit `3da16ad` locally qualifies vesting, two-of-two multisig custody, swap claim/conflict, and
  timeout-refund paths through height 79. Commit `5101111` extends that release-binary process test
  through an exact durable height-78 SQLite snapshot, first refund at 79, a longer non-refund fork at
  height 80, three-node rollback/reopen, alternate-node receiver-wallet recovery, mempool eligibility
  restoration, and identical refund reconfirmation at height 81.
- The clean unattended `5101111` run exited zero. All three nodes ended on
  `8c7ce1043aadd0a4faeae46a6ef6e5f212a100f7b0353d5d7d79e01205b8cd77` with commitment root
  `c50ae942893af7412b2ea5263665e16a40a65a0eb311058e7e4333a98a63180d`, `742000` bridged,
  `500003` fees, `241997` circulating, 21 commitments, and five programs. The report is
  `build/codex-zk/onyx-program-rollback-qualification.json` and is explicitly local, non-release
  evidence.
- The rollback oracle was height 80 block
  `21784d82597721d2307ccdb20407f5c82d90ca69079cd27b478c9ef65aebfae8`, commitment count 20,
  and root `6eb87a0e11d818b4206600234ec8980e61f405c39ae325e80ba5cea9bba97618`. Reconfirmation reused
  refund transaction `bae8c1def7efe4c31d9a4f78e370224c5c0745fd901701d0d4263b3d08c04635`.

Primary locations:

- `ONYX_PROGRAMS.md`
- `docs/Onyx-Compiler-Specification.md`
- `docs/Onyx-Compiler-Frontend.md`
- `tools/onyx/compiler_v1.py`
- `programs/onyx-standard/`
- `tests/onyx_compiler/`
- `sdk/onyx/python/`
- `sdk/onyx/typescript/`
- `sdk/onyx/rust/`

Still required:

- Independent review of compiler lowering, circuit generation, canonical encodings, and consensus
  integration.
- Sustained compiler/parser/backend fuzzing.
- Public testnet qualification of all standard programs and rollback paths.
- Extra language bindings only when an identified maintainer can satisfy the same compatibility bar.
- Unknown or user-supplied circuits must continue to fail closed until explicitly reviewed and
  activated. Do not generalize the compiler boundary casually.

### O6 — Network privacy, scaling, PoW transition, and releases

Status: **Major repository components implemented; public operation, hardware measurements, audits,
and release ceremony remain.**

Implemented:

- Negotiated Dandelion++ relay with epoch rotation, stem selection, loop prevention, hop limits,
  randomized embargo/fluff recovery, disconnect recovery, delivery scoring, and v4 fallback.
- Deterministic adversarial simulation and four-process daemon/miner/wallet topology tests.
- Fail-closed SOCKS5 outbound transport with no local hidden-service DNS lookup.
- Canonical onion/I2P peer identity framing and peer-database persistence.
- Untrusted anonymity-referral bounds, graylisting, validation, and poisoning resistance.
- Linux adversarial SOCKS5 process test and DNS tripwire.
- Vendored RandomX v2.0.1 with delayed branch-derived seed epochs.
- Node/miner template negotiation, malformed-template failure, architecture KATs, full-memory policy,
  reorganization/reopen campaigns, and real daemon/miner process qualification.
- Release archive, checksum, SBOM, dependency lock, provenance, and evidence verification tooling.
- Strict evidence JSON parsing and resource bounds.

Still required:

- Historical released-v4 binary compatibility matrix.
- Real Tor and I2P multi-node service tests.
- Cross-platform packet capture proving no proxy bypass or DNS leakage.
- Longer public Dandelion, long-sync, RandomX epoch, and reorganization soak.
- Published RandomX throughput, memory, and power measurements on native release hardware.
- Independent network privacy, DoS, RandomX integration, and release-process review.
- All external release gates in section 9.
- Proof aggregation/recursion must not be added unless profiling proves a need and the construction is
  independently reviewed.

## 6. Jade-specific status

Implemented Jade hardening includes:

- Explicit authorization-scheme identifier bound into the signed prefix.
- Unknown or inactive scheme rejection.
- Jade-aware wallet construction at its isolated boundary.
- Correct V5 transaction-size estimation and fee calculation.
- Overflow-safe amount-plus-fee and rounding arithmetic.
- Jade sendproof version and scheme preservation.
- Existing V1–V4 and Onyx encodings remain unchanged.

Not implemented:

- The original standalone Jade confidential-amount phase.
- The original large-membership anonymity phase.
- A production hybrid post-quantum signature scheme.

These omissions are why the production selector skips V5/V6 and activates V7 directly. The reserved
hybrid-PQ registry value is only a reservation. Algorithm choice, dependency review, key migration,
address commitments, downgrade rules, sizes, vectors, and audits are all still required before use.

## 7. Cross-cutting security hardening already implemented

The branch also includes security work outside the phase labels:

- HTTP header limit, request-body limit, connection cap, header/body deadlines, and accept recovery.
- Conflicting `Content-Length` rejection.
- JSON depth limit and duplicate decoded-key rejection, including escape-equivalent names.
- Strict UTF-8 and surrogate handling.
- Generic external errors instead of internal exception leakage.
- Constant-behavior credential comparison and protected credential-file loading.
- Rejection of insecure wallet password process arguments.
- Hardware-wallet emulator excluded from release artifacts and blocked in normal runtime.
- Zero-fee standard-program mempool cap checked before expensive proof verification.
- Peer-address log redaction by default.
- Archive source-IP attribution off by default.
- Browser-wallet encrypted persistence, authenticated migration, wrong-password rejection, and durable
  password rotation.
- Remote decoy count enforcement: insufficient decoys cause `NOT_ENOUGH_ANONYMITY`, never a silently
  smaller ring.

These controls reduce identifiable threats. They do not replace TLS termination, trusted deployment,
rate limiting at the network edge, audit, or operator monitoring.

## 8. Release tooling and evidence hardening

The release verifier is designed to distrust repository evidence until it passes strict checks.
Implemented defenses include:

- Duplicate JSON key rejection.
- Non-finite number rejection.
- Numeric overflow rejection.
- JSON byte, nesting, string, list, and object member bounds.
- Symlink, alias, path traversal, and non-regular-file rejection.
- Exact Git-tracked evidence path checks.
- Evidence replay/count inflation prevention.
- Unicode NFKC identity normalization, whitespace collapse, and case normalization.
- Canonical UTC timestamps only.
- Strict public endpoint syntax.
- Gate ordering: governance cannot precede qualification.
- Activation-height map binding to the exact activation commit.
- Compiler and target-profile digest recomputation.
- Source archive/SBOM regeneration and comparison.
- Dependency and vendored-tree locks.

Recent hardening commits:

```text
c0274b9 Reject duplicate keys in release JSON
1d1b4a4 Reject non-finite release JSON numbers
7d372db Reject overflowing release JSON numbers
d5a1d25 Bound release JSON resource usage
2ccc3e9 Reject aliased release evidence paths
a91869c Prevent release evidence count replay
3bc17e8 Normalize release gate identities
1c0e0e0 Canonicalize release gate time and endpoints
```

## 9. External release gates — all still incomplete

The clean-clone release verifier currently reports six incomplete gates. This is expected and honest.
Do not replace real evidence with placeholders or weaken the verifier.

### 9.1 Source provenance

Required:

- Two distinct independent builders.
- Distinct digest-bound build environments.
- Exact frozen revision and dependency lock.
- Byte-identical source archive and SPDX SBOM hashes.
- Named archive/SBOM tools.
- Committed typed attestations and bound checksum/provenance artifacts.

### 9.2 Independent audits

Required:

- Two distinct normalized audit organizations.
- Audits start after the frozen revision exists.
- Distinct report digests.
- Methodology and verified remediation.
- Zero unresolved critical or high findings.
- Combined coverage of ZK cryptography, consensus/state, wallet/privacy, network/DoS,
  migration/supply, compiler, and reproducibility.

### 9.3 Public testnet soak

Required:

- At least 14 elapsed days.
- At least three independently operated nodes.
- At least 10,000 observed blocks.
- One exact frozen revision and genesis/network identity.
- Reorg, malformed-bundle, and denial-of-service scenarios.
- Final converged height/block hash and supply-audit result on every node.
- Successful migration/supply reconciliation.
- Zero unresolved consensus divergence.
- A public credential-free HTTPS evidence endpoint satisfying verifier syntax.

### 9.4 Reproducible platform binaries

Required platforms:

- Linux x86-64.
- macOS ARM64.
- Windows x86-64.

For each platform, two independent builders must reproduce `bytecoind`, `walletd`, and `minerd`,
including exact binary, debug-symbol, and per-binary SBOM hashes. Compiler, SDK, linker, revision,
dependency lock, and environment identity must be bound.

### 9.5 Incident-response drill

Required:

- At least two participants and an independent observer.
- Named decision authority and recorded communications.
- Consensus-stall, reorg, and proof-DoS scenarios exactly once each.
- Ordered detection, triage, and recovery timestamps.
- Preserved artifacts, clean-room reproduction, verified recovery.
- Migration/supply reconciliation and an unresolved-action list.

### 9.6 Governance approval

Required:

- Approval of the exact revision, compiler digest, target profile, and all four activation heights.
- Vote begins only after all prerequisite qualification gates complete.
- Eligible-electorate list, threshold, distinct approvals, recomputed quorum, objection record, and
  zero unresolved blocking objections.
- Reference mainnet height/hash.
- Activation at least 5,040 blocks after the reference height.

## 10. Fixed `--net=onyx` qualification network

Status: **The fixed network was implemented in `5ed59bd`; its three-node local reorganization
qualification was added in `d1dca30`; wallet recovery across that reorganization was added in
`a26303e`; real migration qualification was added in `6ee5247`; an independent-wallet native
shielded transfer was qualified in `dd9755e`; pinned NFT deployment was qualified in `1a82773`; and
one stateful NFT call was qualified in `060b691`.
The pre-wallet Ubuntu qualification jobs for `5fa57c7` and `8861b86` passed.**

Purpose:

`--net=onyx` provides a fixed public qualification network. It is not a runtime override for mainnet,
stagenet, or testnet and must never allow production activation heights to be bypassed.

Committed implementation:

- `src/Core/Config.cpp`
  - Accepts `--net=onyx`.
  - Refuses the network when built with `ONYX_ZK=OFF`.
  - Uses a distinct network UUID.
  - Uses default ports offset by 3000.
  - Uses 30 payment confirmations.
  - Does not inherit mainnet seed nodes.
- `src/Core/Currency.cpp`
  - Sets all upgrade heights and RandomX switch to height 1 for this fixed network.
  - Uses a distinct genesis nonce.
  - Uses low qualification difficulty.
- `src/CryptoNoteConfig.hpp`
  - Preserves the seven-slot checkpoint-difficulty database format with seven inert zero public keys.
  - Does not inherit checkpoint signing authority from mainnet, stagenet, or testnet.
- `src/Core/BlockChain.cpp`
  - Rejects empty checkpoint public keys before curve signature verification, covering both the
    qualification network's inert slots and out-of-range checkpoint identifiers.
- `src/Core/Wallet.cpp`
  - Binds Onyx wallet identity to the distinct qualification-network UUID.
- `src/main_bytecoind.cpp` and `src/main_walletd.cpp`
  - List `onyx` in network-selection help.
- Node and wallet RPC documentation
  - List the fixed network.
- `docs/Onyx-Qualification-Network.md`
  - Explains identity, height-1 direct V4-to-V7 transition, ZK requirement, lack of compiled seed
    nodes, and the fact that a local run does not satisfy public release evidence.
- `tests/blockchain/test_jade_consensus.cpp`
  - Tests distinct UUID, ports, genesis, no inherited seeds, V7/RandomX at height 1, wallet network
    binding, inert checkpoint keys, and non-ZK refusal.
- `tests/network/test_onyx_qualification_process.py`
  - Starts three isolated qualification daemons, mines competing two- and three-block RandomX
    branches, reconnects the topology, and requires a real longer-branch reorganization.
  - Requires exact final height, block-hash, and supply-audit equality across all three nodes.
  - Rejects truncated V7 transaction bytes on every node while proving continued liveness.
  - Creates an encrypted legacy migration-source wallet, derives its network-bound Onyx identity,
    mines branch-B V7 coinbase rewards to it, and verifies reward recognition after node A reorganizes.
  - Backs up the wallet and cache, rotates its password, rejects the old password, and recovers the
    exact legacy address, Onyx address and balance through node C.
  - Selects a real mined wallet output, constructs a bridge proof, signs it through the protected
    software-wallet RPC, rejects a tampered envelope, relays and mines the V7 bridge, and requires all
    three nodes to converge on the resulting block and exact supply audit.
  - Requires exact conservation (`legacy_amount = shielded_balance + fee`), exact removal of the
    migrated amount from legacy wallet balance, and refusal to sign the consumed output again.
  - Creates a second independent encrypted wallet connected through node B, sends the migrated native
    shielded value minus one fee, reserves the sender's pending spend, rejects a tampered transaction,
    mines the valid transfer, and requires exact sender/receiver balances across the next block.
  - Rejects confirmed nullifier replay and requires all three nodes to reconcile two commitments,
    both fees, and exact circulating supply after the transfer.
  - Uses the independent receiver wallet to deploy the pinned NFT program, rejects a tampered
    deployment and pending duplicate, mines the valid registry transition, requires exact program,
    commitment, fee and wallet accounting on all nodes, and rejects confirmed deployment replay.
  - Advances twenty blocks to activation height 26, proves and relays a real NFT state transition,
    rejects tampered proof data, and requires the exact transaction hash on every node before mining.
  - Proves the mutable NFT nonce is excluded from the stable state key: a second valid proof for nonce
    2 is absent from the pool while nonce 1 remains present and the pool count stays one.
  - Does not treat `send_result="broadcast"` as admission evidence because that legacy field is always
    returned even when `add_transaction` reports a conflict; it verifies admission with
    `get_raw_transaction` instead.
  - Mines the accepted call at height 27, waits for independent proof-bearing block validation, then
    requires identical state through both nonce encodings, confirmed replay rejection, and exact final
    supply (`742000` bridged, `100002` fees, `641998` circulating, five commitments, one program).
  - Proves a testnet daemon cannot cross the network identity/genesis boundary.
  - Emits a revision-bound per-node JSON report explicitly marked as non-release evidence.
- `.github/workflows/consensus-integration.yml`
  - Runs Jade invariants in the existing non-ZK job and adds a ZK-enabled daemon/miner process job.
  - Uploads the scoped local qualification report for inspection.

Validation performed before commit:

- ZK-enabled `tests`, `bytecoind`, `walletd`, and `minerd` targets built successfully.
- ZK-enabled `tests` and `bytecoind` were rebuilt after the checkpoint database correction.
- ZK-enabled and non-ZK `tests.exe --jade` both passed after the final correction.
- Non-ZK `tests`, `bytecoind`, `walletd`, and `minerd` targets built successfully.
- Non-ZK `bytecoind --net=onyx` and `walletd --net=onyx` both refused before startup.
- All 61 release-tool unit tests passed after the final code and test changes.
- The real-process qualification test exposed and then verified the repair for the checkpoint-key
  database shape. The expanded test passed twice locally with three nodes, two divergent RandomX
  branches, a height-3 reorganization, exact supply-audit convergence, malformed V7 rejection, and
  testnet isolation. The fixed genesis observed was
  `325a59101b9bcefcc49dfcbcc2367123ed1b0dd6c04568e964cc8ef4e118284c`.
- The wallet extension passed locally after fresh ZK builds: V7 rewards were recognized, and encrypted
  backup, password rotation, old-password rejection and node-C recovery preserved both wallet domains
  and the exact balance. The qualification target is fixed at one second; performance and proof-DoS
  evidence cannot use this accelerated parameter.
- The migration extension passed locally after fresh ZK builds. A real 6,428-byte bridge transaction
  was accepted into the mempool, mined at height 4, recognized by the wallet, and reconciled identically
  by all three nodes. Tampered-envelope signing and consumed-output re-signing were rejected.
- ZK and non-ZK Release targets `tests`, `bytecoind`, `walletd`, and `minerd` built successfully after
  the transfer changes. Both `tests.exe --jade` runs passed, all 61 release tests passed, Python syntax
  validation passed, and `git diff --check` reported no whitespace errors.
- The largest native 2x2 transfer proof test passed in release mode at `k=16` in 70.50 seconds.
- The three-node process harness passed after a fresh build through reorganization, recovery, bridge,
  independent-wallet transfer, tamper/pending-spend/nullifier-replay rejection, exact two-fee supply
  reconciliation, and testnet isolation. Its report remains explicitly non-release local evidence.
- The comprehensive `tests.exe --zk` run reached its final success result, including ABI, hash KAT,
  toy proof, batch verification, malformed-boundary, standard-program deployment/NFT call proving,
  bridge replay defense, and supply accounting stages.
- Python compiler tests passed 25 tests with six environment-dependent tests skipped; the Python SDK
  passed 10 tests, the TypeScript SDK golden/negative suite passed, and the Rust SDK passed four
  conformance tests.
- Full cold/warm, parallel valid-proof runtime, memory-pressure and denial-of-service qualification is
  still open even though the functional ZK suite now passes.
- The first production-domain standard deployment attempt at the general `k=20` exceeded the
  unchanged 180-second wallet RPC deadline. After routing deployments, pinned standard calls and
  wallet scanning through the full-depth-tested `ONYX_PROGRAM_CIRCUIT_K=16`, the complete process
  rehearsal passed at height 6 with one registered program, four commitments, `100002` total fees and
  `641998` circulating native units. Both build variants, both Jade suites, all 61 release tests and
  the complete ZK suite passed after that change.
- The stateful NFT extension passed locally through height 27. During qualification it exposed three
  harness assumptions that future work must not repeat: absent program state is encoded as an empty
  string, pool version is not transaction membership, and the deprecated send result is not an
  admission verdict. Exact transaction lookup plus pool count now proves pending conflict behavior.
- The passing report is `build/codex-zk/onyx-stateful-nft-qualification.json`, marked
  `local-ci-not-release-evidence`; it records identical final tips and supply audits on all three nodes.
- The capped-token extension passed locally through height 50. It deployed at height 28 with native
  funding `k=16` and token execution `k=14`, activated at height 48, issued 1000 units at height 49,
  and transferred 400 units with a one-unit native fee at height 50. The issuer finished with 600
  token units and 541997 native units; the recipient finished with 400 token units and zero native.
- All nodes ended at block `dde2b74470ed0d0a82cb6aeb45365f66594000f91e16b2048d6874de63dc4e11`
  with commitment root `3e4c4f8a6f509942186fac0025db2d50fadd9e30ceafe0c0309aa338fcb9c221`,
  `742000` bridged, `200003` fees, `541997` circulating, 11 commitments and two programs. Eleven is
  exact: the mixed transfer creates recipient token, token change, and native change commitments.
- Functional qualification does not close valid-proof DoS risk. The `k=20` attempt exceeded 1800
  seconds near 3.2 GB RSS; `k=16` cold verification approached/exceeded 30 minutes; even the passing
  `k=14` route takes minutes per cold peer and needs measured backpressure, prewarming, and load tests.
- Commit `3da16ad` qualifies vesting, multisig, and swap with real release binaries. Deployments were
  mined at heights 51, 52, and 53 and activated at 71, 72, and 73. Early vesting release failed and
  the valid release was mined at 75; one-of-two multisig failed and two-of-two authorization was mined
  at 76; wrong-preimage swap claim failed, the valid claim was mined at 77, a valid competing refund
  branch was excluded by the stable state key, early refund failed, and timeout refund was mined at 79.
- The expanded report is `build/codex-zk/onyx-standard-profiles-qualification.json`. All nodes ended
  at height 79 on `63e8b4f97fb494cd3dacbb82aeb9f188b728116f451b4bd41a937f5b937cbc83`
  with root `6d3606e4b912bb42f48205ed2401d1bf0483b542f036574ca8ca6fa42fd63b1a`,
  `742000` bridged, `500003` fees, `241997` circulating, 21 commitments, and five programs.
- The rollback/reopen extension committed in `5101111` passed a fresh clean run from genesis through
  height 81. It waits for node C's exact durable height-78 database commit before using SQLite online
  backup; a raw copy or an online backup before that commit can legitimately reopen at height 77 even
  when RPC already reports height 78. Python SQLite connections are explicitly closed so Windows can
  remove the temporary tree.
- The first refund confirmed at 79, the snapshot fork reached alternative height-80 block
  `21784d82597721d2307ccdb20407f5c82d90ca69079cd27b478c9ef65aebfae8`, and all three primaries
  durably converged there with the refund undone. The receiver wallet reopened through another node;
  the exact refund binary was sent directly to every daemon that lacked it because a duplicate known
  to one primary is not automatically rebroadcast. The same transaction reconfirmed at 81 on
  `8c7ce1043aadd0a4faeae46a6ef6e5f212a100f7b0353d5d7d79e01205b8cd77`.
- The clean run also exposed and fixed a harness-only timeout: capped-token activation inherited 180
  seconds and timed out after reaching height 32 while peers applied the deployment proof. That call
  now uses 1,800 seconds, crossed the former failure boundary, and reached activation height 48.
- Valid program calls took roughly two minutes to construct and minutes per peer to admit/apply.
  Authenticated standard-call replay and stable-key conflict prechecks are now implemented before
  Halo2 while all eligible mempool and block paths retain full verification. The clean three-node
  precheck rerun finished at height 81 and recorded `0.015` seconds for the competing NFT admission
  and `0.0` seconds (below timer resolution) for the competing swap branch. Bounded verifier queues
  and the other transaction families remain the immediate DoS work.
- External Onyx mempool proof work now has a fail-fast RAII bound of one active verifier globally and
  per source plus, in `585bc4d`, a one-job asynchronous worker shared by HTTP and P2P. The worker
  verifies against a captured immutable tip/height/snapshot; the event loop rejects stale results,
  reruns mutable conflicts, and alone mutates chain/pool/peer state. Contention returns retryable RPC
  `-104`; P2P overload is not a ban reason. Blocks still verify independently. ZK/non-ZK Release
  builds and Jade tests pass, and the real two-node valid-proof HTTP/P2P harness passes locally.
- Private transfers now use a signature-authenticated, proof-free metadata extractor for semantic fee
  calculation, read-only `get_tx_fee()`, pool nullifier checks, and a current-snapshot spent-nullifier
  precheck. A non-conflicting transfer still enters the full stateful Halo2 verifier exactly once
  before admission. This removes the former three proof verifications in the admission path without
  weakening block or mempool consensus checks. The optimized real-transfer regression proves fresh
  eligibility and post-apply conflict behavior; ZK/non-ZK Release builds and Jade tests pass.
- Program deployment now authenticates the funding transaction and recomputes the canonical pinned
  manifest program ID before using fee, nullifier, commitment, or program ID metadata. Pending pool
  conflicts fail before Halo2; eligible deployments still execute the stateful proof/apply verifier
  once and must return the same fee and program ID. The real deployment proof regression and both
  feature-mode builds pass.
- Token issuance now uses a state-aware authenticated precheck because the issuer key and supply cap
  must come from the canonical deployed registry. It verifies the registry entry identity, active
  function schema, issuer signature, issuance binding signature, anchor, sequence, and cumulative cap
  before a conflict can reject early. Eligible issuance still runs the complete stateful proof/apply
  verifier once and must reproduce program ID, sequence, and amount. Fee-only reads are proof-free;
  the real issuance regression and both build modes pass. Bridge fee extraction is now the remaining
  proof-backed read path.
- P2P transaction-body downloads are now capped at 32 active requests per peer and 128 process-wide,
  regardless of the larger descriptor chunk allowed on the wire. Verifier-overloaded transaction IDs
  enter a bounded 30-second cooldown; the table holds at most 1,024 IDs and evicts the soonest-expiring
  entry when full. Alternate peers and reannouncements consult the same cooldown, overload remains a
  non-ban event, and later announcements may retry. Duplicate hashes within one descriptor message
  now cause a controlled protocol disconnect rather than an insertion invariant. Deterministic policy tests and both feature-mode
  builds pass; live parallel proof/RSS/fairness qualification remains open.
- Private daemon statistics expose current/peak Onyx verifier concurrency, permit acquisitions,
  global/per-source overload rejections, active transaction downloads, and current cooldown entries.
  These are the authoritative limiter-engagement inputs for live load reports; absent optional fields
  mean zero.
- `tools/onyx_verifier_load.py` turns distinct prebuilt Onyx transactions into a barrier-synchronized
  local load run, samples process RSS/CPU plus limiter statistics, records response latency and
  classification, checks in-load/post-load RPC health, and atomically emits revision-bound JSON. The
  `585bc4d` process harness passed with one accepted/one busy response, 141 successful daemon samples,
  zero sampling/transport errors, verifier peak one, P2P propagation, height-5 progress, and exact
  two-node supply equality. Its measured RSS remains host-local, not a release threshold.
- Commit `7e46efb` makes bridge admission use proof-free canonical metadata extraction for semantic fee reads, then
  authenticates that metadata by resolving the legacy output and verifying the ownership ring
  signature before confirmed/pending key-image conflict checks. The ownership sighash binds the
  bridge preimage, backend, and proof bytes. Eligible mempool and block paths retain the full stateful
  bridge proof/application and authoritative legacy checks. The real bridge regression, failure-output
  clearing test, both feature-mode builds, both Jade suites, and the complete C++ ZK suite pass. No
  Onyx semantic/read-only fee path now needs to verify a proof.

Validation not yet completed:

- Push and validate standard-program commits `1a82773` and `060b691` on GitHub's Ubuntu runner, then
  retain the uploaded revision-bound report. The current stateful-call pass is local evidence only.

Recommended immediate acceptance criteria:

1. ZK-enabled node and wallet both accept `--net=onyx`.
2. Non-ZK node and wallet reject it before opening databases or networking.
3. Three Onyx qualification nodes agree on UUID, genesis, ports, V7 at height 1, and RandomX metadata.
4. Mainnet, testnet, and stagenet behavior remains byte-for-byte or test-for-test unchanged.
5. Wallet files or portable viewing keys from another network are rejected.
6. No default mainnet peer or seed is contacted.
7. `tests.exe --jade` and the release tests pass.

## 11. Known CI issues identified but not yet applied

Several CI-specific fixes were identified. Treat them as proposed work and inspect current CI before
applying:

- Push workflow run `30917654339` proved the expanded fixed-Onyx qualification job itself passed
  through the independent-wallet transfer. The workflow failed only in its separate Dandelion job.
- Linux Consensus integration runs `30527675836` and `30528317812` both confirmed a wallet-height
  race in `test_dandelion_process.py`: after the recovered wallet's second launch, the test calls
  `create_transaction` before waiting for height 15 and receives "before amethyst upgrade". The
  focused fix is to reuse the existing height-synchronization wait immediately after that launch;
  run `30917654339` reproduced the same failure while its Onyx qualification job passed.
- Sanitizer run `30917653262` failed while compiling `src/main_fuzzer.cpp:75`: the bridge fuzz call
  uses `parameters::ONYX_BRIDGE_CIRCUIT_K` outside namespace `cn`; the focused compile repair is the
  explicit `cn::parameters::` qualification. No sanitizer campaign ran after that compile failure.
- Release-evidence run `30917653273` correctly rejected a stale `onyx-zk` tracked-tree digest after
  the native proof cache changed `vendor/onyx-zk/src/proof.rs`. Recompute and review the exact lock
  digest rather than weakening the verifier.
- Windows fixtures may need `.gitattributes` rules forcing LF for Onyx canonical/golden artifacts to
  avoid checkout newline mutation.

Do not apply either blindly. Reproduce the failure, make the smallest change, and verify that the
test still detects the intended protocol failure rather than merely becoming less strict.

## 12. Validation commands

Adapt generator and paths for the host. Keep ZK and non-ZK build directories separate.

### Release tooling

```powershell
python -m unittest discover -s tests/release -p "test_*.py"
python tools/release/verify_dependencies.py
python tools/release/verify_release_gates.py
```

The final command is expected to fail/report incomplete until external evidence exists. It must fail
for missing gates, not crash or accept placeholders.

### C++ with ZK

```powershell
cmake -S . -B build-onyx -DONYX_ZK=ON
cmake --build build-onyx --config Release --target tests bytecoind walletd minerd
.\build-onyx\Release\tests.exe --jade
.\build-onyx\Release\tests.exe --zk
```

The full `--zk` suite can be long. Do not report it as passed unless it reaches its final success
status. It completed successfully for `dd9755e`; future changes must rerun it rather than inheriting
that result.

### C++ without ZK

```powershell
cmake -S . -B build-nozk -DONYX_ZK=OFF
cmake --build build-nozk --config Release --target tests bytecoind walletd minerd
.\build-nozk\Release\tests.exe --jade
.\build-nozk\Release\bytecoind.exe --net=onyx
```

The last command must refuse to start the qualification network.

### Compiler and SDKs

Consult the README in each directory, then run at minimum:

```powershell
python -m unittest discover -s tests/onyx_compiler -p "test_*.py"
python -m unittest discover -s sdk/onyx/python -p "test_*.py"
```

Run the TypeScript package's locked test command from `sdk/onyx/typescript/`. Run Rust offline:

```powershell
cargo test --manifest-path sdk/onyx/rust/Cargo.toml --offline
```

Use the repository's pinned/offline Rust configuration for proof-backend tests. Do not download or
silently upgrade cryptographic dependencies.

### Fuzzing and sanitizers

Follow `docs/Onyx-Fuzzing.md` exactly:

```text
cmake -S . -B build-fuzz -DSANITIZE=fuzzer,address,undefined -DONYX_ZK=ON
```

Record compiler identity, seed corpus digest, duration, crashes, minimized reproducers, and revision.

## 13. Recommended next implementation sequence

### Priority 0 — Finish the qualification network

Status: **Completed in `5ed59bd`, extended in `d1dca30`, wallet-qualified in `a26303e`,
migration-qualified in `6ee5247`, native-transfer-qualified in `dd9755e`, pinned NFT deployment
qualified in `1a82773`, stateful NFT call qualified in `060b691`, and capped-token lifecycle qualified
in `db044e5`, remaining profiles qualified in `3da16ad`, and rollback/reopen/reconfirmation qualified
in `5101111`.**

### Priority 1 — Qualification topology harness

Status: **The topology, mining, restart/reorganization, malformed-binary, isolation, supply-audit,
report, wallet recovery, real migration, independent-wallet native transfer, every pinned program
lifecycle, and deterministic program rollback/reopen/reconfirmation are implemented and locally
process-qualified through `5101111`.**

Implemented:

- Explicit node identities and topology; no implicit seeds.
- Separate data directories and ports.
- Real daemon and miner processes.
- Real wallet process with protected RPC authentication and password input through standard input.
- Competing RandomX branches, node restart/reconnection, and longer-chain reorganization.
- Truncated V7 rejection and post-rejection liveness.
- Mined-fund recognition plus encrypted wallet/cache backup, password rotation, old-password rejection,
  and alternate-node recovery with exact identity/balance comparison.
- Real legacy-to-Onyx bridge proving, wallet-bound signing, tamper rejection, relay/mining, exact
  legacy/shielded/fee reconciliation, cross-node audit equality, and consumed-output replay rejection.
- Real independent-wallet shielded transfer proving, pending-spend reservation, tamper rejection,
  relay/mining, exact sender/receiver/fee accounting, and confirmed nullifier replay rejection.
- Real pinned NFT program deployment, pending-spend reservation, tamper/replay rejection, registry
  convergence, wallet scanning, and exact deployment-fee/supply accounting.
- Real stateful NFT call with activation, exact-hash propagation, tamper/replay rejection, same-state
  pending conflict rejection, stable-key query equivalence, and exact cross-node state/supply checks.
- Real capped-token deployment, activation, issuer/sequence/cap enforcement, private issuance,
  mixed token/native-fee transfer, pending-conflict/tamper/replay rejection, two-wallet balance
  recovery, and exact three-node registry/commitment/supply equality.
- Real vesting, multisig custody, swap claim/refund, pending stable-key conflict, timeout, and replay
  qualification with exact state/supply equality.
- Durable height-78 SQLite snapshot, first refund at 79, isolated alternative fork to 80, exact
  three-node program/commitment/supply rollback, node reopen, alternate-node wallet recovery, restored
  transaction eligibility, and identical refund reconfirmation at 81.
- Machine-readable logs containing revision, genesis, height, block hash, and supply-audit snapshots.
- No credentials or secret keys in logs.

Remaining:

- Repeat cold/warm and sustained valid-proof campaigns on named hardware. The first local parallel
  HTTP/P2P proof-load run is green, but one run cannot define percentile latency, RSS, or CPU limits.
- Add live invalid-proof floods, exact-duplicate/conflict load, disconnect/shutdown cancellation,
  mixed RPC/P2P ingress, and explicit permit-leak/fairness checks. Extend cheap rejection only through
  authenticated metadata extractors.
- Wider randomized rollback campaigns across earlier deployment, issuance, and transfer boundaries.
- A longer local run and the independently operated 14-day public soak.

### Priority 2 — Migration and incident rehearsal tooling

- Automate pre-migration snapshot and supply checks.
- Exercise controlled reorg and rollback.
- Preserve artifacts and chronological event records.
- Provide an evidence template matching `tools/release/qualification_evidence.py`.
- Test clean-room reproduction.

Exit criterion: a local dry run validates structurally, while the real drill remains externally
performed and signed.

### Priority 3 — Real Tor/I2P integration

- Run real Tor and I2P services, not only a SOCKS emulator.
- Use multiple nodes and proxy-only identities.
- Capture traffic on Linux, Windows, and macOS.
- Prove no local hidden-service lookup and no direct fallback.
- Test referral poisoning, proxy restart, disconnect, and peer-database recovery.

Exit criterion: reproducible tests and packet-capture review with no identity leakage or bypass.

### Priority 4 — Compatibility, fuzz, and hardware qualification

- Historical released-v4 binary matrix against current v4 negotiation.
- Long Dandelion and consensus fuzz campaigns.
- Native RandomX x86-64 and ARM64 throughput/power measurements.
- Hardware-wallet and recovery acceptance with independent operators.

### Priority 5 — Freeze and external release ceremony

Only after repository tasks pass:

1. Select and tag one frozen revision.
2. Generate source archive, SBOM, locks, and checksums.
3. Obtain two independent audits and remediate findings.
4. Run the public 14-day/10,000-block/three-node qualification.
5. Reproduce all platform binaries with two independent builders.
6. Execute the incident drill.
7. Hold governance approval last.
8. Set real co-scheduled activation heights with the required notice window.

## 14. Work that must not be "implemented" by weakening controls

Another AI must not:

- Mark evidence gates passed with fabricated JSON.
- Lower node, builder, audit, duration, block, platform, or governance minimums.
- Re-enable standalone Jade V5/V6 activation.
- Move RandomX away from the Onyx activation boundary.
- Enable Onyx when `ONYX_ZK=OFF`.
- Replace Halo2 verification with the toy O0 verifier.
- Introduce runtime consensus activation overrides.
- Accept unknown/user circuits before review and activation.
- Download floating cryptographic dependencies.
- Remove canonical decoding, bounds, domain separation, network binding, or fail-closed checks to make
  tests pass.
- Claim an interrupted suite passed.
- Include user-owned staged files in unrelated commits.

## 15. Definition of done

The project is not finished merely because O0–O6 code exists. Completion requires all of the
following:

- Every repository-controlled phase requirement is implemented and passes clean-clone CI on Linux,
  macOS, and Windows.
- ZK and non-ZK configurations behave as specified.
- Consensus, wallet, compiler, SDK, network, process, sanitizer, fuzz, and reproducibility suites pass.
- No unresolved critical/high audit finding exists.
- All six external release gates validate from committed, independently attributable evidence.
- Governance approves the exact frozen revision and co-scheduled activation values.
- Operators have rehearsed migration, recovery, rollback, and incident response.

Until then, describe the branch as a security-focused implementation and qualification candidate,
not a production-ready or foolproof cryptocurrency release.
