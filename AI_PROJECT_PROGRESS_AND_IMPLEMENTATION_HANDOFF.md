# Bytecoin Jade/Onyx: Complete Project Progress and AI Implementation Handoff

Document date: **2026-08-11**  
Repository: `https://github.com/umerijaz81/bytecoin.git`  
Working branch: `kimiK3/jade-onyx-hardening`  
Committed revision reviewed: `7e46efb` (`Authenticate Onyx bridge admission`)  
Audience: a developer or another AI coding tool continuing this project

## 1. Purpose of this document

This is the current engineering handoff for the security-focused Bytecoin fork. It records:

- what is actually implemented in source code;
- what has local automated or multi-process test evidence;
- what is only partially implemented in the current working tree;
- what remains repository engineering work;
- what remains external security and release work;
- which files, invariants, and tests a future implementer must use;
- a safe order in which to continue the work.

This document does **not** claim that the cryptocurrency is foolproof, unbreakable, fully trustless,
audited, or ready for mainnet. No non-trivial cryptocurrency can honestly make those claims solely
because code exists or local tests pass. The accurate description is:

> A substantial shielded-protocol and security-hardening implementation that is still undergoing
> engineering qualification and has not completed independent release gates.

## 2. How to interpret status labels

Use the following terms exactly. Do not merge them into a vague word such as "done."

| Label | Meaning |
|---|---|
| **Committed** | The implementation is part of Git revision `7e46efb` or an earlier ancestor on this branch. |
| **Working tree** | The implementation exists only as an uncommitted local diff and may be incomplete or untested. |
| **Unit-qualified locally** | Focused tests passed on one development machine. |
| **Process-qualified locally** | A real local daemon/wallet/miner topology passed a bounded scenario. |
| **Repository-complete** | The planned code and automated tests exist, but independent review and operational evidence may not. |
| **External gate** | Work that must be performed by independent people/operators against a frozen revision. |
| **Planned** | Design prose exists, but required code or evidence is absent. |

The Git commit and executable tests are stronger evidence than prose. If this document, another
document, code, and tests disagree, stop and reconcile the disagreement before editing consensus
behavior.

## 3. Current Git and workspace state

### 3.1 Branch history

- Active branch: `kimiK3/jade-onyx-hardening`.
- Current local `HEAD`: `7e46efb`.
- The local branch is 19 commits ahead of `origin/kimiK3/jade-onyx-hardening` at the time of this
  review.
- `origin/claude/bytecoin-privacy-analysis-n1nsck` is already an ancestor of this branch. Its latest
  shared commit is `29df510`, so its work is integrated and must not be merged a second time.
- `codex/jade-onyx-hardening` and `origin/codex/jade-onyx-hardening` are older ancestors of the current
  branch.

Always re-run these commands because the values above will become stale:

```powershell
git status --short --branch
git branch -a
git log --oneline --decorate -20
git rev-list --left-right --count origin/kimiK3/jade-onyx-hardening...HEAD
git merge-base --is-ancestor origin/claude/bytecoin-privacy-analysis-n1nsck HEAD
```

### 3.2 Local changes that must be preserved

The reviewed worktree contains:

```text
 M .gitignore
A  Bytecoin_Onyx_Security_Review.md
 M JADE_ONYX_PROJECT_HANDOFF.md
 M PROJECT_PROGRESS_AND_IMPLEMENTATION_GUIDE.md
 M docs/Onyx-Qualification-Network.md
?? AI_PROJECT_PROGRESS_AND_IMPLEMENTATION_HANDOFF.md
```

Ownership and commit rules:

- `.gitignore` is an unrelated user modification. Do not overwrite or include it in another change.
- `Bytecoin_Onyx_Security_Review.md` is already staged user work. Do not edit, unstage, delete, or
  accidentally commit it with implementation work.
- The eight bridge code files are committed in `7e46efb` and described in section 13.
- This newly created handoff is documentation work and should be committed with an explicit path.
- Never use `git add -A` in this workspace.
- Prefer `git commit --only <explicit paths>` and inspect `git status --short` before and after every
  commit.
- Do not use `git reset --hard`, broad restore/checkout commands, or destructive cleanup.

## 4. Authoritative documents and their roles

Read the following before changing a security boundary:

1. `ONYX_PROTOCOL_SPEC.md` - consensus objects, state transition, circuits, limits, and phase gates.
2. `ONYX_ARCHITECTURE.md` - original system architecture and O0-O6 roadmap.
3. `ONYX_IMPLEMENTATION_STATUS.md` - older roadmap-to-code reconciliation.
4. `PROJECT_PROGRESS_AND_IMPLEMENTATION_GUIDE.md` - detailed historical progress and test evidence.
5. `JADE_ONYX_PROJECT_HANDOFF.md` - operational history and qualification topology.
6. `SECURITY_PRIVACY_AUDIT.md` - original privacy/security findings and threat motivation.
7. `JADE_UPGRADE.md` - Jade scope, implemented subset, and intentionally unfinished proposals.
8. `ONYX_MIGRATION.md` - one-way bridge construction and supply-reconciliation runbook.
9. `ONYX_PROGRAMS.md` - program registry and standard-profile rules.
10. `docs/Onyx-Compiler-Specification.md` - deterministic language/compiler contract.
11. `docs/Onyx-Compiler-Frontend.md` - compiler frontend and packaging details.
12. `docs/Onyx-Qualification-Network.md` - fixed local qualification network and scenarios.
13. `docs/Onyx-Fuzzing.md` - sanitizer and fuzzing procedure.
14. `docs/Release-Readiness.md` - evidence formats, release ordering, and external gates.

Important version note: early architecture prose calls Onyx "V6." The current production selector
reserves V6 and treats Onyx as V7. Do not revive the early numbering without a complete consensus and
migration review.

## 5. System and activation overview

The branch contains two related upgrade efforts:

- **Jade** hardens the legacy CryptoNote path: minimum ring size, authorization-scheme agility,
  wallet-decoy safety, privacy defaults, and supporting network/PoW changes.
- **Onyx** is the shielded replacement protocol: Halo2/Pasta proofs, encrypted notes, commitments,
  nullifiers, private native/token transfers, a one-way legacy bridge, wallet recovery, constrained
  programs, compiler/SDK tooling, and release qualification machinery.

The intended reachable production transition is:

```text
Legacy V1-V3 -> Amethyst V4 -> Onyx V7
```

Jade V5 and reserved V6 are deliberately not separate production intervals. The source currently
uses unreachable placeholder activation heights, and a compile-time invariant co-schedules:

- `UPGRADE_HEIGHT_V5`;
- `RANDOMX_SWITCH_HEIGHT`;
- `UPGRADE_HEIGHT_RESERVED_V6`;
- `UPGRADE_HEIGHT_ONYX`.

Do not change only one of these heights. Do not add a runtime mainnet override. A real activation
height belongs at the end of the release process, after audits, public qualification, reproducible
builds, incident rehearsal, and governance approval for one exact frozen commit.

## 6. Overall status summary

| Area | Current status | Principal remaining work |
|---|---|---|
| Jade hardening | Committed and locally tested | Independent review, historical compatibility, platform/long-run qualification |
| O0 ZK foundation | Substantially repository-complete | Independent circuit/FFI audit, long valid/malformed fuzzing, benchmarks |
| O1 shielded state | Substantially repository-complete | Differential state model, crash injection, independent consensus audit |
| O2 private transfers | Committed and locally process-qualified | Live load evidence, public testnet, independent crypto/wallet audit |
| O3 wallet/RPC | Committed | Hardware-wallet acceptance, multi-operator recovery tests, external review |
| O4 migration | Committed and locally process-qualified | Public supply evidence, independent review, incident rehearsal |
| O5 programs/compiler/SDKs | Major profiles committed and locally process-qualified | Load/performance campaign, sustained fuzzing, independent compiler/circuit audit |
| O6 network/PoW/release | Major code committed | Real Tor/I2P, historical binaries, hardware measurements, clean platform runs |
| External release gates | Incomplete | Independent provenance, audits, 14-day soak, reproducibility, drill, governance |

## 7. Jade implementation inventory

### 7.1 Implemented

- Consensus-enforced minimum ring size at the Jade boundary.
- Rejection of unknown, reserved, or inactive authorization schemes.
- Explicit authorization-scheme identity bound into the signed transaction prefix.
- Jade-aware transaction construction, wire-size estimation, fee calculation, and sendproof
  identity.
- Remote decoy requests fail with `NOT_ENOUGH_ANONYMITY` instead of silently reducing anonymity.
- Full-width decoy indexes and overflow-safe distance/fee/amount arithmetic.
- Compatibility coverage for legacy V1-V4 transaction encodings.
- RandomX and Onyx activation are co-scheduled; incomplete Jade versions are skipped.

Primary code and tests:

- `src/Core/Currency.cpp`
- `src/Core/TransactionExtra.cpp`
- wallet transaction construction under `src/Core/`
- `src/CryptoNoteConfig.hpp`
- `tests/blockchain/test_jade_consensus.cpp`
- `JADE_UPGRADE.md`

Representative commits:

- `7cc496d` - consensus-enforced minimum ring size.
- `d518ed7` - tightened Jade validation and locked Rust builds.
- `8da8d3a` - fail-closed signature-scheme agility.
- `6fcd39d` and `8fddf80` - anonymity and decoy-index hardening.
- `f332647`, `13f2d54`, `8671803` - safe activation topology.

### 7.2 Intentionally not implemented as standalone Jade features

- The proposed Bulletproofs+ confidential-amount phase.
- The proposed Triptych/Seraphis-style large-membership phase.
- An enabled post-quantum transaction-signature algorithm.

The post-quantum scheme is a reserved identifier, not a production implementation. Enabling it would
require algorithm selection, dependency review, key/address migration, downgrade rules, fee and size
limits, hardware support, vectors, interoperability tests, and independent cryptographic audit.

## 8. O0 - Halo2 proof-system foundation

### 8.1 Implemented

- A vendored Rust proof crate in `vendor/onyx-zk/` based on Halo2 and Pasta curves.
- Exact dependency locks, Cargo source vendoring/checksums, and offline build support.
- Panic-contained and size-bounded C ABI in `vendor/onyx-zk/include/onyx_zk.h` and `src/lib.rs`.
- ABI version checking and failure-atomic output behavior.
- C++ proof abstraction and `Halo2ProofSystem` adapter.
- Fail-closed non-ZK builds: `ONYX_ZK=OFF` cannot validate or join the Onyx network.
- Domain-separated Poseidon/Sinsemilla helpers and known-answer coverage.
- Typed calls for transfers, bridge, deployment, issuance, program calls, state queries, wallet
  scanning, and supply auditing.
- Null-pointer, aliasing, allocation-pair, malformed-envelope, and output-clearing tests.
- Separate build artifacts for ZK, non-ZK, sanitizer, and release configurations.
- Seed corpus and sanitizer/libFuzzer scaffolding.
- Bounded proof-key/parameter caching for the fixed native-transfer shapes.

Primary implementation:

- `vendor/onyx-zk/src/*.rs`
- `vendor/onyx-zk/include/onyx_zk.h`
- `src/Core/zk/IProofSystem.hpp`
- `src/Core/zk/Halo2ProofSystem.hpp`
- `src/Core/zk/Halo2ProofSystem.cpp`
- `tests/zk/test_zk.cpp`
- `tests/fuzz/test_seed_corpus.py`
- `CMakeLists.txt`

### 8.2 Security boundary

The toy proof adapter is for ABI/foundation tests only. It must never replace Halo2 consensus
verification. Structural or authenticated metadata extractors may reject work cheaply, but may never
accept or apply a transaction. Every accepted Onyx state transition must still execute its mandatory
full proof and state verifier.

### 8.3 Still required

1. Independent review of every circuit, transcript, public-input ordering, domain constant, fixed
   parameter, and Rust/C ownership rule.
2. Sustained coverage-guided fuzzing of malformed input and **valid proof-bearing** envelopes.
3. Cold and warm proving/verification benchmarks on named x86-64 and ARM64 machines.
4. Peak RSS, CPU, proof-size, and parallel-request evidence for every accepted circuit shape.
5. Reproducible proof-backend builds on Linux, macOS, and Windows from clean source.
6. A documented review of cache cardinality, initialization races, and memory pressure.

## 9. O1 - canonical shielded state

### 9.1 Implemented

- Canonical versioned Onyx transaction envelopes.
- Network-bound encrypted notes and portable viewing-key handling.
- Commitment tree, canonical root, retained anchor window, and wallet witness history.
- Nullifier set and duplicate/replay rejection.
- Versioned, bounded, canonical state snapshots.
- Atomic block apply, undo, rollback, reorganization, and clean reopen behavior.
- Program registry and program-state storage.
- Token issuance ledger with sequence, cap, activation, and mintability checks.
- Exact supply audit: bridged amount, fees, native circulation, token supply, commitments, programs,
  roots, and height.
- Tip-hash-keyed audit cache that invalidates across same-height reorganizations.
- Failure-atomic structured state-query outputs.

Primary implementation:

- `vendor/onyx-zk/src/state.rs`
- `vendor/onyx-zk/src/transaction.rs`
- `vendor/onyx-zk/src/types.rs`
- `src/Core/BlockChainState.cpp`
- `src/Core/BlockChainState.hpp`
- `src/Core/WalletState.cpp`
- `tests/zk/test_zk.cpp`
- `tests/blockchain/test_jade_consensus.cpp`

### 9.2 Local qualification already present

- Three-node longer-chain reorganization.
- Wallet recovery after a reorg.
- Exact root and supply convergence across nodes.
- Stateful standard-program rollback, database reopen, wallet reopen, and reconfirmation.
- SQLite online-backup behavior was tested after raw directory copies proved capable of reopening one
  block behind the RPC-visible tip.

### 9.3 Still required

1. Build a simple independent reference ledger and differential state runner.
2. Generate randomized bridges, transfers, deployments, issuance, program calls, forks, undo, and
   reopen operations.
3. Compare roots, nullifiers, commitment counts, program state, supply, and error behavior after
   every operation.
4. Inject crashes at actual database transaction/flush boundaries, not only clean shutdowns.
5. Fuzz corrupt snapshots and partial writes at configured maximum sizes.
6. Submit the state transition and rollback design to an independent consensus audit.

## 10. O2 - private native and token transfers

### 10.1 Implemented

- Const-shaped Halo2 native transfer circuits for bounded 1x1, 1x2, 2x1, and 2x2 shapes.
- Membership proofs that do not expose the spent note commitment.
- Note commitments, nullifiers, value commitments, encrypted outputs, fee, expiry, network, and
  anchor binding.
- Per-spend authorization and aggregate binding authorization.
- Native value conservation.
- Private-token transfers with token identity and mixed native-fee handling.
- Wallet note selection, recipient/change creation, pending-spend reservation, and recovery.
- Consensus apply/undo, replay rejection, and mempool conflict handling.
- Negative mutation tests for proof, signed metadata, authorization, commitment, and state fields.
- Separate fixed circuit domains: native transfer `k=16`, bridge `k=13`, general programs `k=20`.
- Bounded per-shape proving/verifying key caches with synchronized first initialization.

### 10.2 Authenticated transfer admission hardening

Committed in `fb95d4b`:

- A proof-free metadata extractor decodes the bounded authorized transfer.
- It verifies all spend authorizations and the aggregate binding signature before exposing network,
  anchor, expiry, fee, nullifiers, or commitments.
- Semantic validation and read-only fee lookup no longer execute Halo2 for a native/private-token
  transfer.
- Mempool admission rejects pending or confirmed nullifier conflicts before Halo2.
- An eligible transaction still executes exactly one full stateful `verify_apply_transfer`.
- Pool bookkeeping occurs only after full proof verification and applied metadata equality checks.

### 10.3 Local process evidence

The fixed three-node qualification harness has exercised:

- two independently created encrypted wallets attached to different nodes;
- a real one-way migration followed by a shielded native transfer;
- tampered transaction rejection;
- pending spend reservation;
- confirmed nullifier replay rejection;
- recipient/sender balance reconstruction;
- fee and total-supply convergence after reorganization/recovery.

The recorded transfer milestone report reached height 5 with `total_bridged = 742000`,
`total_fees = 2`, `circulating_supply = 741998`, and two commitments. This is local evidence, not
public release evidence.

### 10.4 Still required

- Run the committed live verifier-load runner with distinct, valid, unsubmitted proof transactions.
- Measure cold/warm proving and verification for every transfer shape.
- Exercise duplicate, conflicting, malformed, and parallel valid submissions while mining and wallet
  RPC continue making progress.
- Verify cache cardinality cannot be attacker-expanded through any ABI path.
- Publicly qualify transfers across independent operators.
- Obtain independent circuit, wallet, and consensus review.

## 11. O3 - wallet, scanning, recovery, and RPC

### 11.1 Implemented

- Spend, full-view, and incoming-view key separation.
- Encrypted note scanning with retained witness history.
- View-only wallet scanning.
- Network-bound portable keys and wallet identity.
- Multi-note payment selection and change construction.
- Pending native, token, and bridge input reservation.
- Wallet migration, deployment, issuance, and standard-call construction.
- Wallet recovery across reorganization and alternate-node reopen.
- Separate native/token balance accounting.
- Browser-wallet encrypted persistence, authenticated migration, password rotation, and wrong-password
  rejection.
- Wallet RPC credential-file hardening and constant-behavior comparisons.
- Rejection of passwords supplied through insecure command-line arguments.
- Sensitive wallet request and mempool fingerprint logging reductions.
- Hardware-wallet emulator excluded from ordinary/release builds.

Primary areas:

- `src/Core/WalletState.cpp` and related wallet code under `src/Core/`
- `vendor/onyx-zk/src/wallet.rs`
- `vendor/onyx-zk/src/keys.rs`
- browser wallet sources under `src/`
- `tests/wallet_state/`
- `tests/security/`
- `tests/network/test_onyx_qualification_process.py`

### 11.2 Still required

1. Real hardware-wallet signing, display verification, backup, restore, and failure testing.
2. Recovery testing by independent operators from only documented backup material.
3. Long-running wallet scanning across large histories, partitions, and repeated reorgs.
4. External RPC authentication, privacy, and penetration review.
5. Platform-specific encrypted-storage behavior and upgrade/migration acceptance.

## 12. O4 - one-way legacy-to-Onyx migration

### 12.1 Implemented and committed

- A one-way legacy-output bridge into an Onyx note.
- Legacy amount, output stack index, key image, destination commitment, fee, network, and expiry are
  bound into the bridge preimage.
- The bridge backend/proof and ownership signature are bound by the ownership sighash.
- C++ resolves the referenced legacy output and performs key-image and ownership checks during state
  application.
- Legacy bridge inputs are reserved while pending and rejected when already spent.
- Atomic application/undo and exact supply-audit accounting.
- Wallet bridge construction and migration RPC workflow.
- Real local migration across three daemons, followed by recovery and supply reconciliation.

Representative commits:

- `4d91915` - core one-way bridge.
- `2ea836d` - wallet-facing migration.
- `5dd2b5b` - rollback-safe supply auditing.
- `c4e876d` and `b4d5a25` - replay/output failure hardening.
- `e52d17f` - pending bridge reservation.
- `6ee5247` and `787a5b1` - process qualification and documentation.

### 12.2 Committed bridge optimization

At revision `8a1bf3a`, the bridge was the last Onyx family whose semantic/read-only fee path verified a
Halo2 proof. Commit `7e46efb` completes the safe replacement:

- Rust exports `onyx_extract_bridge_metadata`.
- The extractor canonically decodes `AuthorizedBridge`, checks the exact bridge backend, calculates
  the ownership sighash, clears outputs on failure, and returns the legacy amount/index/key image,
  ownership signature, and fee **without** invoking Halo2.
- The C header and C++ `Halo2ProofSystem` wrapper expose the helper.
- Semantic validation and read-only fee lookup use the structural helper.
- Mempool admission resolves the exact legacy output and verifies the ownership ring signature before
  confirmed or pending key-image conflict checks.
- The full stateful bridge verifier remains mandatory for acceptance/application.
- Pool cleanup and undo no longer repeat a proof for already accepted bridge transactions.
- Real-proof equivalence, malformed-output clearing, both build modes, and both Jade suites pass.

See section 13 for the implemented boundary and validation record.

### 12.3 Still required after the current refactor

- Public migration rehearsal against an independently calculated pre-migration supply snapshot.
- Partition, rollback, restart, corrupt-database, and incident-response exercises.
- Independent review of inflation, replay, legacy-output resolution, ownership, and supply accounting.
- Published cross-node supply evidence for one frozen revision.

## 13. Committed milestone: authenticate bridge admission

### 13.1 Files currently modified

```text
vendor/onyx-zk/src/lib.rs
vendor/onyx-zk/include/onyx_zk.h
vendor/onyx-zk/src/bridge_circuit.rs
src/Core/BlockChainState.cpp
src/Core/CryptoNoteTools.cpp
src/Core/zk/Halo2ProofSystem.hpp
src/Core/zk/Halo2ProofSystem.cpp
tests/zk/test_zk.cpp
```

The structural extractor, C++ semantic/fee/mempool/bookkeeping integration, and focused Rust/C++ tests
are committed in `7e46efb` and locally validated.

### 13.2 Required security design

`AuthorizedBridge::ownership_sighash()` binds:

- canonical bridge preimage;
- expected network and expiry;
- bridge fee;
- legacy amount and stack index;
- legacy key image;
- the created Onyx output;
- exact bridge backend identifier;
- bridge proof bytes.

The structural extractor may expose those fields, but C++ must resolve the claimed legacy output and
verify the returned ownership signature against its actual public key **before** using extracted
metadata for a cheap rejection or pool reservation.

### 13.3 Implemented sequence

1. Add Rust tests using an existing real proof-bearing bridge fixture.
2. Compare every extracted field with `onyx_verify_apply_bridge`/`onyx_verify_bridge` output.
3. Add malformed-input tests proving all scalar, fixed-array, signature, and hash outputs are cleared.
4. In `validate_tx_semantic`, replace proof-backed bridge fee extraction with the structural helper.
5. In `get_tx_fee`, replace proof-backed bridge fee extraction with the structural helper.
6. In `BlockChainState::add_transaction`, extract bridge metadata before the expensive proof.
7. Reconstruct the key image, ownership sighash, and signature using the existing canonical C++
   types; do not reinterpret variable-length caller buffers.
8. Check the legacy key image is in the required subgroup.
9. Reject stack-index overflow before conversion to the C++ index type.
10. Resolve the exact legacy output by `(legacy_amount, legacy_stack_index)`.
11. Check the output is unlocked for the next-block consensus context.
12. Verify the one-member ownership ring signature against the resolved legacy output key.
13. Reject a key image already spent in the current confirmed state.
14. Reject a conflict with `m_memory_state_ki_tx` before Halo2.
15. Keep the existing full `verify_apply_bridge` inside authoritative transaction application.
16. Require semantic and authenticated fees to agree, and compare every extracted field with the full
    verifier in the real proof regression.
17. Use proof-free extraction for pool removal/undo metadata only where the transaction was already
   fully accepted; preserve defensive failure behavior.
18. Confirm that no semantic or read-only Onyx fee path invokes Halo2 after this change.

### 13.4 Critical invariant

The full bridge branch in `BlockChainState::redo_transaction` (or its current equivalent) must remain
the consensus authority. It must still:

- execute `verify_apply_bridge`;
- reject a spent legacy key image in the transaction delta;
- validate subgroup membership;
- resolve and unlock the legacy output;
- verify the ownership ring signature;
- store the legacy key image;
- apply the returned Onyx snapshot atomically.

The new extractor is a rejection optimization, not an acceptance oracle.

### 13.5 Validation completed before committing

```powershell
cargo fmt --manifest-path vendor\onyx-zk\Cargo.toml
cargo check --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml
cargo test --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml <focused-bridge-test>
cmake --build build\codex-zk --config Release --target bytecoind tests
cmake --build build\codex-nozk --config Release --target bytecoind tests
.\build\codex-zk\artifacts\bin\Release\tests.exe --jade
.\build\codex-nozk\artifacts\bin\Release\tests.exe --jade
git diff --check
```

Completed evidence:

- `cargo fmt` and `cargo check --release --locked --offline` pass.
- The real proof-bearing bridge equivalence test passes: one selected, one passed.
- The failure-atomic extractor test passes: one selected, one passed.
- ZK and non-ZK Release `bytecoind`/`tests` targets build successfully.
- ZK and non-ZK `tests.exe --jade` both pass.
- The complete ZK C++ suite reaches `test_zk: OK`, including the new metadata adapter regression and
  the full bridge proving, replay-defense, state-application, and supply-accounting stage.
- `git diff --check` passes apart from informational Windows line-ending warnings.

## 14. O5 - program system, compiler, and SDKs

### 14.1 Program registry and deployment implemented

- Fail-closed program registry.
- Consensus-funded and wallet-funded deployment.
- Pinned standard artifacts and canonical program identifiers.
- Funding transfer, deployment descriptor, network, circuit domain, and entrypoint binding.
- Unknown/user-supplied circuit profiles fail closed unless explicitly activated.
- Authenticated proof-free deployment metadata extraction committed in `c08da0e`.
- Pending funding-nullifier and program-ID conflicts are rejected before Halo2.
- Eligible deployment still runs exactly one full stateful deployment verifier.

### 14.2 Token issuance implemented

- Capped private token policies and issuance sequence/cap enforcement.
- Registry-derived issuer policy and issuer signature verification.
- Issuance-specific value-binding authorization.
- Token issuance ledger and supply auditing.
- Registry-authenticated proof-free precheck committed in `46df99a`.
- Pending issuance and confirmed sequence/cap conflicts reject before Halo2.
- Eligible issuance still runs exactly one full stateful issuance proof.

### 14.3 Standard program profiles implemented

The pinned constrained profile set includes locally qualified lifecycle coverage for:

- stateful NFT deployment, mint/call, ownership/state transition, and conflict behavior;
- capped private token deployment, issuance, private transfer, and cap/sequence checks;
- vesting transitions;
- multisignature transitions;
- atomic swap transitions;
- refund, rollback, reopen, mempool restoration, and reconfirmation.

The standard-call path authenticates its contextual value-layer envelope and derives canonical
nullifiers and stable state keys before Halo2. It rejects pending and confirmed conflicts cheaply but
retains the original full stateful proof/application path.

Representative milestones:

- `1a82773` - standard NFT deployment qualification.
- `060b691` - stateful NFT call qualification.
- `db044e5` - private token lifecycle and circuit-domain split.
- `3da16ad` - vesting, multisig, swap, and remaining profiles.
- `5101111` - rollback, reopen, recovery, and reconfirmation.
- `1ad3432` - authenticated standard-call conflict prechecks.

### 14.4 Compiler implemented

- Deterministic compiler frontend.
- Bounded arrays, records, fixed types, and checked integers.
- Content-addressed imports and acyclic call inlining.
- Scalar and composite lowering into deterministic Halo2 gates.
- Guarded execution and flattened composite leaves.
- Versioned Poseidon intrinsics.
- Explicit export/public-input binding.
- Contextual program proof composition.
- Structured compiler fuzz scaffolding.
- Pinned artifact generation and verification tools.

Primary files:

- `tools/onyx/compiler_v1.py`
- `vendor/onyx-zk/src/compiler_backend.rs`
- `vendor/onyx-zk/src/program*.rs`
- `vendor/onyx-zk/src/standard_programs.rs`
- `tests/onyx_compiler/`
- `programs/onyx-standard/`
- `docs/Onyx-Compiler-Specification.md`

### 14.5 SDKs implemented

- Versioned compatibility contract.
- Deterministic standard-program descriptors/builders.
- Python SDK with package/wheel verification.
- TypeScript SDK and web-boundary documentation.
- Dependency-free Rust SDK.
- Network-bound portable key formats.

Primary directories:

- `sdk/onyx/python/`
- `sdk/onyx/typescript/`
- `sdk/onyx/rust/`
- `sdk/onyx/v1/`

### 14.6 Still required

1. Independent review of parsing, type checking, lowering, constraint completeness, canonical
   encoding, artifact pinning, and SDK compatibility.
2. Sustained compiler/parser/IR/descriptor fuzzing with coverage and minimized reproducers.
3. Public multi-operator qualification of every standard profile and rollback path.
4. Benchmark every accepted deployment, issuance, and call profile under cold/warm and parallel load.
5. Add language bindings only with a named maintainer and compatibility-test obligation.
6. Keep arbitrary user circuits disabled until a reviewed activation mechanism exists.

## 15. Proof-admission and denial-of-service hardening

### 15.1 Implemented

- Zero-fee standard-program pool capacity is checked before expensive verification.
- Exact transaction duplicates are rejected before the verifier permit.
- External Onyx mempool admission uses a fail-fast process-wide RAII permit.
- Default maximum is one active external Onyx verifier globally and one per source.
- Contention returns retryable RPC error `-104` (`VERIFIER_BUSY`).
- P2P overload is local and non-banning.
- Block application and internal reorg restoration bypass the non-consensus external limiter.
- Per-peer active transaction-body downloads are capped at 32.
- Process-wide active transaction-body downloads are capped at 128.
- Duplicate hashes in a descriptor message cause controlled protocol rejection rather than an
  invariant crash.
- Overloaded transaction IDs enter a 30-second retry cooldown.
- The cooldown table is capped at 1,024 entries with bounded eviction.
- Private statistics expose active/peak/acquired/rejected verifier counters, active downloads, and
  retry cooldown size.
- `tools/onyx_verifier_load.py` performs barrier-synchronized submissions, process RSS/CPU sampling,
  authenticated statistics polling, response classification, health checks, and atomic JSON output.
- `tests/network/test_onyx_verifier_load_unit.py` covers transaction input handling, missing optional
  counters, response classes, and local process sampling.
- CI contains a verifier-load qualification hook.

Representative commits:

- `1bc8370` - fail-fast mempool verifier bound.
- `4c9db42` - P2P backlog and cooldown bounds.
- `c4c735c` - private load counters.
- `8a1bf3a` - standalone load qualification runner and tests.

### 15.2 What is not yet proven

The runner exists, but a representative live run still needs at least two distinct valid,
unsubmitted, proof-bearing transactions prepared for the same live state. Do not fabricate fixtures,
RSS ceilings, counter evidence, or benchmark numbers.

### 15.3 Next implementation task after bridge admission

1. Extend the qualification harness to create/export multiple valid transactions without submitting
   them prematurely.
2. Keep transactions distinct and state-compatible enough to exercise real verifier contention.
3. Run separate cold-start and warm-cache processes.
4. Test valid parallel submissions, exact duplicates, authenticated conflicts, malformed proof floods,
   and mixed RPC/P2P load.
5. Continue mining and ordinary wallet RPC during load to prove liveness/fairness.
6. Record revision, OS, CPU, RAM, compiler, circuit shape, `k`, request count, response timing, CPU,
   RSS/peak RSS, limiter counters, daemon health, and final chain/root convergence.
7. Establish thresholds only after repeated measurements show stable variance.

## 16. O6 - network privacy, RandomX, scalability, and release tooling

### 16.1 Dandelion++ implemented

- Negotiated relay protocol/version.
- Stem selection and epoch rotation.
- Loop/hop limits.
- Randomized embargo and fluff recovery.
- Disconnect recovery, delivery scoring, and V4 fallback.
- Deterministic policy/adversarial simulations.
- Real multi-process daemon/miner/wallet relay topology test.

Remaining:

- test against historical released V4 binaries;
- long partitions/churn/eclipse/timing-analysis campaigns;
- reproduce and resolve any current hosted wallet-height race without weakening the assertion;
- independent network privacy and DoS review.

### 16.2 SOCKS5, Tor, and I2P implemented

- Fail-closed SOCKS5 outbound transport.
- No local hidden-service DNS resolution.
- Versioned onion/I2P peer identities and persistence.
- Referral validation, bounds, graylisting, and poisoning resistance.
- Linux adversarial SOCKS emulator and DNS tripwire process tests.

Remaining:

- real Tor and I2P daemons, not only an emulator;
- restart/authentication/referral/database-recovery scenarios;
- packet captures on Linux, Windows, and macOS proving no DNS/direct fallback;
- operator documentation for proxy-only and hidden-service nodes.

### 16.3 RandomX implemented

- Vendored RandomX v2.0.1.
- Delayed branch-derived seed epochs.
- Node/miner template negotiation and malformed-template failure.
- Known-answer coverage, full-memory dataset support, and multithreaded mining.
- Branch/reorg/reopen/retained-seed campaigns.
- RISC-V vector qualification work.
- Co-scheduled Onyx activation.

Remaining:

- native x86-64 and ARM64 throughput, memory, startup, and power measurements;
- long epoch-boundary/reorg/partition/restart soak;
- historical binary upgrade-boundary tests;
- independent consensus/integration review.

### 16.4 RPC/parser/operational hardening implemented

- HTTP header/body/connection limits and deadlines.
- Conflicting `Content-Length` rejection and accept-loop recovery.
- JSON depth, member, string, UTF-8, surrogate, duplicate decoded-key, non-finite, and overflow
  protections where applicable.
- Canonical/bounded binary and key-value parsing.
- Generic external errors instead of exception detail leakage.
- Credential and sensitive-log hardening.
- CSPRNG reseed boundaries.
- Privacy-sensitive peer/source attribution disabled by default.
- Release hardware emulator exclusion.

These do not replace TLS termination, deployment rate limiting, monitoring, secret management, or an
external penetration test.

### 16.5 Release tooling implemented

- Source archives, checksums, SPDX SBOM, dependency locks, provenance, and evidence schemas.
- Strict bounded JSON parsing and canonical identity/time/endpoint handling.
- Symlink, traversal, alias, non-regular, and untracked evidence rejection.
- Replay/count-inflation prevention.
- Revision/freeze/activation/compiler/profile/artifact digest binding.
- Release-gate ordering and governance quorum verification.
- Workflows for consensus, ZK, qualification, network privacy, RandomX, fuzzing, evidence, and
  reproducibility.

Primary directories:

- `tools/release/`
- `tests/release/`
- `release/`
- `.github/workflows/`
- `docs/Release-Readiness.md`

Never make a release verifier accept placeholder or self-fabricated evidence merely to turn CI green.

## 17. Fixed local Onyx qualification network

Implemented starting in `5ed59bd`:

- Separate network UUID, genesis, ports, data directory, and wallet domain.
- Height-1 direct V4-to-Onyx/RandomX transition.
- One-second low-difficulty local blocks.
- No compiled seed nodes.
- Inert checkpoint keys with fail-closed checkpoint admission.
- Mandatory ZK-enabled daemon.
- Three isolated nodes, miner, encrypted wallets, competing branches, reorg, malformed V7 rejection,
  migration, transfer, programs, recovery, rollback, reopen, and supply convergence.
- Machine-readable reports explicitly labeled local/non-release evidence.

The most comprehensive recorded program rollback run finished at height 81 on block
`135019cdf8c964f11fc4c666e082f4ad10ad265a53eca4c3682d9795eb9fc23a`, with all nodes on commitment
root `3950785d3dfe4dc5494960c05312b81e45f1d006c71e5af008e00d8591d9f136`.

This accelerated local network is excellent regression evidence. It is not a substitute for public
multi-operator operation, realistic proof load, real network latency, or the required 14-day soak.

## 18. Validation matrix for future work

Use separate build directories. A focused test is acceptable while iterating, but the relevant full
matrix must pass before a milestone is called complete.

### 18.1 Integrity

```powershell
git status --short --branch
git diff --check
python tools\release\verify_dependencies.py
```

### 18.2 ZK-enabled C++

```powershell
cmake -S . -B build\codex-zk -DONYX_ZK=ON
cmake --build build\codex-zk --config Release --target tests bytecoind walletd minerd
.\build\codex-zk\artifacts\bin\tests.exe --jade
.\build\codex-zk\artifacts\bin\tests.exe --zk
```

### 18.3 Non-ZK C++

```powershell
cmake -S . -B build\codex-nozk -DONYX_ZK=OFF
cmake --build build\codex-nozk --config Release --target tests bytecoind walletd minerd
.\build\codex-nozk\artifacts\bin\tests.exe --jade
.\build\codex-nozk\artifacts\bin\bytecoind.exe --net=onyx
```

The final command must fail closed before joining/opening an Onyx network database.

### 18.4 Rust proof backend

```powershell
cargo check --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml
cargo test --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml
```

### 18.5 Compiler and SDKs

```powershell
python -m unittest discover -s tests\onyx_compiler -p "test_*.py"
python -m unittest discover -s sdk\onyx\python -p "test_*.py"
node sdk\onyx\typescript\test.mjs
cargo test --locked --offline --manifest-path sdk\onyx\rust\Cargo.toml
```

### 18.6 Network/load/release tooling

```powershell
python -m unittest tests.network.test_onyx_verifier_load_unit -v
python -m unittest discover -s tests\release -p "test_*.py"
python tools\release\verify_dependencies.py
python tools\release\verify_release_gates.py
```

Missing external release evidence should be rejected clearly. A parser crash or acceptance of fake
evidence is not an expected pass.

### 18.7 Three-node qualification

```powershell
python tests\network\test_onyx_qualification_process.py `
  --bytecoind build\codex-zk\artifacts\bin\bytecoind.exe `
  --minerd build\codex-zk\artifacts\bin\minerd.exe `
  --walletd build\codex-zk\artifacts\bin\walletd.exe `
  --revision working-tree `
  --report build\codex-zk\onyx-qualification.json
```

This is a long test. Run it only for a milestone that changes its covered consensus/wallet/process
behavior, and preserve its report and exact exit result.

## 19. Prioritized remaining implementation roadmap

### Priority 0 - publish the authenticated bridge milestone

Section 13 is implemented, locally validated, and committed as `7e46efb`. Publish the branch without
including or altering the user-owned staged security review or `.gitignore` change, then retain hosted
CI evidence for the exact revision.

Exit condition: all Onyx semantic/read-only fee paths are proof-free or protocol constants, cheap
rejections use only structurally bounded and cryptographically authenticated metadata, and every
accepted transition retains one mandatory full stateful proof.

### Priority 1 - execute real verifier-load qualification

Create valid fixture transactions safely, run cold/warm concurrent workloads, sample RSS/CPU and
limiter counters, prove ordinary daemon/wallet/mining progress, and save a revision-bound report.

Exit condition: repeated results establish defensible resource thresholds without changing consensus
validity or skipping verification.

### Priority 2 - deterministic differential state/crash runner

Implement a small independent ledger and compare it after generated apply/undo/fork/reopen sequences.
Add crash injection at database boundaries and save minimized failing seeds.

Exit condition: long campaigns produce no unexplained root, supply, nullifier, or program-state
divergence.

### Priority 3 - compiler and valid-envelope fuzz campaigns

Run parser/type/IR/backend/descriptor fuzzing and proof-bearing envelope/state fuzzing for sustained
periods. Record coverage and minimize every failure.

Exit condition: revision-bound campaign reports and no unresolved memory-safety, canonicalization, or
constraint-completeness failures.

### Priority 4 - real Tor/I2P and historical compatibility

Test real proxy daemons, restarts, authentication failures, referrals, packet captures, and released
V4 nodes across supported platforms.

Exit condition: no direct/DNS fallback, no identity corruption, and documented compatibility behavior.

### Priority 5 - hardware and clean-platform qualification

Measure RandomX/proofs on x86-64 and ARM64, exercise hardware wallets, and run clean Linux, macOS, and
Windows build/test/reproducibility matrices.

### Priority 6 - freeze and external release gates

Only after repository engineering is complete, freeze one commit and perform the independent gates in
section 20. Any code change after freeze creates a new candidate and invalidates evidence that no
longer binds to the new revision.

## 20. External release gates that remain incomplete

These cannot be completed by asking an AI to generate JSON files.

### 20.1 Independent source provenance

- Two independent builders with distinct digest-bound environments.
- Exact frozen revision and dependency lock.
- Byte-identical archive and SPDX SBOM hashes.
- Named tools and typed attestations.

### 20.2 Independent audits

- At least two distinct audit organizations.
- Coverage of ZK cryptography, consensus/state, wallets/privacy, networking/DoS, migration/supply,
  compiler, and reproducibility.
- Verified remediation and no unresolved critical/high issue.

### 20.3 Public qualification soak

- At least 14 elapsed days.
- At least three independently operated nodes.
- At least 10,000 observed blocks.
- One exact revision/network/genesis.
- Reorg, malformed input, valid-proof DoS, migration, recovery, and supply scenarios.
- Final block/root/supply convergence and zero unexplained consensus divergence.

### 20.4 Reproducible binaries

For Linux x86-64, macOS ARM64, and Windows x86-64:

- two independent builders per platform;
- reproducible `bytecoind`, `walletd`, and `minerd` plus symbols/SBOMs;
- compiler, SDK, linker, environment, revision, and dependency-lock binding.

### 20.5 Incident-response drill

- At least two participants and an independent observer.
- Consensus-stall, reorg, and proof-DoS scenarios.
- Preserved chronology, decisions, communications, artifacts, recovery, supply reconciliation, and
  clean-room reproduction.

### 20.6 Governance approval

- Must occur last.
- Must approve the exact frozen revision, compiler/profile digests, and four co-scheduled heights.
- Must prove electorate, threshold, distinct approvals, quorum, objections, reference chain point, and
  required activation notice.

## 21. Non-negotiable rules for another AI tool

An AI continuing this repository must not:

- fabricate, backdate, or self-sign release evidence;
- claim local tests are an audit or public testnet result;
- lower auditor, builder, node, platform, duration, block, or governance thresholds;
- report an interrupted or timed-out test as passed;
- enable a separate incomplete Jade V5/V6 production interval;
- separate RandomX and Onyx activation;
- allow `ONYX_ZK=OFF` to accept Onyx consensus;
- replace Halo2 acceptance with a toy verifier or metadata extractor;
- trust unauthenticated metadata for mempool rejection/bookkeeping;
- remove proof, state, signature, network, expiry, anchor, supply, canonicalization, or domain checks;
- accept arbitrary/user-generated circuits without a reviewed activation policy;
- introduce floating cryptographic dependencies;
- log keys, seeds, passwords, credentials, raw wallet files, or sensitive requests;
- mix `.gitignore` or `Bytecoin_Onyx_Security_Review.md` into unrelated commits;
- make broad refactors while changing a cryptographic/consensus invariant;
- describe the system as foolproof, unbreakable, fully audited, or production-ready.

## 22. Recommended workflow for another AI tool

For each task:

1. Read this file and the task-specific authoritative documents.
2. Run `git status --short --branch` and identify user-owned changes.
3. Inspect the exact existing code path and its tests before proposing edits.
4. Write down the acceptance/rejection boundary and consensus invariants.
5. Select one bounded milestone with explicit files and non-goals.
6. Add negative tests before or with the implementation.
7. Use cheap prechecks only for rejection; retain the full authoritative verifier.
8. Run focused tests, then the proportional build/test matrix.
9. Record exact commands, exit codes, timeouts, and untested areas.
10. Recheck the diff for accidental scope and secret leakage.
11. Commit only explicit paths.
12. Update this handoff when status changes.

Suggested prompt template:

```text
Repository: Bytecoin fork on branch kimiK3/jade-onyx-hardening.
Read AI_PROJECT_PROGRESS_AND_IMPLEMENTATION_HANDOFF.md and the authoritative documents it names.

Task: <one bounded milestone>
Files initially in scope: <explicit paths>
Security invariants: <specific acceptance, authentication, state, supply, and compatibility rules>
Required tests: <exact commands>
Non-goals: <external gates and unrelated refactors>

Before editing, report git status and preserve the user's staged
Bytecoin_Onyx_Security_Review.md and unrelated .gitignore modification. Do not use git add -A.
Do not weaken full consensus verification or fabricate evidence. Report committed, working-tree,
tested, timed-out, and untested work separately. Stop if code/tests/specification disagree.
```

## 23. Definition of project completion

The complete project may be called release-ready only when one frozen revision satisfies all of the
following:

1. The bridge admission refactor and live verifier-load qualification are complete.
2. ZK and non-ZK matrices pass from clean builds on all supported platforms.
3. Proof, state, wallet, program, compiler, SDK, network, migration, recovery, fuzz, sanitizer, and
   release-tool suites pass without unexplained interruption.
4. Valid-proof CPU/RSS/concurrency limits are measured and enforced without weakening verification.
5. Differential state/crash campaigns find no unresolved divergence or corruption.
6. Real Tor/I2P, historical compatibility, RandomX hardware, and hardware-wallet qualification pass.
7. Two independent audits cover all required security domains with no unresolved critical/high issue.
8. A public three-operator, 14-day, 10,000-block qualification converges exactly.
9. Required platform binaries reproduce through independent builders.
10. The independently observed incident drill and clean-room reproduction pass.
11. Governance approves the exact revision and co-scheduled heights after all prerequisites.

Until every item is true, continue to label the repository as under active implementation and
qualification.

## 24. Milestone commit index

This is a navigation index, not a substitute for `git log master..HEAD`.

| Area | Important commits |
|---|---|
| Initial audit/Jade | `b2a4f53`, `7cc496d`, `de55b2f`, `d518ed7` |
| O0 proof foundation | `0c84c36`, `29df510`, `f313435` |
| Shielded state/transfers | `833c02c` through `48175cf` |
| Bridge/wallet | `4d91915` through `5dd2b5b` |
| Programs/tokens | `b8cf7ea` through `d1d9ce6` |
| SDKs/compiler | `0d5c302`, `55338aa`, `b3797ee`, `da0b586` through `7a00906`, `3ecaa34` |
| Network/PoW | `9daef2c`, `a78ad99`, `4ee9132` and later qualification commits |
| Release hardening | `8de34ca` and the subsequent evidence/provenance/reproducibility commits |
| Fixed Onyx network | `5ed59bd`, `d1dca30`, `a26303e`, `6ee5247` |
| Transfer/program qualification | `dd9755e`, `1a82773`, `060b691`, `db044e5`, `3da16ad`, `5101111` |
| Authenticated prechecks | `1ad3432`, `fb95d4b`, `c08da0e`, `46df99a` |
| Verifier load controls | `1bc8370`, `4c9db42`, `c4c735c`, `8a1bf3a` |

For the complete chronological implementation record, use:

```powershell
git log --reverse --format="%h`t%s" master..HEAD
```
