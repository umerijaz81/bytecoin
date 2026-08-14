# Bytecoin Jade/Onyx: Complete Project Progress and AI Implementation Handoff

- Document date: **2026-08-14**
- Repository: `https://github.com/umerijaz81/bytecoin.git`
- Working branch: `kimiK3/jade-onyx-hardening`
- Committed revision reviewed: `43e6d73` (`Retain alternate Onyx P2P retry sources`)
- Audience: a developer or another AI coding tool continuing this project

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
| **Committed** | The implementation is part of Git revision `43e6d73` or an earlier ancestor on this branch. |
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
- Implementation baseline reviewed by this handoff: `43e6d73`; the documentation-only follow-up may
  be the branch tip. Always use the commands below to determine the current local/remote revision.
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

After committing the asynchronous verifier milestone, the reviewed worktree contains only the two
pre-existing user-owned changes:

```text
 M .gitignore
A  Bytecoin_Onyx_Security_Review.md
```

Ownership and commit rules:

- `.gitignore` is an unrelated user modification. Do not overwrite or include it in another change.
- `Bytecoin_Onyx_Security_Review.md` is already staged user work. Do not edit, unstage, delete, or
  accidentally commit it with implementation work.
- The authenticated bridge code is committed in `7e46efb`, documented in `1587b50`, and described in
  section 13.
- The asynchronous HTTP/P2P verifier boundary, workflow job, and real process harness are committed
  in `585bc4d` and described in section 15.
- Authenticated pool/state conflicts now reject before verifier permit acquisition and worker
  submission in `715d019`; the expanded live harness proves the transfer case and exposes a private
  precheck-conflict counter.
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
| O1 shielded state | Reference-ledger, SQLite-boundary, and proof-bearing full-daemon crash runners implemented locally | Long/multi-platform campaigns, maximum-size corruption and checkpoint testing, independent consensus audit |
| O2 private transfers | Committed, functionally process-qualified, and locally valid-proof load-qualified over HTTP and P2P | Cold/warm and sustained load campaigns, public testnet, independent crypto/wallet audit |
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
- `vendor/onyx-zk/src/state_model_tests.rs` now contains an independent reference ledger and a
  deterministic generated apply/undo/fork/reopen campaign. The reference model uses its own
  containers and incremental Poseidon frontier rather than calling production state-transition
  helpers.
- A fixed prelude guarantees successful bridge, token deployment, NFT deployment, issuance,
  contextual standard-program call, and transfer operations, followed by reopen, duplicate
  rejection, undo, and fork coverage. Seeded exploration continues after the prelude.
- After every accepted operation the runner compares commitment root/count, nullifiers, retained
  anchors, height, bridged/fee/circulating supply, program registry/function/cost data, token
  issuance supply/sequence, and standard-program state. It re-encodes and reopens the production
  snapshot at every step and repeats the comparison.
- Rejected operations must agree between the production and reference ledgers and leave the encoded
  production state byte-for-byte unchanged. A failure prints the seed, failing step, and complete
  shortest generated prefix needed to replay that divergence.
- The ordinary unit campaign runs two fixed seeds for at least 74 steps. Replay or extend it with
  `ONYX_STATE_MODEL_SEED=<hex>` and `ONYX_STATE_MODEL_STEPS=<count>` before invoking the focused Rust
  test.
- `tools/onyx/state_model_campaign.py` runs the model as a locked, offline release test, validates a
  machine-readable result for every seed, writes its JSON atomically after each seed, and preserves
  full digest-bound output on failure. The scheduled qualification workflow retains the report for
  the exact Git revision for 90 days.
- The default retained campaign uses eight published 64-bit seeds and 2,000 requested iterations per
  seed. The 2026-08-12 local Windows run passed all 16,000 iterations with 11,333 recorded operations
  and nonzero bridge, transfer, deployment, issuance, contextual, rejection, undo, fork, and reopen
  coverage for every seed. See `docs/Onyx-State-Model-Qualification.md` for schema and replay details.
- Schema v2 builds the test once, binds the executable digest, and samples the test process itself.
  Weekly limits are 180 wall seconds, 120 CPU seconds, 1,024 MiB peak RSS, and 2 MiB output per seed;
  missing samples or any exceeded ceiling fail closed. A divergence is rerun at `step + 1` and its
  predecessor; exact reproduction plus predecessor absence produces a digest-bound minimized trace.
- The v2 local repeat preserved the 16,000/11,333 coverage totals and observed maxima of 7.61 wall
  seconds, 7.640625 CPU seconds, 5,832,704 peak RSS bytes, and 504 output bytes. An injected failure
  proved minimization from 100 to 38 requested steps and absence at 37.
- Snapshot tests reject every truncated prefix, a supply-field corruption, and anchor/nullifier/
  program-state counts at configured maximum plus one before allocation. These are bounded
  regressions.
- An ignored exact-limit Rust test separately constructs, decodes, and canonical re-encodes valid
  snapshots containing exactly 1,000,000 anchors, nullifiers, or program states. The retained Python
  runner binds resource/output/executable identities and executes weekly. All three local cases
  passed; the largest was a 64,000,053-byte program-state snapshot with 285,687,808 bytes peak RSS
  under the final 20 ms sampling interval.
- A structured snapshot corruption campaign uses four canonical fixture shapes, six targeted decoder
  failures, eight mutation families, four published seeds, 20,000 cases per seed, exact
  reject-or-canonicalize invariants, process resource ceilings, and retained revision-bound reports.
  The local 80,000-case run rejected 65,706 inputs and accepted 14,294 only as byte-stable canonical
  snapshots; its maximum seed time was 19.234 seconds.
- `tests/network/test_onyx_db_crash_process.py` repeatedly terminates the native C++ test process at
  three real SQLite transaction boundaries using the production DB adapter and Onyx state/undo key
  shapes: after the state write, after the complete state/undo pair but before commit, and directly
  after commit. It verifies rollback or survival through both the C++ adapter and an independent
  read-only Python SQLite connection plus `PRAGMA integrity_check`.
- The 2026-08-12 local crash run observed exact child exit codes 85/86/87, rolled back both
  uncommitted cases, recovered the committed pair, and reported SQLite integrity `ok`. Its report
  schema is `bytecoin-onyx-db-crash-v1` and its scope is deliberately
  `local-process-crash-not-release-evidence`.
- Weekly qualification CI builds the native `tests` target, runs the crash harness, and uploads its
  revision-bound JSON report. The ordinary Onyx Rust matrix maps the new model module exactly once;
  local shard validation currently reports 111 tests total and 77 in the core shard.
- `tests/network/test_onyx_db_corruption_process.py` creates disposable committed and hot-journal
  fixtures through the production adapter, then executes eight deterministic main-image mutations
  and seven rollback-journal mutations. Native probes classify exact state, adapter failure, or
  semantic mismatch; an independent Python SQLite reader checks integrity and exact raw rows. Reports
  bind the executable, revision, every source/result image size and digest, and the deliberately
  limited scope `disposable-sqlite-image-local-or-ci-not-power-loss-release-evidence`.
- The 2026-08-12 Windows run passed all 15 cases: five clean adapter failures, seven exact rollback
  recoveries, and three readable state/undo mismatches caught by the exact semantic oracle. The first
  run found that corrupting `kv_table` to `jv_table` in `sqlite_master` made independent SQLite
  inspection reject the schema while the embedded adapter still returned the expected rows through
  the old root page. `DBsqliteKV` now queries `sqlite_master` and requires the exact canonical table
  declaration on every open. The fixed campaign, original crash campaign, and native DB suite pass.
- `tests/network/test_onyx_db_wal_process.py` uses hidden native modes to commit two real WAL frames,
  retain them across abrupt process exits, checkpoint a cloned bundle, and execute eleven WAL
  mutations plus four pre/post-checkpoint main/WAL/shared-memory combinations. Its report records WAL
  geometry and commit boundaries, every source/output size and SHA-256 digest, child time/output
  bounds, executable/revision identity, independent SQLite integrity/journal mode/raw rows, and exact
  native classifications.
- The final Windows WAL run passed all 15 bounded cases in 1.047 seconds: five exact recoveries and
  ten semantic mismatches, with no malformed bundle accepted as the committed state. The fixture used
  two 4,120-byte frames around 4,096-byte pages, with commit boundaries at 4,152 and 8,272 bytes.
  SQLite commonly discarded a corrupt WAL and returned the older main image with integrity `ok`; the
  exact state/undo oracle rejected every such result. Missing shared memory was safely reconstructed
  when the full WAL remained. `delete_db` now removes `.sqlite-journal`, `.sqlite-wal`, and
  `.sqlite-shm` so a recreated database cannot inherit stale sidecars.
- `tests/network/test_onyx_db_full_process.py` sets SQLite's connection-local maximum page count to the
  fixture's current two pages, then attempts a fixed 1 MiB state value either directly or at the undo
  stage after staging the small new state. Native children must return primary code 13 at the named
  stage. Fresh production-adapter and independent SQLite probes require the exact old state, no undo,
  integrity `ok`, and unchanged raw database identity; a committed control must recover the new pair.
- The 2026-08-12 final Windows page-exhaustion run passed both fault cases and the positive control in 0.203
  seconds. Both failed images remained byte-identical at 8,192 bytes. Report schema
  `bytecoin-onyx-db-full-campaign-v1` binds revision/executable identity, the 1 MiB attempt, error code,
  time/output/report limits, raw rows, page counts, and image digests. It is deterministic SQLite
  page-exhaustion evidence, not physical host-disk, quota, journal-write, fsync, or device-failure
  evidence.
- With `ONYX_CRASH_TESTS=ON`, `DBsqlite3.cpp` compiles `onyx-fault-vfs`, a forwarding wrapper around
  the platform default VFS. It preserves the underlying I/O-method ABI version and delegates every
  call except one armed main-journal/main-database/WAL `xWrite` or `xSync`. Hidden native modes report
  target, operation, state/undo/commit stage, exact extended SQLite code, and trigger count. Ordinary
  builds compile out the wrapper, modes, marker, and case strings; the release-absence scan enforces
  that boundary.
- `tests/network/test_onyx_db_ioerr_process.py` v3 runs journal/database/WAL write and sync failures,
  plus first-byte, half-write, and final-byte-short failures on every file class. Each of fifteen fault
  types runs across three independent fresh images, must trigger once with code 778
  (`SQLITE_IOERR_WRITE`) or 1034 (`SQLITE_IOERR_FSYNC`), then recover the exact old raw rows through
  both native and independent SQLite readers. A committed control must advance. The `cef868c`
  Windows run passed 46 cases in 3.734 seconds; its report was 116,581 bytes. Exact observed prefixes
  were journal 1/256/511 of 512 bytes, database 1/2,048/4,095 of 4,096 bytes, and WAL 1/16/31 of 32
  bytes.
- `tests/network/test_onyx_daemon_crash_process.py` now drives six compile-time-gated fault points
  through real `bytecoind` processes: apply after the state/undo writes, apply before commit, apply
  after commit, reorganization after undo, reorganization before commit, and reorganization after
  commit. Exit codes 91 through 96 and matching log markers prove that each named point was reached.
- The apply cases reuse one signed bridge transaction from a committed height-3 baseline. Recovery
  before commit must reproduce the exact baseline tip/audit and contain no Onyx state rows; recovery
  after commit must reproduce the bridge root, count, bridged amount, fee, circulation, state value,
  and one correctly shaped empty prior-snapshot undo entry.
- The reorganization cases use a real deployed/activated NFT program and its first proved state
  transition. A longer branch forked immediately before the call removes that state. Pre-commit
  crashes must reopen the exact stateful height-26 branch and `found=true` program value; the
  post-commit crash must reopen the exact longer height-27 branch, restore the pre-call root/supply,
  return `found=false`, and contain the exact pre-call Onyx database rows.
- Every recovered database is independently opened by Python in read-only mode, checked with
  `PRAGMA integrity_check`, and compared by exact state/undo key, value size, and SHA-256 identity.
  The passing local report is schema `bytecoin-onyx-daemon-crash-v1`, scope
  `local-full-daemon-crash-not-release-evidence`.
- The first live reorganization run found a real SQLite adapter defect: a present zero-length BLOB
  was treated as a missing key because `sqlite3_column_blob` may return null for empty values. The
  first bridge's valid empty prior snapshot therefore could not be loaded during undo. The adapter
  now tracks row presence independently of its data pointer, supplies a safe empty range to callers,
  and has string/byte-array/cursor regressions. The six-point campaign passes with the fix.
- Fault points exist only when configured with `ONYX_CRASH_TESTS=ON`, which requires `ONYX_ZK=ON`
  and emits a non-distributable build warning. Normal binaries compile out the field, option,
  markers, and calls. `tests/security/test_release_crash_hook_absence.py` scans the binary and proves
  the hidden option is rejected as unknown.

### 9.3 Still required

1. Establish immutable-revision Linux/macOS/Windows resource baselines, tighten the portable weekly
   ceilings where supported, add more published seeds/operation counts, and compare roots across
   platforms.
2. Extend the new full-daemon runner beyond its bridge and NFT-state cases: multi-transaction blocks,
   transfers, issuance, deployment undo, several-block undo/redo, repeated crash cycles, real
   filesystem quota exhaustion and combined/arbitrary-cut/directory-sync I/O failures, and real
   in-checkpoint process termination plus OS flush/power-loss simulation. Bounded SQLite page
   exhaustion, repeated independent rollback-journal/database/WAL write/sync faults including two
   half-write positions, rollback-journal/WAL mutation, and
   checkpoint-bundle mixing are covered, but they are not substitutes for those storage boundaries.
3. Add sustained coverage-guided/sanitizer snapshot and database-image fuzzing, arbitrary partial
   writes, and combined boundary-sized state campaigns. The structured in-memory and deterministic
   SQLite mutation campaigns are retained regression evidence, not coverage evidence. Extend
   exact-limit cases through production SQLite reopen and named-host resource qualification.
4. Run the same campaigns on clean Linux, macOS, and Windows builds and archive reports for one
   immutable revision. A local Windows pass is regression evidence only.
5. Submit the state transition, snapshot, persistence, rollback, and reference-model assumptions to
   an independent consensus audit. Resolve every finding before activation.

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

### 15.2 Bounded asynchronous proof boundary (committed in `585bc4d`)

The synchronous daemon-dispatch blocker is fixed without making consensus state multithreaded. The
implementation has an immutable worker phase and an event-loop commit phase:

1. `BlockChainState::begin_onyx_mempool_verification` performs the duplicate check and, since
   `715d019`, every available authenticated pool/state conflict check before acquiring the existing
   global/per-source permit. It then captures the transaction hash, envelope, exact chain tip, next
   height, network ID, and complete Onyx snapshot.
2. `BoundedWorker` owns one background thread and admits at most one occupied job. It has no attacker-
   controlled waiting queue. Worker exceptions are contained, and completions are queued for the
   node event loop.
3. `BlockChainState::verify_onyx_mempool_transaction` runs the complete stateful Halo2 proof/apply
   operation against the captured immutable snapshot for transfers, standard calls, deployments,
   issuance, or bridges. It records the typed authenticated result and next snapshot.
4. HTTP submissions and downloaded P2P transaction bodies share the bounded executor. Busy HTTP
   requests receive retryable `VERIFIER_BUSY`; P2P overload remains local and non-banning.
5. Completion returns to the event loop. `add_transaction` requires the same transaction, envelope,
   tip, next height, and snapshot. A changed state produces a retryable stale/busy result.
6. Cheap authenticated metadata and every mutable pool conflict are checked again on the event loop.
   Only then is the worker-produced next snapshot applied.
7. Mempool admission performs one full proof verification. Block acceptance remains independent and
   always verifies again; a mempool result is never trusted as a block-consensus cache.
8. HTTP disconnect drops response ownership while the bounded job may safely finish. Node destruction
   joins the worker before dependent node/chain state is destroyed.
9. P2P disconnect nulls the pending source pointer. A valid late result may still enter the pool, but
   a disconnected peer cannot be dereferenced or banned by completion.
10. P2P download bookkeeping is released after scheduling, and completion notifies other peers so
    alternate-download and overload-cooldown state remains coherent.

Primary files are `src/Core/Multicore.*`, `src/Core/BlockChainState.*`, `src/Core/Node.*`, and
`src/Core/Node_P2PProtocolBytecoin.cpp`. Deterministic Jade coverage checks one-job admission,
concurrent rejection, event-loop-only completion, exception containment, exact context matching,
and stale tip/height rejection.

### 15.3 Real two-node valid-proof qualification result

`tests/network/test_onyx_verifier_load_process.py` runs two connected ZK daemons, two wallets, and a
miner. It mines legacy funds, confirms a real bridge, creates two distinct valid unsubmitted shielded
transfers spending the same note, submits them concurrently, waits for P2P propagation, mines the
accepted transaction, and compares both nodes' final supply state.

The successful 2026-08-12 local report is
`build/codex-zk/onyx-verifier-load-process-p2p.json`. Generated reports are intentionally not tracked
release evidence. Results were:

| Measurement/check | Result |
|---|---:|
| Submission classifications | one `accepted`, one `verifier_busy` |
| Successful daemon samples during proof | 141 |
| Daemon sampling errors / transport errors | 0 / 0 |
| Peak active verifier count | 1 |
| Peak primary-daemon RSS | 563,384,320 bytes |
| Primary-daemon RSS growth | 266,223,616 bytes |
| HTTP responsiveness during proof | passed |
| P2P asynchronous propagation | passed |
| Primary and relay final height | 5 |
| Final circulating supply / bridged / fees | 741,998 / 742,000 / 2 on both nodes |
| Final commitment root | exact match on both nodes |
| Overall local harness result | passed |

The expanded `715d019` run adds a post-admission sibling-transfer check. The distinct valid sibling
was rejected in 0.016 seconds; verifier acquisitions remained exactly 2 before and after; private
`onyx_verifier_precheck_conflicts` increased from 0 to 1; and the pool stayed at one transaction.
The same run recorded 140 successful daemon samples, peak verifier one, zero sampling/transport
errors, 552,927,232-byte peak RSS, 266,080,256-byte RSS growth, and exact height-5 supply equality.
This proves the asynchronous entry point no longer spends Halo2 work on that authenticated pending
transfer conflict. It remains local evidence and does not establish a release RSS or latency limit.

Commit `59b0721` adds an exact duplicate resubmission to the same real-proof scenario. It completed
below timer resolution with verifier acquisitions unchanged at 2, precheck conflicts unchanged at 1,
and pool count still exactly one. The temporally frozen observation prevents the final report from
mistaking the expected post-mining empty pool for a duplicate-admission failure. The combined run
passed all nine wrapper checks with 143 successful daemon samples, zero sampling/transport errors,
peak verifier one, 552,902,656-byte peak RSS, 266,117,120-byte RSS growth, and exact height-5 supply
equality. These memory measurements remain host-local evidence, not release limits.

Commit `d8abdef` adds a raw-socket abandoned-request phase before the normal barrier load. The client
sends one complete valid transfer, waits until the daemon proves the verifier was acquired and active,
then closes without reading a response. The private `onyx_verifier_abandoned_rpcs` counter advances
0 to 1, acquisitions advance 1 to 2, active verification returns to zero, and both pool count and
transaction lookup remain empty. The subsequent barrier run acquires verifier 3 and passes, proving
the permit and worker capacity were released. All ten wrapper checks, complete C++ ZK and Jade suites,
both feature-mode builds, load units, and ordinary-artifact fault-control absence pass.

The report scope is `local-load-not-release-evidence`. It proves the specific event-loop liveness
failure is fixed on this host; it does not establish cross-platform, cold/warm, sustained-load, or
public-testnet thresholds. The runner now requires at least two successful in-load daemon samples,
zero sampling errors, zero submission transport errors, and peak verifier concurrency at most one.

Commit `933eb94` extends the campaign with graceful daemon shutdown during an active valid-proof
verification. `stop_daemon` is a private JSON-RPC method that is disabled when no explicit private
credential exists and requires both valid Basic authorization and `confirm=true`. The handler first
returns `stopping=true`, then a 100 ms timer cancels the event loop so normal main-stack unwinding
destroys `Node`; member destruction joins `BoundedWorker` before its captured inputs and pending RPC
maps disappear. The process test rejects an unauthenticated confirmed request and an authenticated
unconfirmed request, observes one active acquired verifier, receives the authenticated stop
acknowledgement, and records exit code 0 after 30.703 seconds. A new daemon opens the identical data
folder and originally appeared at height 4. `c39ba96` later proved that observation was peer-assisted,
not durable-state evidence. The exit-zero/worker-join result remains valid, but the original persistence
claim must not be cited. This design waits for the backend call; it does not interrupt Halo2
cooperatively, so operator shutdown latency includes the remaining proof-verification time.

Commit `d96060f` introduces the first authenticated-invalid-proof qualification without adding an
unsafe production wallet facility. `ONYX_INVALID_PROOF_TESTS` requires `ONYX_ZK=ON`, enables the Rust
`qualification-fixtures` feature, emits a non-distribution warning, and uses a build-tree-local Cargo
target so differently featured `onyx_zk` libraries cannot replace each other. Only that build exposes
the wallet RPC field and C ABI. The builder mutates one byte after creating a real Halo2 proof and
before generating spend/binding signatures. The direct Rust invariant verifies all authorization and
then requires Halo2 failure. The enhanced ordinary-artifact scanner proves both fixture strings are
absent from clean ZK and non-ZK `bytecoind` and `walletd` builds.

The live process report records a single 8,403-byte authenticated invalid transaction submitted three
times. Every attempt returns `-101` (`Invalid asynchronous Onyx verification result`) in
0.218/0.297/0.297 seconds; acquisitions advance 2 to 5; verifier active, pool count, and transaction
lookup end at 0/0/false. The subsequent valid barrier advances acquisition to 6, proving permit reuse.
All 12 wrapper checks pass. This is bounded local evidence and must not be represented as a sustained
invalid-proof flood threshold.

Commit `c39ba96` closes both the persistence correction and stale-chain completion gap. Before the
shutdown RPC acknowledges, it calls the chain database commit on the event-loop thread. Failure is
reported and cancellation is not scheduled. The reopened node is deliberately pointed at an
unreachable peer; it opens at exact height 4 with pool 0 and the interrupted transaction unknown,
proving disk persistence rather than resynchronization. Exit is 0 after a 31.484-second join.

The same campaign copies the committed height-4 database, captures a real 464-byte height-5 block via
a local JSON-RPC forwarding proxy, and injects it after a valid proof reports active. Completion sees
the changed tip/snapshot and returns retryable `-104` (`Onyx state changed during verification; retry
later`), acquisitions 0 to 1, active 0, and no pool admission. Resubmission against height 5 acquires
permit 2 and admits one transaction. All 13 wrapper checks pass; no verifier sleep or production test
hook was added.

Commit `47c3485` adds deterministic mixed-ingress qualification on an isolated copy of that durable
height-4 state. A fresh relay accepts one valid sibling over RPC and announces it through real P2P.
While the target reports that P2P proof active, the other sibling reaches target RPC and returns
retryable `-104` in 0.015 seconds. Acquisitions stay 0 to 1, the global-overload counter moves 0 to 1,
and the sibling is not admitted. Once the P2P transaction occupies the one-entry pool, retrying the
sibling returns in 0.032 seconds, leaves acquisitions at 1, advances authenticated conflicts 0 to 1,
and remains unknown. All 15 wrapper checks pass in 431.1 seconds at exact revision `47c3485`, after a
428.7-second working-tree pass. This is one deterministic transfer campaign, not repeated fairness or
a release operating limit.

Commit `a0395f2` covers the reciprocal scheduling direction on a new connected empty height-4 pair.
A relay RPC proof receives a measured 5.078-second head start. An abandoned target RPC proof then
acquires the target verifier before the relay completes and broadcasts the other valid binary through
real P2P. The target records acquisitions 0 to 1, global overload rejections 0 to 1, one bounded retry
cooldown, zero remaining downloads, two connected peers, and no admission or ban. Once the abandoned
RPC releases and the cooldown expires (27.656 seconds remained after cleanup), explicitly submitting
the exact P2P-overloaded binary succeeds in 0.235 seconds. Acquisitions advance 1 to 2, cooldowns and
downloads remain zero, and exactly one target pool entry exists. All 17 checks pass in 507.6 seconds
at exact revision `a0395f2`, after a 506.5-second working-tree pass. Two discarded harness designs also
established that a same-height reconnect is not a valid automatic pool-reannouncement oracle; this
milestone therefore does not claim eventual P2P fairness without an explicit reannouncement.

Commit `18f00d0` implements bounded automatic retry instead of waiting for that external event. One
process-wide event-loop registry stores source peer, bounded descriptor, stem hop, and expiry under the
same 1,024-entry bound as cooldown state. Earliest-expiry eviction, peer-disconnect cleanup, and one
non-resetting one-second polling timer prevent attacker-controlled memory or timer growth and prevent
new arrivals from indefinitely postponing older entries. After cooldown, eligible bodies are requested
again from the live source. Pool/chain ownership transfer, increased fee policy, and stale referenced
blocks terminate retry; only real per-peer/global download-cap pressure stays queued. Consensus proof
verification and all mutable node state remain on their existing authoritative paths.

The final harness exposes and checks `onyx_verifier_pending_retries`. It warms only the relay with the
authenticated-invalid fixture, starts a cold abandoned target RPC proof, and submits the warm valid
relay proof. The real P2P broadcast reaches the busy target in 0.531 seconds. Acquisitions move 0 to 1,
global overload rejections 0 to 1, cooldowns/pending retries 0 to 1, downloads zero, and two peers stay
connected. With no reconnect or second submission, automatic retry completes 29.797 seconds after RPC
cleanup: acquisitions move 1 to 2, cooldowns/pending retries/downloads all become zero, and one pool
entry is admitted. All 17 checks pass in 521.6 seconds at exact revision `18f00d0`; two prior final-tree
runs also passed.

Commit `43e6d73` adds bounded multi-peer failover. A pending hash retains at most four live sources
whose size, fee, and newest-reference descriptor matches the original, while the global pending-hash
bound stays 1,024. Alternate announcements do not reset cooldown. Disconnect removes only the failed
source. The event-loop poll chooses the oldest eligible entry and issues at most one body request per
second; capacity failure rotates the source and delays that entry one second so map order cannot cause
a request burst or monopolize every tick. Private stats/load reports add retained-source and cumulative
retry-request counters.

The deterministic three-node phase warms primary and backup relays, occupies the cold target, records
the primary's P2P overload, and has the backup reannounce the same valid transaction during cooldown.
Sources move 1 to 2; stopping the primary leaves the pending hash and one backup source. Without a
harness retry or reconnect, the target admits through that backup. At exact revision `43e6d73`, the
relay returns in 0.563 seconds, admission completes 29.922 seconds after RPC cleanup, sources drain
1 to 2 to 1 to 0, two requests match two overload rejections, acquisitions move 0 to 2, and final
cooldown/pending/download counts are zero with one pool entry. All 18 checks pass in 554.4 seconds;
the preceding working-tree pass also passes all 18 in 554.1 seconds.

Validation through `43e6d73`: qualification-feature ZK, ordinary ZK, and non-ZK Release
`bytecoind`/`tests` builds and their Jade suites pass; Python compilation and all three load-runner
units pass; and the 18-check exact-revision process campaign passes. Earlier complete C++ `--zk`
evidence remains valid because this milestone changes node scheduling/P2P qualification rather than
circuits or consensus.
The normal non-ZK daemon still excludes the crash/fault controls.

### 15.4 Remaining verifier qualification work

1. Repeat separate cold-start and warm-cache runs on named x86-64 and ARM64 hosts.
2. Exercise deployment/issuance/bridge/program-call authenticated conflicts and invalid proofs, plus
   stale-chain completion under deterministic and live conditions. Pending
   private-transfer conflict, exact duplicate resubmission, HTTP client abandonment, and graceful
   active-proof shutdown, a three-attempt authenticated invalid private-transfer campaign, and
   deterministic stale-tip discard/retry are now live-qualified.
3. Repeat RPC-only, P2P-only, and mixed-ingress campaigns, extend mixed ingress beyond transfers, and
   repeat multi-hash and more-than-two-source fairness while ordinary RPC, wallet scanning, mining,
   and block application remain active. Single-hash primary/backup failover is now live-qualified.
4. Extend authenticated-invalid and valid-proof work into sustained floods while proving
   queue/download/cooldown bounds and no permit leaks.
5. Establish percentile latency, CPU, and RSS thresholds from repeated measurements rather than the
   single local run.
6. Retain hosted CI artifacts for the exact committed revision and complete the independently
   operated 14-day/10,000-block qualification.

### 15.5 Historical valid-proof harness state before `585bc4d`

`tests/network/test_onyx_verifier_load_process.py` now creates the previously missing real inputs. It:

1. starts a minimal local ZK daemon, source wallet, receiver wallet, and miner;
2. mines spendable legacy funds;
3. performs and confirms a real legacy-to-Onyx bridge;
4. creates two distinct valid, unsubmitted shielded transfers that spend the same live note;
5. invokes `tools/onyx_verifier_load.py` with a barrier-synchronized parallel submission;
6. requires one acceptance and one retryable `VERIFIER_BUSY` overload response;
7. if the load gate passes, mines the accepted transaction and checks wallet and supply progress;
8. writes a wrapper report and preserves the raw load report.

The pre-`585bc4d` working-tree workflow added the scheduled/manual `verifier-valid-proof-load` job
that is now committed. It builds the ZK daemon, wallet, and miner and runs this process scenario. The
job must remain a qualification gate:
do not add `--allow-no-overload`, reinterpret a transport failure as success, or weaken its assertions
to make CI green.

Static validation completed on 2026-08-11:

- Python compilation passed for the process harness, load runner, and full qualification harness.
- `python -m unittest tests.network.test_onyx_verifier_load_unit -v` passed all three tests.
- ZK Release `bytecoind`, `walletd`, `minerd`, and `tests` built successfully.
- Non-ZK Release `bytecoind` and `tests` built successfully.
- ZK and non-ZK `tests.exe --jade` passed.

### 15.6 Historical live-load blocker found on 2026-08-11

Before `585bc4d`, this milestone was blocked at daemon dispatch rather than proof correctness or
fixture generation. The following failed runs explain why the asynchronous boundary was required:

- First run, before the working-tree experiment: both concurrent HTTP requests were serialized by the
  daemon event loop. Each call spent about 34.4 seconds and returned `broadcast`; verifier acquisitions
  rose from 1 to 3, rejection counters stayed at zero, and only one transaction entered the pool due
  to their state conflict.
- Second run: one valid transaction was accepted after about 52.0 seconds and the competing HTTP
  connection was forcibly reset before it reached verifier admission. Acquisitions rose from 1 to 2,
  peak active verification stayed at 1, rejection counters stayed at zero, the node recovered after
  load, baseline RSS was about 297 MB, and observed peak RSS was about 571 MB.
- During the expensive proof, repeated `get_statistics` calls timed out. This demonstrates that
  ordinary RPC/control-plane progress is not currently maintained while synchronous proof work owns
  the node event loop.
- The raw failing report is generated at
  `build/codex-zk/onyx-verifier-load-process-raw.json`; it is local diagnostic output, not release
  evidence and is not committed.

The existing `OnyxVerifierAdmission` permit is inside `BlockChainState::add_transaction`. That is too
late to protect responsiveness when `Node::on_send_transaction` and `http::Server` dispatch the
request synchronously on the single event loop. A competing request either waits outside the permit
or reaches its HTTP timeout; therefore the configured one-verifier limit can keep proof concurrency
at one while still failing to provide prompt, deterministic overload responses.

A one-second post-release cooldown was prototyped and passed a deterministic unit check, but the live
run proved it insufficient: it cannot classify a connection that the blocked event loop has not read.
The experiment was removed rather than retaining a delay that did not solve the liveness boundary.

### 15.7 Historical implementation design (completed in `585bc4d`)

The bounded asynchronous implementation now follows this design while preserving single-threaded
state mutation:

1. Parse and size-bound the request on the event loop.
2. Perform cheap transaction decoding, duplicate/pool-capacity checks, and acquire the existing
   global/per-source permit before scheduling expensive work.
3. Copy an immutable verification input: transaction bytes, transaction hash, required Onyx snapshot
   or authenticated state inputs, source identity, and the chain-tip/state generation being checked.
4. Run only CPU-heavy cryptographic verification on a bounded worker executor. Never mutate chain,
   pool, archive, peer, or wallet state from the worker.
5. Post the result back to the event loop. Recheck chain tip/state generation and every mutable pool
   conflict before insertion; retry/reverify or reject if the captured state is stale.
6. Keep the permit alive through the worker job and release it on every success, error, disconnect,
   shutdown, and cancellation path.
7. Return `VERIFIER_BUSY` promptly when no worker/permit is available. Do not queue attacker-selected
   proof jobs in an unbounded container.
8. Make HTTP client disconnects cancel response delivery safely without abandoning cleanup. Decide
   explicitly whether already-running cryptography is allowed to finish or uses cooperative
   cancellation.
9. Add deterministic tests for busy response, stale-state recheck, disconnect, shutdown, exception,
   permit leak, and exactly-once pool insertion.
10. Rerun the real process harness and require RPC sampling plus mining/wallet progress during—not
    merely after—the proof window.

Do not simply move all of `BlockChainState::add_transaction` to another thread. Its maps, database,
archive, chain view, relay machinery, and event-loop assumptions are not established as thread-safe.

After the async boundary passes, run separate cold-start and warm-cache processes; authenticated
non-transfer conflicts; malformed-proof floods; RPC and P2P ingress; mixed ordinary RPC/mining load;
and repeated runs for defensible CPU, latency, and RSS thresholds. The pending transfer conflict is
live-qualified in `715d019`, exact duplicate resubmission in `59b0721`, HTTP client abandonment after
verifier start in `d8abdef`, active-proof worker join in `933eb94`, bounded authenticated invalid-transfer
rejection/permit reuse in `d96060f`, offline shutdown persistence plus stale discard/retry in
`c39ba96`, deterministic transfer P2P/RPC contention plus proof-free retry in `47c3485`, reciprocal
RPC-active/P2P overload in `a0395f2`, bounded automatic live-peer retry/admission in `18f00d0`, and
bounded primary/backup source failover in `43e6d73`. Repeated multi-hash/more-than-two-source and
sustained fairness remain open.

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

### Priority 0 - authenticated bridge milestone (completed)

Section 13 is implemented and locally validated in `7e46efb`, documented in `1587b50`, and both
commits are published on `origin/kimiK3/jade-onyx-hardening`. Retain hosted CI evidence for the exact
revision without including or altering the user-owned staged security review or `.gitignore` change.

Exit condition: all Onyx semantic/read-only fee paths are proof-free or protocol constants, cheap
rejections use only structurally bounded and cryptographically authenticated metadata, and every
accepted transition retains one mandatory full stateful proof.

### Priority 1 - broaden verifier-load qualification (async blocker completed)

Commit `585bc4d` implements bounded asynchronous HTTP/P2P verification and the real two-node harness
passes with continuous daemon sampling, deterministic overload, P2P propagation, mining/wallet
progress, and exact cross-node supply equality. Commit `715d019` moves authenticated conflicts before
worker submission and live-qualifies the pending transfer case; `47c3485` adds deterministic transfer
P2P/RPC contention and proof-free retry; `a0395f2` adds reciprocal P2P overload/non-ban cooldown; and
`18f00d0` adds bounded automatic live-peer retry; and `43e6d73` adds bounded alternate-source failover.
Continue with cold/warm, repeated multi-hash/more-than-two-source fairness,
non-transfer invalid-proof, sustained-load, repeated-host, and hosted-CI campaigns in section 15.4.

Exit condition: repeated named-host results establish defensible percentile latency, CPU, and RSS
thresholds without changing consensus validity or skipping verification.

### Priority 2 - deterministic differential state/crash runner

Status: **bounded model plus proof-bearing full-daemon apply/reorg runner implemented and passing
locally; long and platform-diverse qualification remains**.

Implemented in the current working milestone: independent ledger comparisons after generated
apply/undo/fork/reopen sequences, deterministic seed/step replay, failure-prefix output, snapshot
prefix/corruption rejection, forced-process SQLite state/undo transaction tests, and six real-daemon
apply/reorganization termination points over bridge and stateful NFT transitions. See section 9.2
for exact coverage and section 9.3 for the remaining scope.

Exit condition: long campaigns produce no unexplained root, supply, nullifier, or program-state
divergence, and extended full-daemon block/reorg/checkpoint campaigns recover without corruption. The
current bounded local campaigns alone do not satisfy the long, multi-platform exit condition.

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

1. The committed bridge admission refactor remains intact and live verifier-load qualification passes
   with responsive bounded asynchronous admission.
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
