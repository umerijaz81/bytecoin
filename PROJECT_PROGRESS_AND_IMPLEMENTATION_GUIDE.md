# Bytecoin Jade/Onyx Project Progress and Implementation Guide

Last reconciled: **2026-08-11**
Repository: `https://github.com/umerijaz81/bytecoin.git`  
Working branch: `kimiK3/jade-onyx-hardening`  
Implementation revision documented: `7e46efb` (`Authenticate Onyx bridge admission`)
Purpose: detailed engineering handoff for a developer or another AI coding tool

## 1. Executive summary

This repository is a security-focused fork of Bytecoin. It contains two related upgrade efforts:

- **Jade (V5)** hardens the legacy CryptoNote transaction path, closes the minimum-ring-size and
  remote-decoy downgrade issues, adds signature-scheme agility, and introduces networking and PoW
  improvements. Jade's originally planned confidential-amount and large-membership systems were not
  completed.
- **Onyx (V7 in the current code)** is the replacement shielded protocol. It uses a vendored
  Halo2/Pasta proof backend, encrypted notes, nullifiers, a commitment tree, a one-way legacy bridge,
  wallet scanning and recovery, private transfers, a constrained program system, SDKs, and release
  qualification tooling.

The production selector intentionally jumps from Amethyst V4 directly to Onyx V7. Jade V5 and the
reserved V6 are not independently reachable because exposing incomplete Jade privacy work as a
production phase would be unsafe. The RandomX transition is co-scheduled with Onyx.

The repository is **not production-ready**. Most planned repository code exists, but important
process qualification and all external release gates remain. In particular, no independent
cryptographic/consensus audit, 14-day public soak, independent reproducible builds, realistic incident
drill, or final governance approval is recorded. “Foolproof” security is not a realistic or verifiable
property for cryptocurrency software.

Current overall status:

| Area | Status | Meaning |
|---|---|---|
| O0 proof foundation | Implemented in repository | Needs independent crypto/FFI review, benchmarks, and sustained fuzzing |
| O1 canonical shielded state | Implemented in repository | Needs independent consensus audit and long differential/crash campaigns |
| O2 private transfers | Implemented and process-qualified locally | Real two-wallet transfer is committed; hosted CI and independent/public qualification remain |
| O3 wallet and RPC | Implemented in repository | Needs real hardware-wallet and multi-operator acceptance |
| O4 legacy migration | Implemented and committed | Local three-node migration passes; public supply evidence and incident drill remain |
| O5 programs/compiler/SDKs | Substantially implemented; NFT, capped-token, vesting, multisig, swap, and refund rollback/reopen lifecycles are committed and locally process-qualified | Implement performance/DoS limits, hosted CI, and public operation |
| O6 network/PoW/release | Major components implemented | Real Tor/I2P, long soaks, platform measurements, audits, and ceremony remain |
| External release gates | Not complete | Must be independently performed; must never be fabricated in repository JSON |

## 2. Status vocabulary

Use these labels precisely in issues, commits, prompts, and future documentation:

- **Committed**: present at or before Git revision `7e46efb` on this branch.
- **Working-tree implementation**: code exists locally but is not part of `HEAD`, has not received a
  branch commit, and may not have run in hosted CI.
- **Locally qualified**: a bounded test passed on one machine. This is useful regression evidence but
  is not independent release evidence.
- **Repository-complete**: required code and automated tests are present. This does not mean secure,
  audited, performant, or production-ready.
- **Release-complete**: every repository test and every independently attributable external gate has
  passed for one frozen revision.
- **Planned**: documentation describes the work but an implementation or required evidence is absent.

Never convert “implemented” into “secure” without evidence. Never convert “local test passed” into
“public qualification passed.”

## 3. Workspace and Git state that must be preserved

At reconciliation, the worktree contains both user-owned changes and active implementation work.
Always obtain a fresh `git status --short --branch`; the following is the ownership map, not a promise
that every listed file is still modified:

```text
 M .gitignore
A  Bytecoin_Onyx_Security_Review.md
 M JADE_ONYX_PROJECT_HANDOFF.md
 M PROJECT_PROGRESS_AND_IMPLEMENTATION_GUIDE.md
 M docs/Onyx-Qualification-Network.md
```

Important ownership rules:

- `Bytecoin_Onyx_Security_Review.md` is already staged and belongs to the user. Do not edit, unstage,
  delete, overwrite, or include it in an unrelated commit.
- `.gitignore` is an unrelated local modification. Preserve it unless the user explicitly assigns it.
- Commit implementation files using an explicit path list or `git commit --only <paths...>`.
- Do not run `git add -A`, `git reset --hard`, broad checkout/restore commands, or destructive cleanup.
- Recheck `git status --short` before and after every commit.

This guide is tracked documentation and should normally be committed separately from cryptographic or
consensus changes so the code commit remains independently reviewable.

## 4. Authoritative documentation and precedence

Read these before modifying consensus or cryptographic code:

1. `ONYX_PROTOCOL_SPEC.md` — protocol objects, state transitions, circuits, limits, and phase gates.
2. `ONYX_ARCHITECTURE.md` — component boundaries and original phased design.
3. `ONYX_IMPLEMENTATION_STATUS.md` — reconciliation of roadmap versus implemented code.
4. `JADE_ONYX_PROJECT_HANDOFF.md` — earlier operational handoff and historical validation.
5. `SECURITY_PRIVACY_AUDIT.md` — original findings, threat rationale, and mitigation status.
6. `JADE_UPGRADE.md` — Jade design, implemented subset, and intentionally incomplete work.
7. `ONYX_MIGRATION.md` — legacy bridge signing, supply accounting, and operator runbook.
8. `ONYX_PROGRAMS.md` — program registry and standard-program execution rules.
9. `docs/Onyx-Compiler-Specification.md` — frozen compiler/language profile.
10. `docs/Onyx-Compiler-Frontend.md` — parser, package, and frontend details.
11. `docs/Onyx-Qualification-Network.md` — fixed `--net=onyx` behavior and local harness.
12. `docs/Release-Readiness.md` — release artifacts, evidence schemas, and external gates.
13. `docs/Onyx-Fuzzing.md` — sanitizer and fuzz campaign instructions.

Consensus code and tests are the executable source of truth. If code, tests, and prose disagree, stop
and reconcile the conflict. Do not silently select the most permissive behavior.

## 5. Upgrade and activation model

The production configuration in `src/CryptoNoteConfig.hpp` uses unreachable placeholder values:

```cpp
UPGRADE_HEIGHT_V5          = 10000000;
RANDOMX_SWITCH_HEIGHT      = 10000000;
UPGRADE_HEIGHT_RESERVED_V6 = 10000000;
UPGRADE_HEIGHT_ONYX        = 10000000;
```

A compile-time assertion requires all four heights to remain equal. Release tooling independently
parses and verifies the same relationship. The reachable path is:

```text
Legacy V1–V3 -> Amethyst V4 -> Onyx V7
```

Rules for future work:

- Do not activate Jade V5 or reserved V6 as separate production intervals.
- Do not change a single activation height in isolation.
- Do not move RandomX away from the Onyx boundary.
- Do not add a runtime flag that overrides production consensus heights.
- Real heights may be selected only after the frozen-revision release gates pass and governance
  approves the exact values.

Relevant commits include `f332647` (skip incomplete Jade versions), `13f2d54` (align RandomX), and
`8671803` (compile-time co-scheduling assertion).

## 6. Implemented foundation and security hardening

### 6.1 Jade consensus and wallet hardening

Implemented:

- Consensus-enforced minimum ring size at the Jade boundary.
- Remote-wallet anonymity requests fail with `NOT_ENOUGH_ANONYMITY` when the remote node cannot
  supply enough decoys; the wallet does not silently construct a smaller ring.
- Full-width decoy index arithmetic and overflow-safe distance calculations.
- Explicit transaction authorization-scheme identifier bound into the signed prefix.
- Rejection of unknown, reserved, or inactive authorization schemes.
- Jade-aware transaction construction, size estimation, fee calculation, and sendproof identity.
- Overflow-safe amount-plus-fee and amount-rounding helpers.
- Compatibility checks preserving V1–V4 and Onyx encodings.

Primary files:

- `src/Core/Currency.cpp`
- `src/Core/TransactionExtra.cpp` and transaction serialization paths
- wallet construction and decoy selection under `src/Core/`
- `tests/blockchain/test_jade_consensus.cpp`
- `JADE_UPGRADE.md`

Intentionally not implemented:

- Standalone Jade confidential amounts (the earlier Bulletproofs+ concept).
- Standalone Jade large-membership proofs (the earlier Triptych/Seraphis concept).
- A production hybrid post-quantum signature algorithm.

The post-quantum scheme identifier is only a reserved registry value. Enabling it requires algorithm
selection, dependency review, key/address migration, downgrade rules, vectors, size/fee limits,
hardware support, and independent audit.

### 6.2 Cross-cutting RPC, parser, and operational hardening

Implemented:

- HTTP header/body/connection bounds and header/body deadlines.
- Conflicting `Content-Length` rejection and accept-loop recovery.
- JSON depth limits, strict UTF-8/surrogate handling, and duplicate decoded-key rejection, including
  escape-equivalent property names.
- Canonical/bounded binary and key-value decoding tests.
- Generic external errors instead of internal exception details.
- Constant-behavior credential comparison and protected credential-file loading.
- Rejection of wallet passwords supplied through insecure process arguments.
- Hardware-wallet emulator excluded from normal/release binaries and guarded behind an explicit
  non-release build option.
- Peer-address logging and archive source-IP attribution disabled by default.
- Zero-fee standard-program mempool cap checked before expensive proof verification.
- Browser-wallet encrypted persistence, authenticated migration, password rotation, and wrong-password
  rejection.

These controls reduce known attack surfaces; they do not replace TLS termination, external rate
limiting, monitoring, key-management policy, or independent penetration testing.

## 7. O0 — proof-system foundation

Status: **repository implementation substantially complete**.

Implemented:

- Vendored Rust crate at `vendor/onyx-zk/` using Halo2/Pasta dependencies.
- Exact dependency pins, committed Cargo lock, offline source configuration, and checksum validation.
- Panic-contained, bounded C ABI with explicit ABI versioning.
- C++ `cn::zk::IProofSystem` abstraction and active `Halo2ProofSystem` adapter.
- Fail-closed non-ZK behavior: a binary built with `ONYX_ZK=OFF` cannot validate Onyx consensus and
  cannot join `--net=onyx`.
- Deterministic Poseidon/Sinsemilla helpers and known-answer tests.
- Toy prover retained only for foundation/ABI testing; it is not a production consensus verifier.
- Typed verification/extraction APIs for transfers, bridge, deployment, issuance, programs, state,
  wallet scan, and supply audit.
- Output-atomic FFI behavior: failed calls clear fixed outputs, buffers, counts, and partially decoded
  structures rather than leaking stale caller data.
- Null-pointer, aliasing, allocation-pair, batch-shape, and malformed-envelope tests.
- CMake integration that recursively tracks first-party Rust sources and isolates ZK, non-ZK,
  sanitizer, and release artifacts.
- Sanitizer/libFuzzer scaffolding and deterministic seed corpora.

Primary implementation:

- `vendor/onyx-zk/src/`
- `vendor/onyx-zk/include/onyx_zk.h`
- `src/Core/zk/IProofSystem.hpp`
- `src/Core/zk/Halo2ProofSystem.hpp`
- `src/Core/zk/Halo2ProofSystem.cpp`
- `tests/zk/test_zk.cpp`
- `CMakeLists.txt`

Still required:

1. Independent review of the Halo2 circuits, transcript use, domain separation, dependency pins, and
   C ABI ownership rules.
2. Sustained coverage-guided fuzz campaigns over both malformed and valid proof envelopes.
3. Frozen, published proving/verification benchmarks on representative x86-64 and ARM64 release
   hardware.
4. Reproducible proof-backend builds on Linux, macOS, and Windows.
5. Valid-proof CPU/memory denial-of-service qualification, including cold-start and parallel requests.

Acceptance criteria for the remaining repository work:

- Full Rust tests and C++ `tests --zk` finish successfully without manual interruption.
- No unbounded allocation, panic escape, stale output, or verifier/prover parameter mismatch is found.
- Benchmark artifacts identify revision, CPU, memory, OS, compiler, circuit shape, `k`, wall time, CPU
  time, peak RSS, and proof size.
- Fuzz runs record revision, seed corpus digest, duration, coverage, crashes, and minimized reproducers.

## 8. O1 — canonical Onyx shielded state

Status: **repository implementation substantially complete**.

Implemented:

- Canonical, versioned Onyx transaction envelopes.
- Encrypted notes bound to network and protocol domains.
- Commitment tree and canonical commitment root.
- Retained anchor window and historical wallet witnesses.
- Nullifier set and duplicate/replay rejection.
- Versioned state snapshots with bounded/canonical decoding.
- Atomic block application and rollback/undo.
- Reorganization and persistence coverage.
- Token issuance ledger with sorted unique entries, positive sequences, supply caps, program activation,
  and mintability checks.
- Supply audit with exact bridged amount, fees, circulating supply, commitments, programs, root, and
  height.
- Tip-hash-keyed supply-audit cache that recomputes after same-height reorganization.
- Failure-atomic state-query outputs.

Primary implementation:

- `vendor/onyx-zk/src/state.rs` and related note/transaction modules
- `src/Core/zk/Halo2ProofSystem.*`
- `src/Core/BlockChainState.*`
- wallet snapshot/scanning paths in `src/Core/WalletState.*`
- `ONYX_PROTOCOL_SPEC.md`

Still required:

1. Independent consensus/state audit.
2. Long randomized apply/undo/reorg differential campaigns against a simple reference model.
3. Crash/restart tests at real database interruption points, not only clean process restarts.
4. Corrupt snapshot and partial-write recovery campaigns.
5. Resource measurements for large valid state snapshots at configured limits.

Suggested implementation task:

- Build a deterministic state-model runner that generates bridges, transfers, deployments, issuance,
  and standard calls; applies them to the Rust/C++ implementation and a minimal reference ledger;
  randomly forks and rolls back; serializes/reopens at every step; and compares roots, nullifiers,
  supply, program state, and failure behavior. Save the seed and shortest reproduction on mismatch.

## 9. O2 — private native transfers and authorization

Status: **core and independent-wallet process qualification committed in `dd9755e`**.

Committed implementation:

- Const-shaped Halo2 transfer circuits for bounded spend/output shapes.
- Membership proofs without exposing spent commitments.
- Note commitments, nullifiers, value commitments, encrypted outputs, fee, network, and expiry binding.
- Spend authorization and aggregate binding authorization.
- Native value conservation.
- Multi-note selection, recipient/change construction, pending spend reservation, and wallet recovery.
- Consensus verification, state application, mempool replay/conflict handling, and rollback.
- Negative mutation tests for public inputs, proof bytes, signatures, commitments, and authorization.
- Envelope size and program/proof resource limits.

Transfer qualification added in `dd9755e`:

- Adds `ONYX_TRANSFER_CIRCUIT_K = 16` in `src/CryptoNoteConfig.hpp` for the bounded 1x1, 1x2, 2x1,
  and 2x2 native-transfer family. General program circuits remain at `ONYX_CIRCUIT_K = 20`; the bridge
  remains at `ONYX_BRIDGE_CIRCUIT_K = 13`.
- Routes native transfer creation, fee extraction, consensus verification, state apply, rollback, and
  replay paths through the new transfer-specific `k=16` constant.
- Adds a transfer/bridge/general domain invariant to `tests/blockchain/test_jade_consensus.cpp`.
- Adds bounded in-memory native-transfer parameter, verifying-key, and proving-key caches in
  `vendor/onyx-zk/src/proof.rs`, keyed by `(k, Merkle depth, spend count, output count)`.
- Extends `tests/network/test_onyx_qualification_process.py` with a second independently created,
  encrypted wallet attached to another node.
- Performs a real shielded transfer after the migration, reserves the sender's pending spend, rejects
  a tampered transaction, mines the valid transaction, checks both wallet balances, rejects confirmed
  nullifier replay, and reconciles fees/supply across three nodes.

Local evidence collected from the code committed as `dd9755e`:

- Report: `build/codex-zk/onyx-qualification.json`.
- Report is explicitly `local-ci-not-release-evidence`; it was generated with revision label
  `working-tree` immediately before the scoped commit.
- Final height: 5.
- `total_bridged = 742000`, `total_fees = 2`, `circulating_supply = 741998`.
- `commitment_count = 2`.
- Sender balance: 0; independent receiver balance: 741998.
- Transfer tamper rejection, pending-spend reservation, nullifier replay rejection, supply convergence,
  migration, reorg, recovery, and foreign-network rejection all report `passed`.
- Python syntax validation and `git diff --check` pass.
- The process harness passed after key caching was added. Before caching, cold node verification took
  roughly 140 seconds and the wallet forwarding RPC exceeded its 180-second timeout.
- The release-mode 2x2 native transfer proof test passed at `k=16` in 70.50 seconds.
- ZK and non-ZK Release builds, both Jade suites, all 61 release tests, and the complete C++ ZK suite
  passed. The full ZK suite reached its final success result through standard-program and bridge stages.
- Compiler tests passed 25 tests with six environment-dependent skips; Python, TypeScript, and Rust
  SDK suites passed.

Implemented cache safeguards and remaining review points:

1. The cache helper accepts only `MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>`, so another circuit
   type cannot reuse a native key based only on the shape tuple.
2. Per-shape initialization locks prevent simultaneous first-use requests from duplicating the same
   expensive key generation while allowing different shapes to initialize independently.
3. Prove remote callers cannot populate an unbounded number of cache entries. Consensus uses fixed
   `k=16` and four native shapes, but every C ABI entry point must be checked.
4. Measure cold and warm proving/verification independently. In-memory caching improves repeated work
   but does not solve cold-start DoS or memory-pressure behavior.
5. Ensure every native-transfer verifier path uses `ONYX_TRANSFER_CIRCUIT_K`, while bridge and program
   paths retain their own domains.

Remaining work for this milestone:

- The hosted fixed-Onyx Ubuntu job passed for `02d6fc6` and uploaded its local qualification report.
  Separate workflow failures are recorded in section 13.4 and remain to be repaired/rerun.
- Complete independent cold/warm, concurrent valid-proof and memory-pressure qualification; functional
  success and local caching do not establish denial-of-service safety.

## 10. O3 — wallet, scanning, recovery, and RPC

Status: **core repository implementation complete; operational/hardware acceptance remains**.

Implemented:

- Network-bound Onyx seed/key hierarchy, address derivation, and full viewing keys.
- Encrypted note scanning, witness maintenance, native/token balances, and recovery.
- View-only wallet scanning without seed or spend authority.
- Network-bound portable viewing-key format.
- Encrypted wallet persistence and browser/portable migration.
- Pending note, nullifier, program, issuance, and bridge reservations.
- Transaction construction against the expected next-block version.
- Fail-closed pre-activation behavior and controlled one-block-ahead construction window.
- Overflow-safe expiry and fee arithmetic.
- Encrypted backup, password rotation, wrong-password rejection, alternate-node recovery, identity and
  balance preservation, and recovered spending in the process harness.
- Software-wallet bridge signing without spend-key export.
- View-only/hardware wallet fail-closed behavior for the software-only bridge signer.

Wallet JSON-RPC surface documented in `docs/Bytecoin-Wallet-Daemon-JSON-RPC-API.md` includes:

- `get_onyx_status`
- `get_onyx_asset_balance`
- `get_onyx_program_status`
- `create_onyx_transaction`
- `create_onyx_token_transaction`
- `create_onyx_program_deployment`
- `create_onyx_standard_program_deployment`
- `create_onyx_standard_program_call`
- `create_onyx_token_issuance`
- `create_onyx_bridge`
- `sign_onyx_bridge`
- `finalize_onyx_bridge`

Node RPC includes `get_onyx_supply_audit` and `get_onyx_standard_program_state`.

Still required:

1. Test bridge/transfer signing with a real supported hardware wallet or independently maintained
   signer implementation.
2. Define and document hardware signing APDUs/messages, display requirements, network binding, fee and
   destination confirmation, and anti-klepto expectations.
3. Run multi-operator backup/recovery rehearsal on a frozen qualification revision.
4. Test long offline gaps, pruned/alternate nodes, deep allowed reorgs, corrupted cache, and rebuild
   from seed/viewing key.
5. Complete operator acceptance with signed results and secret-redaction review.

## 11. O4 — one-way legacy-to-Onyx migration

Status: **implemented, committed, and locally qualified; independent/public evidence remains**.

Implemented:

- One-way shielding of exactly one unlocked legacy output into one encrypted native Onyx note.
- Ownership authorization using a one-member CryptoNote ring signature.
- Legacy stack index, amount, output public key, key image, fee, network, expiry, and destination
  binding.
- Legacy key-image replay prevention and a domain-separated Onyx bridge replay marker.
- Atomic legacy-output consumption, commitment append, supply accounting, and rollback.
- Wallet pending bridge reservation and confirmed key-image consumption.
- `create_onyx_bridge`, protected `sign_onyx_bridge`, and `finalize_onyx_bridge` workflow.
- Software signer re-derives the exact one-time key, verifies the unsigned envelope and ownership,
  signs, verifies the result, and never exports the spend key.
- Bridge-specific `ONYX_BRIDGE_CIRCUIT_K = 13`.
- Supply-audit RPC and rollback-safe accounting.

Committed process qualification (`6ee5247`, documented by `787a5b1`):

- Mines a real legacy output on the fixed three-node qualification network.
- Recovers the encrypted wallet through another node.
- Builds and signs a bridge through wallet RPC.
- Rejects a tampered bridge.
- Relays/mines the valid bridge and converges all nodes.
- Checks exact legacy decrease, shielded increase, fee, and supply audit.
- Rejects re-signing/replaying the consumed output.

Still required:

1. Automated pre-migration snapshot and independent supply scan tooling.
2. Controlled reorg/rollback incident rehearsal with chronological evidence.
3. Clean-room reproduction of the incident artifacts.
4. Independent audit of ownership binding, key-image domains, atomicity, rollback, and supply formulas.
5. Public qualification evidence binding start/end block hashes, state roots, legacy scan totals, bridge
   totals, fees, and operator identities.

Do not add an implicit or unaudited deshield path. Any future deshield mechanism is a new consensus
protocol requiring its own threat model, supply proof, activation rules, tests, and audit.

## 12. O5 — standard programs, compiler, and SDKs

Status: **substantially implemented; real pinned NFT deployment/call, capped-token, vesting,
multisig, swap, and refund rollback/reopen lifecycles are committed and locally process-qualified
through `5101111`. Bounded verifier performance, hosted CI, and independent/public qualification
remain.**

Implemented program consensus:

- Canonical registry with deployment, activation/deactivation, resource accounting, and rollback.
- Funded capped fungible-token deployment.
- Private issuance with issuer authorization, sequence, cap, and ledger checks.
- Private token transfers with native-fee payment.
- Pinned standard profiles for NFT, vesting, multisignature custody, and atomic swap.
- Canonical application/context encoding and ordered call bundles.
- Stateful conflict detection, atomic application/undo, and mempool conflict eviction.
- Read-only canonical program-state RPC.

Implemented compiler/toolchain:

- Strict parser and type checker for a deliberately frozen bounded language.
- Canonical IR and deterministic package/bundle generation.
- Reproducible content-addressed dependency locking.
- Checked unsigned arithmetic, booleans/fields, comparisons, division/remainder, shifts, guarded
  execution, fixed arrays, bounded indexing, records, fixed bytes, direct acyclic calls, and inlining.
- Versioned Poseidon, Merkle-node, and nullifier intrinsics.
- Resource analysis after expansion.
- Deterministic Halo2 descriptor generation and independent bundle verification.
- Export identity binding and real proof vectors.
- Canonical standard packages and committed artifacts under `programs/onyx-standard/`.

Implemented developer surface:

- Dependency-free Python profile with typed RPC codec and standard-program builders.
- Dependency-free TypeScript/JavaScript profile.
- Dependency-free Rust profile with network-bound portable keys and typed JSON structures.
- Shared `sdk/onyx/v1/wallet-rpc.json` compatibility contract and golden fixtures.
- Cross-language canonical request/response tests.

Primary files:

- `tools/onyx/compiler_v1.py`
- `tools/onyx/verify_compiler_bundle_v1.py`
- `tools/onyx/structured_fuzz_v1.py`
- `tests/onyx_compiler/`
- `programs/onyx-standard/`
- `sdk/onyx/python/`
- `sdk/onyx/typescript/`
- `sdk/onyx/rust/`
- `vendor/onyx-zk/src/compiler.rs` and standard-program proof modules
- `ONYX_PROGRAMS.md`

Process qualification implemented in `1a82773`:

- Introduces `ONYX_PROGRAM_CIRCUIT_K=16` for pinned stateful standard-program deployments and calls.
  The later uncommitted token work separates token execution from deployment funding; see below.
- Routes semantic validation, fee extraction, mempool dry-run, block apply/undo, conflict eviction,
  wallet construction and type-aware wallet scanning through the program-specific domain.
- The first real production-path attempt at the unrelated general `k=20` domain exceeded the
  unchanged 180-second RPC deadline; the committed full-depth C ABI fixture already proves deployment
  funding and an NFT call at `k=16`.
- An independently funded encrypted wallet constructs and relays a pinned NFT deployment.
- A byte-tampered deployment, pending duplicate spend, and confirmed replay are rejected.
- Three nodes converge at height 6 with one program, four commitments, `100002` total fees and
  `641998` circulating native units.
- ZK/non-ZK builds, both Jade suites, all 61 release tests, and the complete C++ ZK suite pass locally.

### Stateful NFT call qualification implemented in `060b691`

`tests/network/test_onyx_qualification_process.py` now continues after the committed NFT deployment:

1. Mines the twenty blocks required by the default deployment delay and requires all nodes and the
   independent receiver wallet to reach activation height 26.
2. Queries `get_onyx_standard_program_state` on every node before the first call. The canonical RPC
   representation for an absent value is `found=false`, `state=""`, not a 32-byte zero hex string.
3. Constructs a real NFT application for collection field 21, token field 22, serial 33 and transfer
   nonce 1. It proves a transition from
   `dea354729d447a92315a7730a8ffa9c2621f025a2e73cf2c794b7923939f1a00` to
   `8503` followed by 30 zero bytes, using owner witness field 34.
4. Rejects a byte-tampered call, relays the valid call, and waits until the exact transaction hash is
   queryable through `get_raw_transaction` on all three nodes. Do not use
   `transaction_pool_version > 1` as a membership test; the version persists across earlier activity.
5. Builds a second valid proof with nonce 2 and a different next state. NFT nonce is intentionally
   excluded from the stable state key, so this transition conflicts with the pending first call.
6. Verifies admission by state, not by the deprecated transport string: node `send_transaction`
   always returns `send_result="broadcast"` even when `add_transaction` returns false. The test
   requires the competitor hash to be absent, the original hash to remain present, and pool count to
   remain exactly one.
7. Mines the original call at height 27, allows up to 360 seconds for independent proof validation,
   and requires identical tips and state on all nodes. Querying with nonce 1 or nonce 2 returns the
   same stable-key value `8503...0000` at height 27.
8. Rejects confirmed replay and reconciles exact final supply: `742000` bridged, `100002` fees,
   `641998` circulating, five commitments, and one registered program. A zero-fee stateful call does
   not change wallet native balance.
9. Extends the local report with activation/call heights, program ID, application bytes, prior/next
   state, balance, and explicit scenario results. The report remains
   `local-ci-not-release-evidence` and contains no wallet credentials or spend secrets.

The complete three-node process run passed locally against the release ZK binaries and wrote
`build/codex-zk/onyx-stateful-nft-qualification.json`. Python syntax validation and
`git diff --check` also passed. This is strong functional regression evidence, not public or
independent release evidence.

### Locally qualified capped-token implementation and circuit-domain split (`db044e5`)

The token scenario exposed an architectural coupling that must be understood before changing any
proof API. A program-deployment transaction contains two different objects:

1. a native funding transfer that pays the deployment fee and creates change; and
2. a registered program artifact whose verifier shape is later reused by issuance and token transfer.

The original C ABI accepted one `circuit_k` for both objects. Using `k=16` for funding and deployment
made pinned programs practical, but a token artifact created at that value could not later be used by
the old issuance path, which expected the generic `ONYX_CIRCUIT_K=20`. Using `k=20` for the entire
deployment was functionally consistent but operationally unacceptable: a real wallet RPC remained in
proof construction for more than 30 minutes and grew to several gigabytes of resident memory.

The committed implementation therefore makes the domains explicit:

| Domain | Constant | Current value | Purpose |
|---|---:|---:|---|
| Generic/legacy Onyx | `ONYX_CIRCUIT_K` | 20 | Existing generic compatibility domain; do not use automatically for every transaction |
| Native transfer | `ONYX_TRANSFER_CIRCUIT_K` | 16 | Private native spends and outputs |
| Stateful standard program | `ONYX_PROGRAM_CIRCUIT_K` | 16 | Pinned NFT, vesting, multisig, and swap calls and their funding transfers |
| Capped token execution | `ONYX_TOKEN_CIRCUIT_K` | 14 | Token program artifact, issuance, and mixed token/native-fee transfer |
| Bridge | `ONYX_BRIDGE_CIRCUIT_K` | 13 | One-way legacy-to-Onyx migration |

`k` is the Halo2 circuit capacity exponent. Reducing it does not reduce the Pasta curve's
cryptographic strength; it prevents allocating rows that the fixed token constraint system does not
use. The full token function set fits at `k=14`, which is pinned by a Jade consensus test. A future
constraint change that no longer fits must fail tests and receive explicit migration/activation
design; silently increasing `k` is not an acceptable performance fix.

The API change is cross-layer and must stay atomic:

- Rust `build_program_deployment` and `verify_standard_deployment` now take `program_k` and
  `funding_k` independently.
- The exported C functions for create, verify, and verify/apply deployment expose both values.
- `vendor/onyx-zk/include/onyx_zk.h` documents the split, and the C++ `Halo2ProofSystem` adapter
  forwards both values.
- Consensus admission, mempool dry-run, block apply/undo, wallet construction, wallet scanning, ZK
  tests, and fuzz entry points pass the correct pair rather than relying on a hidden default.
- The wallet scan C ABI also carries both values. This is essential: the first height-28 process run
  proved consensus acceptance but exposed that a one-parameter scanner reconstructed the token
  artifact at funding `k=16`, refused to commit the block, and retained the pre-deployment balance.
  The split scanner now records the artifact at token `k=14` while scanning its funding transfer,
  including in viewing-only wallets.
- Transfer verification/application likewise accepts native and token domains independently. The
  authenticated proof backend selects `ONYX_TRANSFER_CIRCUIT_K=16` for native transfers and
  `ONYX_TOKEN_CIRCUIT_K=14` for token/mixed transfers. The first height-49 issuance run caught the
  old one-domain path when a wallet-created mixed transfer was rejected as an invalid authorized
  transfer. A release-mode Rust proof/apply regression now uses deliberately different values and
  passes, preventing an unauthenticated caller hint or fallback-order ambiguity.
- Pinned standard deployments pass `k=16` for both arguments. Capped-token deployments pass funding
  `k=16` and program `k=14`; issuance and token transfers use token `k=14`.
- The Rust wallet regression creates a funding proof at `k=10` and token artifact at `k=14`, verifies
  the correct pair, and rejects verification when the wrong program domain is supplied.
- Before constructing a token artifact, the wallet now performs the same native-note availability
  selection needed for the one-unit self-output plus fee. A pending duplicate deployment therefore
  returns `InsufficientFunds` before rebuilding token proving/verifying material.

Measured qualification history, all local and non-release:

- Token `k=20`: wallet-side capped-token deployment construction exceeded the 1,800-second RPC
  deadline while the wallet stayed alive at roughly 3.2 GB RSS. This is valid-request DoS evidence.
- Token `k=16`: construction completed in roughly 10–12 minutes, but independent cold-node
  verification approached or exceeded 30 minutes. This was still unsuitable for bounded admission.
- Token `k=14`: native binaries build, the full C++ `--zk` suite passes, and the Jade consensus suite
  passes. Deployment construction measured about six minutes on this Windows host. Intermediate
  process runs exposed the scanner and mixed-transfer dispatch defects described above. After both
  fixes, a clean three-node/two-wallet run exited zero through height 50 and wrote the report described
  below. Cold verification still takes minutes and remains a release-blocking DoS/backpressure task.

The extended process harness in `tests/network/test_onyx_qualification_process.py` performs the
following deterministic scenario after the committed NFT call at height 27:

1. Deploy a capped token with cap `5000`, metadata `QTK/2`, fee `100000`, funding `k=16`, and token
   execution `k=14`; reject tampering and a second wallet construction while funding is reserved.
2. Mine deployment at height 28, assert issuer/cap/metadata/zero issued supply, reject confirmed
   replay, then mine the 20-block delay to activation height 48.
3. Reject issuance by the non-issuer wallet. Issue `1000` units at sequence zero to the independent
   receiver; reject proof tampering and pending sequence reuse; mine at height 49.
4. Reject confirmed issuance replay, zero issuance, and a `5000`-unit over-cap issuance after the
   first `1000` units are issued.
5. Transfer `400` token units back to the original wallet while paying a one-unit native fee; reject
   tampering and pending token/native-spend reuse; mine at height 50 and reject replay.
6. Require all nodes and both wallets to converge. Expected final token balances are `600` at the
   issuer wallet and `400` at the recipient; expected native balances are `541997` at the issuer and
   zero at the recipient.
7. Require final native audits of `742000` bridged, `200003` fees, `541997` circulating, eleven
   commitments, and two registered programs. Require token issued supply `1000`, remaining cap
   `4000`, and next issuance sequence `1`.
8. Write `build/codex-zk/onyx-private-token-qualification.json`, marked
   `local-ci-not-release-evidence`, with hashes/heights/state totals but no wallet secrets.

The clean run exited zero and wrote
`build/codex-zk/onyx-private-token-qualification.json` with scope
`local-ci-not-release-evidence`. Its final block is
`dde2b74470ed0d0a82cb6aeb45365f66594000f91e16b2048d6874de63dc4e11` at height 50. All three nodes
reported the same commitment root
`3e4c4f8a6f509942186fac0025db2d50fadd9e30ceafe0c0309aa338fcb9c221`, `742000` bridged,
`200003` fees, `541997` circulating native units, 11 commitments, two programs, and block program
cost `378000`. The token program id is
`730901bd595a8732a5c85343b80b350f02baa3e7f2c928f4d4d7795c573d8b5e`.

The final count is 11, not 10: the mixed transfer spends one token note and one native note, then
creates three commitments (400 token to the recipient, 600 token change to the issuer, and 541997
native change after the one-unit fee). The first complete functional run reached identical height-50
state on every node but correctly failed its report assertion because the harness expected 10. The
assertion was audited and corrected, and the subsequent clean run passed. Do not weaken this to a
range or suppress an unexpected commitment-count change.

This is local functional qualification only. Cold verifier initialization and transaction propagation
still need explicit bounded-performance work; lower `k` is an important mitigation, not a complete
admission-control design.

### Completed implementation: remaining standard-profile qualification

Commit `3da16ad` extends the same release-binary three-node/two-wallet process harness through all
remaining pinned profiles. The deterministic continuation after the capped-token transfer is:

1. Deploy vesting, multisig, and swap at heights 51, 52, and 53, paying `100000` native units for
   each deployment. Their activation heights are 71, 72, and 73.
2. Reject vesting release before its unlock height; mine the boundary and accept release at height 75.
3. Reject a one-of-two multisig witness; accept the pinned two-of-two authorization at height 76.
4. Reject a swap claim with the wrong preimage. At height 77, construct two individually valid claim
   and refund branches sharing the same stable state key, admit the claim, and reject the competing
   refund while retaining exactly one pool entry.
5. For a separate swap instance, reject refund before timeout, mine boundary height 78, and accept
   the timeout refund at height 79.
6. After every accepted call, require exact state equality on all nodes, confirmed replay rejection,
   both wallets synchronized, and exact supply-audit equality.

The clean run exited zero and wrote
`build/codex-zk/onyx-standard-profiles-qualification.json`, marked
`local-ci-not-release-evidence`. All three nodes finished at height 79 on block
`63e8b4f97fb494cd3dacbb82aeb9f188b728116f451b4bd41a937f5b937cbc83`, with commitment root
`6d3606e4b912bb42f48205ed2401d1bf0483b542f036574ca8ca6fa42fd63b1a`, `742000` bridged,
`500003` fees, `241997` circulating native units, 21 commitments, and five programs.

Exact profile evidence:

| Profile | Program id | Deploy/activate/call | Transaction | Result |
|---|---|---|---|---|
| Vesting | `e4e51abf57263caa36f948af5067182b49e45407c74bfbba44b892b0e54aa5b2` | 51 / 71 / 75 | `d00747e9b85c6f60b0e09c6f05c4bfe13493e058b993c5a7146732e56ad9aeb9` | Early release rejected; state advanced to canonical field 902 at unlock 75 |
| Multisig | `2f6464de478dcc47c162f2181e0e0f802692e1b7921bbff207e91786c4d54b35` | 52 / 72 / 76 | `767381c27748a8c430553a80902479121f47cec4a8d27ca8a4b7d3979933b145` | One-of-two rejected; two-of-two advanced state to field 903 |
| Swap claim | `5775b7e698fd801084b1bb5d9c265fc69563066e8cdd7dcdfb024381b11285af` | 53 / 73 / 77 | `41927336ec5c64cb134cbefec3a541870fa83d8e4a281ea5ff2b0ec6486b70fa` | Wrong preimage and competing refund rejected; claim advanced state to field 904 |
| Swap refund | same swap program | separate key, timeout/call 79 | `0c0ed581f51c3d94a63a58ea3849405e7791444b4973272311c6567f4b24ecab` | Early refund rejected; timeout refund advanced state to field 906 |

Observed performance is not a release pass. Program proof creation took roughly two minutes per call
on this Windows host, and each peer independently consumed minutes verifying/admitting or applying a
valid proof. At the time of this run, confirmed replays and pending stable-key competitors also reached
expensive verification. The authenticated admission precheck described below now rejects those two
standard-call conflict classes before Halo2, without changing block verification.

### Completed implementation: program-state rollback, reopen, and recovery (`5101111`)

The release-binary process harness now continues beyond the first swap refund and proves an actual
program-state undo/reapply lifecycle. This is a local regression gate, not public release evidence.
The clean unattended run on 2026-08-11 exited zero and wrote
`build/codex-zk/onyx-program-rollback-qualification.json` with scope
`local-ci-not-release-evidence`.

Deterministic branch sequence:

1. Complete the five-program lifecycle through swap claim height 77, then mine the empty timeout
   boundary at height 78. Record tip
   `8bc5bf085294530004ab078de8ffddc7b3bbd0809bcf2733403df9eef74ebf48`, the complete supply
   audit, and the pre-refund program state.
2. Wait for node C's exact `db_commit started... tip_height=78` log event. RPC/header height is not
   accepted as proof that SQLite has durably committed the same tip.
3. Use SQLite's online backup API while node C remains live to create a transactionally consistent
   height-78 database image. Both source and destination connections are explicitly closed so Windows
   cleanup can remove the temporary tree.
4. Stop/reopen node C from its live database at the exact height-78 tip, construct the timeout refund,
   and confirm transaction
   `bae8c1def7efe4c31d9a4f78e370224c5c0745fd901701d0d4263b3d08c04635` at height 79.
5. Open the height-78 snapshot as an isolated daemon with an unused exclusive peer port, mine two
   empty blocks, and obtain the alternative height-80 tip
   `21784d82597721d2307ccdb20407f5c82d90ca69079cd27b478c9ef65aebfae8`.
6. Restart all three primaries against that longer fork. Require every primary to durably converge on
   the same height-80 block and prove the refund is undone: program state, supply audit, commitment
   count, commitment root, and transaction eligibility return to the recorded pre-refund oracle.
7. Stop/reopen the receiver wallet through an alternate primary node. Require its reconstructed
   native/token/program view to match the rollback state.
8. Submit the identical refund binary directly to every daemon that does not know it, including the
   isolated fork. This is necessary because restoring a transaction to a primary mempool does not
   rebroadcast it when a duplicate submission is rejected as already known.
9. Reconfirm the same refund at height 81 on block
   `8c7ce1043aadd0a4faeae46a6ef6e5f212a100f7b0353d5d7d79e01205b8cd77`; require all nodes,
   wallets, program state, commitments, and supply audits to converge again.
10. Reject a testnet process at the Onyx identity/genesis boundary, write the report, terminate all
    processes, close every database handle, and remove the temporary qualification directory.

Exact passing final audit on all three primary nodes:

| Field | Value |
|---|---:|
| Final height | `81` |
| Final block | `8c7ce1043aadd0a4faeae46a6ef6e5f212a100f7b0353d5d7d79e01205b8cd77` |
| Commitment root | `c50ae942893af7412b2ea5263665e16a40a65a0eb311058e7e4333a98a63180d` |
| Commitment count | `21` |
| Program count | `5` |
| Total bridged | `742000` |
| Total fees | `500003` |
| Circulating native supply | `241997` |
| Current-block program cost | `4096` |

The rollback oracle at height 80 restored commitment count `20` and root
`6eb87a0e11d818b4206600234ec8980e61f405c39ae325e80ba5cea9bba97618` before the height-81
reconfirmation appended the twenty-first commitment. The final report marks every rollback scenario
passed, including commitment-root rollback, program-state rollback, mempool eligibility restoration,
alternate-node wallet reopen, and reconfirmation after node reopen.

Qualification failures that informed the final design must not be erased from future handoffs:

- A raw database-directory copy and a backup taken before the daemon's periodic commit both reopened
  one block behind the RPC-visible tip. The final harness waits for the exact durable log event and
  uses SQLite online backup.
- A duplicate refund submission to a primary that had automatically restored the transaction to its
  mempool did not rebroadcast to the isolated fork. The final harness checks each daemon and submits
  the exact binary wherever it is absent.
- Python's SQLite connection context manager does not close the handle. Explicit closing fixed a
  Windows temporary-directory cleanup failure after an otherwise successful diagnostic run.
- Capped-token activation originally inherited the helper's 180-second miner timeout. Multi-peer
  deployment proof application exhausted it after reaching only height 32. The scoped activation
  call now uses 1,800 seconds; the clean rerun crossed that old boundary and reached height 48.

Acceptance criteria now proven locally:

- All three nodes converge after every valid program transaction and after the longer-branch reorg.
- Reorg/undo restores exact program state, commitments, supply, and transaction eligibility.
- Node reopen and alternate-node wallet recovery reconstruct the rollback state.
- The identical transaction can reconfirm after rollback, restoring the final root/audit exactly.
- Native supply remains `bridged - all fees`; token supply remains within its program cap.
- The report is valid JSON and cleanup leaves no daemon, wallet, miner, or temporary data directory.

This scenario deliberately rolls back the swap refund because it exercises program state, commitment
undo, mempool restoration, wallet recovery, and reconfirmation in one bounded branch. It does not yet
replace wider randomized reorg campaigns across every earlier deployment/issuance transition.

### Completed implementation: authenticated standard-call conflict prechecks

Standard-program mempool admission now authenticates the contextual value-layer envelope and derives
its canonical nullifiers and stable state keys before invoking Halo2. It rejects a nullifier or stable
key already reserved by the local pool, then decodes the current rollback-safe consensus snapshot and
rejects an already-spent nullifier or stale signed prior state. The precheck does not inspect
unauthenticated caller-supplied identifiers and cannot admit anything: an eligible result still enters
the original full stateful proof verifier, and block application is unchanged.

The Rust/C ABI boundary returns three explicit outcomes: malformed/unauthorized input, authenticated
state conflict, or eligible for full verification. C++ preserves the two existing caller semantics:
pending pool conflicts return `false`, while conflicts against committed state throw the same
`ConsensusError` used by the full verifier. An initial qualification attempt exposed this distinction:
returning `false` for a confirmed replay correctly rejected it internally but made RPC report
`broadcast`; the final implementation restores the consensus-error response and the rerun passes.

Focused and process validation:

- The optimized Rust wallet fixture constructs and fully verifies a signed NFT call, confirms the
  fresh snapshot is eligible, applies it, and confirms both the internal helper and FFI return a cheap
  replay conflict. Unsupported Merkle depth fails closed.
- Release `bytecoind`, `walletd`, `minerd`, and `tests` rebuild successfully; `tests.exe --jade`
  passes and the Python harness compiles cleanly.
- The complete three-node run exited zero and wrote
  `build/codex-zk/onyx-precheck-qualification.json` with scope
  `local-ci-not-release-evidence`. It finished at height 81 on block
  `135019cdf8c964f11fc4c666e082f4ad10ad265a53eca4c3682d9795eb9fc23a`, with all three nodes on
  commitment root `3950785d3dfe4dc5494960c05312b81e45f1d006c71e5af008e00d8591d9f136`.
- Timed admission of an already-built competing NFT transition took `0.015` seconds; the competing
  swap branch measured below the timer's resolution and was recorded as `0.0` seconds. Both are below
  the conservative 30-second regression ceiling, while valid proof admission on the same host still
  consumed minutes per peer.
- The same run passed confirmed replay rejection, every token/profile lifecycle, durable rollback,
  restored refund eligibility, reconfirmation, alternate-node wallet reopen, and exact supply
  convergence. The report records the measured timings for future comparison.

### Next implementation: bounded verifier performance

Cheap standard-call replay/conflict amplification is closed, but valid proofs and the deployment,
issuance, and private-transfer families can still consume substantial CPU. The immediate order is:

#### Implemented: fail-fast concurrent mempool verification bound

External Onyx mempool admission now obtains a process-local RAII permit before
`validate_tx_semantic`. At introduction, transfer, bridge, deployment, and issuance metadata
extraction could itself verify a proof; authenticated filters added afterward remove proof work from
all semantic/read-only fee paths. The default bound is one active external Onyx verifier globally and one per source.
There is no waiting queue: a contending request receives retryable RPC error `-104`
(`VERIFIER_BUSY`) immediately. P2P treats the same overload as a local non-ban condition.

The limiter is deliberately non-consensus. Block application and internal transaction restoration
after reorganization use empty sources and bypass it, so local load cannot change block validity or
prevent deterministic rollback recovery. Exact transaction duplicates and the zero-fee standard-call
pool cap are checked before acquiring or spending proof resources. `add_transaction` now returns the
fee it already verified, so RPC/P2P descriptor construction no longer calls proof-backed
`get_tx_fee()` outside the permit or verifies the same envelope twice. A focused RAII test proves global
and per-source bounds, fail-fast behavior, permit release/reuse, empty-source rejection at the limiter,
and the stable retryable RPC code. Both ZK and non-ZK Release builds plus `tests.exe --jade` pass.

This closes concurrent in-process verification growth, but it is not yet the complete performance
gate: the current synchronous networking architecture can still accumulate requests outside the
limiter, and sustained sequential valid-proof traffic remains expensive. Live parallel/RSS/load
qualification and request-rate/backlog bounds are still required.

#### Implemented: authenticated private-transfer prechecks and single-proof admission

Native and private-token transfer envelopes now have a state-independent authenticated metadata
extractor. It decodes the bounded canonical `AuthorizedTransaction`, verifies every spend
authorization and the binding signature, and only then exposes the signed network, anchor, expiry,
fee, nullifiers, and commitments. It deliberately does not inspect or trust an unverified Halo2
proof. The extractor is used by semantic fee calculation and `get_tx_fee()`, so read-only fee paths
can no longer trigger proof verification.

External mempool admission uses the authenticated nullifiers to reject a pending pool conflict, then
decodes the rollback-safe snapshot and rejects an already-spent nullifier before Halo2. An eligible
transaction still executes `verify_apply_transfer`, which verifies the complete proof, network,
expiry, anchor window, nullifier state, and state transition. The resulting fee must equal the signed
authenticated fee. Pool bookkeeping uses the authenticated nullifier/commitment delta only after
that full stateful verifier succeeds.

Before this change, transfer admission verified the same proof during semantic fee extraction,
`verify_and_extract_transfer`, and state application. It now performs cheap signature authentication
for metadata and exactly one mandatory stateful Halo2 verification. Block validation retains full
stateful proof verification through transaction application; the new helper cannot admit a
transaction or change consensus validity.

Focused validation constructs a real proof-bearing transfer, checks identical metadata from the full
and authenticated extractors, observes an eligible precheck against the funding snapshot, applies the
proof, and then observes a conflict against the spent snapshot. Malformed input clears every output
before returning failure. `cargo check --release`, the optimized proof regression, ZK and non-ZK
Release daemon/test builds, and both `tests.exe --jade` runs pass.

#### Implemented: authenticated program-deployment extraction

Program deployments now receive the same proof-free treatment without trusting a caller-provided
program identifier. The Rust boundary decodes and structurally validates the complete deployment,
verifies the signed funding transaction, enforces the bounded 1x1 through 2x2 funding shape and
backend identity, reconstructs the pinned standard/token program entry for the selected Merkle depth
and circuit domain, derives its canonical program ID, and requires the signed deployment call to name
that exact ID. Only then does it expose the funding fee, nullifiers, commitments, and program ID.

Semantic fee reads and `get_tx_fee()` use this authenticated extractor. Mempool admission rejects
pending funding-nullifier or canonical-program-ID conflicts before Halo2. A non-conflicting
deployment still executes `verify_apply_program_deployment` exactly once; it must return the same fee
and program ID before the pool records the authenticated delta. This removes the former semantic,
extraction, and application proof duplication while retaining full stateful verification.

The optimized real-deployment regression matched the authenticated output to full verification and
then completed stateful application/replay checks. Cargo check, ZK/non-ZK Release daemon and test
builds, and both Jade suites pass.

#### Implemented: registry-authenticated token-issuance precheck

Issuance cannot safely use a state-independent extractor because its issuer key lives in the deployed
token policy. The new precheck therefore decodes the canonical snapshot, loads the exact signed
program ID from the registry, recomputes and verifies the registry entry ID, validates the token
depth/domain and active issuance function schema, and obtains the issuer key and supply cap from that
policy. It then verifies both the separate issuer signature and the issuance-specific value-binding
signature before exposing any metadata.

Only authenticated values drive rejection. The precheck compares network, expiry distance, the signed
anchor against the retained anchor window, next issuance sequence, and cumulative supply against the snapshot. A current-state conflict
throws a consensus rejection; a second pending issuance for the same authenticated program returns a
pool conflict. An eligible issuance still executes `verify_apply_token_issuance` exactly once, and
the applied program ID, sequence, and amount must match the authenticated precheck result.

Semantic validation and `get_tx_fee()` now return the protocol-defined zero issuance fee without
proof verification. This is safe because neither path admits or applies the transaction; mempool and
block state application still enforce the complete registry, issuer, proof, cap, sequence, network,
expiry, and state transition rules. The proof-bearing regression confirms fresh eligibility, full
application, replay conflict, and corrupted-issuer rejection. Cargo check, ZK/non-ZK Release builds,
and both Jade suites pass.

#### Implemented in `7e46efb`: authenticated bridge admission

Bridge semantic validation and read-only fee calculation now decode canonical bridge metadata
without invoking Halo2. The extracted legacy amount, stack index, key image, fee, ownership sighash,
and ownership signature are not trusted directly: mempool admission resolves the exact legacy output,
checks the key-image subgroup and index bounds, checks next-block unlock context, and verifies the
one-member ownership ring signature against the resolved output key before consulting confirmed or
pending key-image conflicts.

The ownership sighash binds the complete canonical bridge preimage, backend identifier, and proof
bytes. Consequently, a successful ownership signature authenticates the values used for cheap
rejection without treating the structural extractor as a proof verifier. A non-conflicting bridge
still enters the unchanged authoritative `verify_apply_bridge` path, followed by the legacy spent
check, output resolution/unlock check, ownership verification, key-image storage, and atomic Onyx
snapshot application. Pool cleanup and block undo use structural metadata only for transactions that
were already fully accepted.

The optimized real bridge regression compares every structural field with the full stateful verifier.
Malformed extraction clears every output. `cargo check --release`, both focused Rust tests, ZK and
non-ZK Release daemon/test builds, both Jade suites, and the complete C++ ZK suite pass. This completes
proof-free semantic and read-only fee handling for every Onyx transaction family; live valid-proof
load qualification remains the next performance milestone.

#### Implemented: bounded P2P download backlog and verifier-overload cooldown

Transaction descriptor messages may advertise up to 1,000 entries, but the node no longer turns an
entire chunk from every connected peer into simultaneous object downloads. A saturating admission
calculation limits active transaction-body downloads to 32 per peer and 128 process-wide. Candidates
remain sorted by fee-per-byte, so the bounded slots go to the highest-priority eligible descriptors.
These are local resource limits only; they do not affect block validity, transaction validity, or the
consensus pool ordering rules. Duplicate hashes inside one descriptor message are rejected as a
protocol violation before insertion, replacing the former invariant-crash path.

When an Onyx transaction reaches the node while the proof-verifier permit is occupied, its
transaction ID enters a 30-second retry cooldown. Reannouncements and alternate-peer retry callbacks
consult that table before requesting the body again. The table is capped at 1,024 IDs, removes expired
entries lazily, and evicts the entry expiring soonest when full, preventing attacker-selected IDs from
creating unbounded memory. Overload remains a non-ban condition, and a later announcement after the
cooldown can retry normally.

Deterministic tests cover saturation at every peer/global boundary, cooldown retention and expiry,
bounded eviction, permit reuse, and the stable retryable RPC code. ZK and non-ZK Release daemon/test
builds and both Jade suites pass. The caps bound queued transaction bodies and retry metadata; they do
not yet constitute live evidence for verifier RSS, CPU fairness, or ordinary wallet/block progress
under parallel proof load.

The private `get_statistics` response now exposes active and peak verifier count, successful permit
acquisitions, global/per-source permit rejections, active transaction-body downloads, and current
retry-cooldown table size. These counters are updated under the same lock as permit state, allowing a
load report to prove both resource behavior and whether the intended limiter engaged. Optional
zero-valued fields may be absent from JSON; qualification readers must treat absence as zero.

The standalone `tools/onyx_verifier_load.py` runner accepts distinct prebuilt transaction files,
releases concurrent submissions on a barrier, samples cross-platform process RSS/peak RSS/CPU, polls
the authenticated counters, measures each response, checks post-load node health, and writes an
atomic revision-bound JSON report with scope `local-load-not-release-evidence`. It fails closed on a
verifier peak above one, missing permit activity, missing required overload evidence, post-load RPC
failure, or a caller-supplied RSS ceiling violation. Unit tests cover canonical/distinct input
handling, optional counter normalization, response classification, and live process sampling.

1. Benchmark cold/warm valid proofs, duplicate replays, conflicts, parallel requests, RSS, and block
   application on named hardware. Pin thresholds only after measuring variance.
2. Run adversarial mixed workloads and prove ordinary block/wallet progress continues under load.

Other remaining O5 work:

- Independent compiler lowering/circuit/canonical-encoding review.
- Sustained parser, type checker, IR decoder, backend, and descriptor fuzzing.
- Public testnet qualification of every standard profile and rollback path.
- Language bindings only where a named maintainer can preserve the compatibility contract.
- Unknown/user-supplied circuits must continue to fail closed until explicitly reviewed and activated.

## 13. O6 — network privacy, RandomX, scalability, and release machinery

Status: **major repository components implemented; operational evidence remains**.

### 13.1 Dandelion++

Implemented:

- Negotiated P2P relay version.
- Stem selection and epoch rotation.
- Loop and hop-limit handling.
- Randomized embargo and fluff recovery.
- Disconnect recovery and delivery scoring.
- Fallback compatibility for older V4 peers.
- Deterministic policy tests and a real multi-process daemon/miner/wallet topology test.

Remaining:

- Historical released-V4 binary compatibility matrix.
- Long adversarial topology soak with partitions, churn, eclipse attempts, and timing analysis.
- Resolve the known CI wallet-height race in `test_dandelion_process.py` only after reproducing it and
  preserving the intended assertion. The proposed fix is to wait for the recovered wallet to reach
  height 15 before calling `create_transaction`.
- Independent network-privacy and denial-of-service review.

### 13.2 Tor/I2P and SOCKS5

Implemented:

- Fail-closed SOCKS5 outbound connection path.
- No local hidden-service DNS resolution.
- Canonical onion/I2P peer identity framing and peer-database persistence.
- Referral bounds, validation, graylisting, and poisoning resistance.
- Linux adversarial SOCKS emulator and DNS tripwire process test.

Remaining:

- Real Tor and I2P daemons in multi-node qualification, not only an emulator.
- Proxy restart, authentication failure, referral poisoning, disconnect, and database recovery tests.
- Linux, Windows, and macOS packet captures proving no direct fallback or DNS leak.
- Operator documentation for proxy-only nodes and hidden services.

### 13.3 RandomX

Implemented:

- Vendored RandomX v2.0.1 integration.
- Delayed branch-derived seed epochs.
- Node/miner template negotiation.
- Malformed-template failure.
- Architecture known-answer tests.
- Full-memory policy support.
- Reorganization/reopen campaigns and real daemon/miner process qualification.
- Co-scheduled Onyx/RandomX activation.

Remaining:

- Native x86-64 and ARM64 throughput, memory, startup, and power measurements.
- Long seed-epoch, partition, reorg, and restart soak.
- Historical compatibility and upgrade-boundary testing with released binaries.
- Independent RandomX integration/consensus review.

### 13.4 Release tooling

Implemented:

- Source archive, checksum, SPDX SBOM, dependency lock, provenance, and evidence tools.
- Strict JSON parsing with duplicate-key, non-finite, overflow, byte, depth, string, list, and member
  bounds.
- Symlink, path traversal, alias, non-regular-file, and untracked evidence rejection.
- Evidence replay/count-inflation prevention.
- Unicode-normalized actor identities and canonical UTC timestamps.
- Strict public endpoint syntax and release-gate ordering.
- Activation commit/height binding, compiler/profile digest recomputation, and archive/SBOM
  regeneration checks.

Primary files:

- `tools/release/`
- `tests/release/`
- `release/dependencies.lock.json`
- `release/activation-gates.json`
- `.github/workflows/release-evidence.yml`
- `.github/workflows/reproducible-binaries.yml`

Known hosted CI findings at `02d6fc6`:

- The fixed-Onyx qualification job passed; Consensus failed in the separate, previously documented
  recovered-wallet Dandelion height race.
- The sanitizer harness did not compile because `src/main_fuzzer.cpp:75` refers to
  `parameters::ONYX_BRIDGE_CIRCUIT_K` outside namespace `cn`.
- Release evidence correctly rejected the stale tracked-tree digest for `vendor/onyx-zk` after the
  native proof cache changed `proof.rs`.
- These require focused fixes and reruns; none justify weakening their checks.

## 14. Fixed `--net=onyx` qualification network

Status: **committed and locally exercised**.

Implemented in `5ed59bd` and extended by later commits:

- Distinct network UUID, genesis nonce, default ports, data directory, and wallet identity domain.
- V5/RandomX/V6/V7 co-scheduled at height 1 for a direct V4-to-V7 qualification transition.
- One-second low-difficulty local block target.
- No compiled seed nodes.
- Inert zero checkpoint public keys with fail-closed checkpoint admission.
- ZK-enabled binary requirement.
- Three isolated nodes, real miner, authenticated encrypted wallets, competing branches, reorg,
  malformed V7 rejection, recovery, migration, and independent-wallet shielded transfer.
- Revision-bound machine-readable report explicitly marked as local/non-release evidence.

Committed milestones:

| Commit | Milestone |
|---|---|
| `5ed59bd` | Fixed Onyx qualification network |
| `d1dca30` | Three-node longer-branch reorganization |
| `a26303e` | Wallet recovery across reorganization |
| `6ee5247` | Real legacy-to-Onyx migration |
| `787a5b1` | Migration qualification documentation |
| `dd9755e` | Independent-wallet native shielded transfer and native proof-key caching |
| `1a82773` | Pinned NFT deployment and program-specific consensus domain |
| `060b691` | Stateful NFT call, exact-hash propagation, stable-key conflict and state convergence |

The local network is intentionally accelerated. Its proof, PoW, and timing results cannot substitute
for public release hardware or 14-day qualification evidence.

## 15. External release gates — all incomplete

These tasks cannot be truthfully completed by generating placeholder files. They require independent
actors and real elapsed work against one frozen commit.

### 15.1 Source provenance

Required:

- Two independent builders with distinct digest-bound environments.
- Exact frozen revision and dependency lock.
- Byte-identical source archive and SPDX SBOM hashes.
- Named tools and committed typed attestations.

### 15.2 Independent audits

Required:

- Two distinct audit organizations.
- Work begins after the frozen revision exists.
- Combined coverage of ZK cryptography, consensus/state, wallet/privacy, network/DoS, migration/supply,
  compiler, and reproducibility.
- Distinct report digests, documented methodology, verified remediation, and zero unresolved critical
  or high findings.

### 15.3 Public qualification soak

Required:

- At least 14 elapsed days.
- At least three independently operated nodes.
- At least 10,000 observed blocks.
- One exact frozen revision and one fixed network/genesis identity.
- Reorg, malformed bundle, valid-proof DoS, migration, recovery, and supply reconciliation scenarios.
- Final converged block hash/height and supply audit on every node.
- Zero unresolved consensus divergence.
- Public credential-free HTTPS evidence endpoint accepted by the release verifier.

### 15.4 Reproducible platform binaries

Required for Linux x86-64, macOS ARM64, and Windows x86-64:

- Two independent builders per platform.
- Reproduced `bytecoind`, `walletd`, and `minerd`.
- Exact binary, debug-symbol, and per-binary SBOM hashes.
- Bound compiler, SDK, linker, revision, dependency lock, and environment identity.

### 15.5 Incident-response drill

Required:

- At least two participants and an independent observer.
- Named decision authority and preserved communications.
- Consensus-stall, reorg, and proof-DoS scenarios exactly once each.
- Ordered detection, triage, recovery, supply reconciliation, artifacts, clean-room reproduction, and
  unresolved-action list.

### 15.6 Governance approval

Required last:

- Approval of the exact frozen revision, compiler digest, target profile, and four co-scheduled heights.
- Eligible electorate, threshold, distinct approvals, recomputed quorum, objections, and no blocking
  objection.
- Reference mainnet height/hash and at least 5,040 blocks of activation notice.

## 16. Recommended continuation order

Use this order unless new evidence changes the risk assessment.

### Step 1 — finish and publish the native-transfer milestone

Status: **implemented in `dd9755e`, documented/pushed in `02d6fc6`, and passed in the hosted fixed-Onyx
Ubuntu job.**

Files in scope:

```text
src/Core/BlockChainState.cpp
src/Core/CryptoNoteTools.cpp
src/Core/WalletState.cpp
src/CryptoNoteConfig.hpp
tests/blockchain/test_jade_consensus.cpp
tests/network/test_onyx_qualification_process.py
vendor/onyx-zk/src/proof.rs
```

Completed locally:

1. Audit every changed call site and cache boundary.
2. Run focused Rust proof tests and full build/test matrix.
3. Update qualification documentation.
4. Commit only the listed implementation files as `dd9755e`.

Hosted follow-up:

1. The fixed-Onyx qualification job passed and uploaded its non-release report.
2. Repair and rerun the separate Dandelion, sanitizer compile, and release-lock failures recorded in
   section 13.4 after their focused plan is approved.

Exit criterion: clean scoped diff, local matrix passes, hosted Onyx qualification passes, and no
unrelated user file enters the commit.

### Step 2 — implement standard-program multi-process qualification

Status: **pinned NFT deployment is committed in `1a82773`, its stateful NFT call is committed in
`060b691`, capped-token deployment/issuance/transfer and split circuit APIs are committed in
`db044e5`, vesting/multisig/swap process qualification is committed in `3da16ad`, and deterministic
refund rollback/reopen/reconfirmation qualification is committed in `5101111`.**

Follow the exact results in section 12. Implement cheap safe replay/conflict admission checks and
bounded verifier scheduling next, retaining full consensus verification, per-transition branch tips,
state/audit oracles, rollback/recovery, and deterministic overload behavior.

Exit criterion: real wallets and three nodes prove valid transitions, invalid mutation rejection,
rollback, recovery, fee/supply correctness, and bounded runtime.

### Step 3 — build valid-proof DoS and performance qualification

Tasks:

- Separate cold and warm measurement processes.
- Exercise every accepted circuit shape at its fixed `k`.
- Run concurrent valid submissions, duplicate submissions, invalid-proof floods, and mixed RPC/P2P
  load.
- Measure queue latency, verification count, cache hit/miss, CPU, RSS, disk, and node liveness.
- Add strict admission/backpressure only from measured evidence; never skip consensus verification.
- Test cache initialization races and bounded entry counts.

Exit criterion: published revision-bound benchmark and load report with explicit safe operating limits
and no consensus divergence or uncontrolled memory growth.

### Step 4 — migration/incident automation

Tasks:

- Snapshot and independently calculate pre-migration supply.
- Execute bridge, transfer, partition, reorg, rollback, restart, and recovery.
- Collect chronological logs, block hashes, roots, supply audits, and process resource data.
- Produce a structurally valid local evidence template without pretending it is independently signed.
- Reproduce from artifacts in a clean directory.

### Step 5 — real Tor/I2P and historical compatibility

Run real proxy services, packet capture on all supported platforms, referral/churn attacks, and released
V4 binary compatibility. Do not relax proxy fail-closed behavior to make a scenario pass.

### Step 6 — long fuzzing, hardware, and platform qualification

- Run compiler, envelope, state, RPC, Dandelion, and snapshot campaigns.
- Record seeds and minimize every failure.
- Measure RandomX on native x86-64 and ARM64 hardware.
- Perform real hardware-wallet signing/recovery acceptance.
- Complete clean-clone Linux/macOS/Windows CI.

### Step 7 — freeze, audit, public soak, reproduce, drill, govern

Freeze one commit only after repository work passes. Then complete the external gates in their enforced
order. Any code change after freeze creates a new candidate revision and invalidates revision-bound
evidence that no longer applies.

## 17. Validation command matrix

Use separate build directories. Adjust executable layout for the chosen CMake generator.

### 17.1 Preliminary integrity

```powershell
git status --short --branch
git diff --check
python -m py_compile tests\network\test_onyx_qualification_process.py
python tools\release\verify_dependencies.py
```

### 17.2 ZK-enabled C++

```powershell
cmake -S . -B build-onyx -DONYX_ZK=ON
cmake --build build-onyx --config Release --target tests bytecoind walletd minerd
.\build-onyx\artifacts\bin\tests.exe --jade
.\build-onyx\artifacts\bin\tests.exe --zk
```

Do not report the full `--zk` suite as passing unless it reaches its final success exit. Record the
last completed stage and timeout/interrupt separately if it is bounded.

### 17.3 Non-ZK C++

```powershell
cmake -S . -B build-nozk -DONYX_ZK=OFF
cmake --build build-nozk --config Release --target tests bytecoind walletd minerd
.\build-nozk\artifacts\bin\tests.exe --jade
.\build-nozk\artifacts\bin\bytecoind.exe --net=onyx
```

The final command must refuse before opening a qualification database or network connection.

### 17.4 Rust proof backend

```powershell
cargo check --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml
cargo test --release --locked --offline --manifest-path vendor\onyx-zk\Cargo.toml
```

Use a focused test filter during iteration, but run the full locked/offline suite before accepting a
cryptographic milestone.

### 17.5 Local three-node process qualification

```powershell
python tests\network\test_onyx_qualification_process.py `
  --bytecoind build-onyx\artifacts\bin\bytecoind.exe `
  --minerd build-onyx\artifacts\bin\minerd.exe `
  --walletd build-onyx\artifacts\bin\walletd.exe `
  --revision working-tree `
  --report build-onyx\onyx-qualification.json
```

### 17.6 Compiler and SDKs

```powershell
python -m unittest discover -s tests\onyx_compiler -p "test_*.py"
python -m unittest discover -s sdk\onyx\python -p "test_*.py"
node sdk\onyx\typescript\test.mjs
cargo test --locked --offline --manifest-path sdk\onyx\rust\Cargo.toml
```

Read each SDK README for packaging verification in addition to unit tests.

### 17.7 Release tooling

```powershell
python -m unittest discover -s tests\release -p "test_*.py"
python tools\release\verify_dependencies.py
python tools\release\verify_release_gates.py
```

`verify_release_gates.py` is expected to report incomplete external gates until real evidence exists.
Expected incompleteness is success only when the verifier rejects missing evidence for the correct
reason; a crash or acceptance of placeholders is a failure.

### 17.8 Fuzzing/sanitizers

Follow `docs/Onyx-Fuzzing.md` exactly. A typical Linux configuration is:

```text
cmake -S . -B build-fuzz -DSANITIZE=fuzzer,address,undefined -DONYX_ZK=ON
```

Store campaign metadata outside release evidence until an independent operator attests it.

## 18. Rules another AI must not weaken

Another AI or developer must not:

- Fabricate, backdate, or self-sign external release evidence.
- Lower required auditor, builder, platform, node, duration, block, or governance thresholds.
- Mark an interrupted or timed-out test as passed.
- Re-enable a standalone Jade V5/V6 production interval.
- Separate RandomX and Onyx activation heights.
- Enable Onyx consensus in `ONYX_ZK=OFF` builds.
- Replace Halo2 consensus verification with the toy prover/verifier.
- Add runtime mainnet activation overrides.
- Accept unknown/user-generated circuits without reviewed activation.
- Download floating cryptographic dependencies or alter pinned dependencies without review.
- Remove canonical decoding, bounds, domain separation, network binding, authorization, or fail-closed
  checks just to make tests pass.
- Log seeds, spend keys, passwords, auth tokens, full sensitive requests, or raw wallet files.
- Mix user-owned staged files into implementation commits.
- Claim this project is unbreakable, foolproof, fully trustless, audited, or production-ready before
  the evidence supports that wording.

## 19. Suggested task template for another AI tool

Give the AI one bounded milestone at a time. A useful prompt structure is:

```text
Repository: Bytecoin fork, branch kimiK3/jade-onyx-hardening.
Read PROJECT_PROGRESS_AND_IMPLEMENTATION_GUIDE.md and the authoritative protocol documents it names.

Task: <one concrete milestone>
Files initially in scope: <explicit paths>
Security invariants: <specific fail-closed, supply, privacy, and compatibility rules>
Tests required: <exact commands and expected results>
Non-goals: <external gates or unrelated refactors>

Before editing, report git status and reconcile existing changes. Preserve staged
Bytecoin_Onyx_Security_Review.md and unrelated .gitignore changes. Use explicit commit paths.
Do not weaken consensus checks or fabricate evidence. Report implemented, tested, and untested work
separately. Stop if protocol prose and consensus code disagree.
```

Recommended task sizes:

- One circuit/cache review.
- One process scenario (deployment, issuance, token transfer, or one standard profile).
- One deterministic state-model campaign.
- One proxy platform.
- One release-evidence schema/tool.

Avoid a single prompt such as “finish the entire cryptocurrency”; it makes security boundaries,
review, test evidence, and regressions difficult to track.

## 20. Definition of done

The full project is done only when all of the following are true for one frozen revision:

1. Current native-transfer work and standard-program process qualification are committed and pass
   clean-clone hosted CI.
2. ZK and non-ZK build/test matrices pass on every supported platform.
3. Full proof, consensus, wallet, compiler, SDK, network, migration, sanitizer, fuzz, recovery, and
   reproducibility suites pass without unexplained interruption.
4. Valid-proof performance/DoS limits are measured and enforced without weakening verification.
5. Real Tor/I2P, packet-capture, RandomX hardware, historical compatibility, and hardware-wallet
   qualification are complete.
6. Two independent audits cover every required security domain and leave no unresolved critical/high
   issue.
7. The public three-operator, 14-day, 10,000-block qualification converges with exact supply evidence.
8. Required platform binaries reproduce with two independent builders each.
9. The incident drill completes with independent observation and clean-room reproduction.
10. Governance approves the exact revision and co-scheduled heights after every prerequisite gate.

Until then, the accurate description is: **a substantial security and shielded-protocol implementation
under active qualification, not a production release**.
