# Bytecoin Jade/Onyx Project Progress and Implementation Guide

Last reconciled: **2026-08-04**  
Repository: `https://github.com/umerijaz81/bytecoin.git`  
Working branch: `kimiK3/jade-onyx-hardening`  
Committed revision at reconciliation: `dd9755e` (`Qualify independent Onyx transfers`)  
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
| O5 programs/compiler/SDKs | Substantially implemented | Real multi-process standard-program qualification is the next major code task |
| O6 network/PoW/release | Major components implemented | Real Tor/I2P, long soaks, platform measurements, audits, and ceremony remain |
| External release gates | Not complete | Must be independently performed; must never be fabricated in repository JSON |

## 2. Status vocabulary

Use these labels precisely in issues, commits, prompts, and future documentation:

- **Committed**: present at or before Git revision `dd9755e` on this branch.
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

At reconciliation, the worktree contains both user-owned changes and active implementation work:

```text
 M .gitignore
A  Bytecoin_Onyx_Security_Review.md
 M JADE_ONYX_PROJECT_HANDOFF.md
 M docs/Onyx-Qualification-Network.md
?? PROJECT_PROGRESS_AND_IMPLEMENTATION_GUIDE.md
```

Important ownership rules:

- `Bytecoin_Onyx_Security_Review.md` is already staged and belongs to the user. Do not edit, unstage,
  delete, overwrite, or include it in an unrelated commit.
- `.gitignore` is an unrelated local modification. Preserve it unless the user explicitly assigns it.
- Commit implementation files using an explicit path list or `git commit --only <paths...>`.
- Do not run `git add -A`, `git reset --hard`, broad checkout/restore commands, or destructive cleanup.
- Recheck `git status --short` before and after every commit.

This guide itself is a new documentation file and should be committed separately from cryptographic or
consensus changes unless the user deliberately requests a combined commit.

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

- Push `dd9755e` and the associated documentation, then verify hosted Ubuntu CI and retain its report.
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

Status: **substantially implemented; real end-to-end process qualification is the next major code phase**.

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

### Next implementation: standard-program process qualification

Extend `tests/network/test_onyx_qualification_process.py` after the independent-wallet transfer. Keep
the scenario deterministic and bounded.

Recommended order:

1. **Fund the actor wallets**
   - Preserve enough native shielded value for deployment and call fees.
   - If the preceding full-balance transfer consumes all sender value, split the transfer or add a
     dedicated funded program wallet.
   - Assert exact starting balances and node heights.

2. **Capped token deployment**
   - Call `create_onyx_program_deployment` through wallet RPC.
   - Reject a byte-tampered deployment on a different node.
   - Relay the valid transaction, mine it, and wait for all nodes and the wallet.
   - Query wallet/node program status and verify program ID, issuer, cap, activation, metadata, fee,
     and supply state.

3. **Private issuance**
   - Issue a bounded amount to an independent receiver.
   - Test wrong issuer, wrong sequence, zero amount, over-cap issuance, tampered proof, and duplicate
     pending issuance.
   - Mine and check token balance, sequence advancement, cap, native fee, and cross-node convergence.

4. **Private token transfer**
   - Transfer part of the issued asset to another independent wallet while paying native fees.
   - Check sender/receiver asset balances, native balance changes, pending nullifier reservation,
     tamper rejection, and confirmed replay rejection.

5. **Pinned standard deployments and calls**
   - Deploy NFT, vesting, multisig, and swap artifacts one at a time.
   - For each, exercise one valid state transition and its most important invalid transition.
   - Query `get_onyx_standard_program_state` before and after mining.
   - Force a short reorg and prove canonical state, wallet state, and mempool conflicts roll back.

6. **Evidence/report extension**
   - Add scenario names, program IDs, transaction hashes, heights, final state commitments, balances,
     fees, and supply audit to the local report.
   - Do not log seeds, passwords, raw spend keys, authorization signatures, or wallet auth tokens.
   - Keep the report labeled `local-ci-not-release-evidence`.

Acceptance criteria:

- All three nodes converge after every valid program transaction.
- Invalid and conflicting transactions are rejected before state mutation.
- Reorg/undo restores exact prior program roots, sequences, balances, supply, and mempool eligibility.
- Wallet recovery through another node reconstructs program and asset state.
- Native supply remains `bridged - all fees`; token supply never exceeds its program cap.
- The harness finishes within a documented CI budget after warm-up.

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

Status: **implemented, locally validated, and committed as `dd9755e`; documentation/push and hosted CI
verification remain.**

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

Remaining:

1. Commit the associated documentation separately.
2. Push the branch and inspect hosted CI logs and the uploaded non-release qualification report.

Exit criterion: clean scoped diff, local matrix passes, hosted Onyx qualification passes, and no
unrelated user file enters the commit.

### Step 2 — implement standard-program multi-process qualification

Follow the detailed scenario in section 12. Start with capped token deployment/issuance/transfer, then
the four pinned profiles, then reorg/recovery. Avoid combining all profiles into one opaque commit.

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
