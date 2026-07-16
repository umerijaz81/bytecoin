# Onyx (V6): Programmable Privacy Protocol — Architecture & Migration Design

> **Status:** authoritative design. This document defines the target protocol for overhauling
> Bytecoin into a programmable privacy coin. It is the spec the multi-phase implementation executes
> against. No production ZK code is written here — consensus-critical cryptography is vendored from
> peer-reviewed implementations and audited before activation (the same rule that governs the Jade
> work in `JADE_UPGRADE.md`).

## 1. The decision and why

A genuinely *programmable privacy* coin cannot be built on CryptoNote. CryptoNote's model — one-time
output keys, ring signatures, no accounts, no persistent mutable state — is structurally hostile to
programs: there is nowhere for application state to live and no way to constrain how it evolves. Every
production programmable-privacy chain (Zcash's shielded protocol, Aztec, Aleo, Namada) instead uses a
**zero-knowledge note/commitment model**: private state lives in a Merkle tree of commitments, and
state transitions are proven correct in zero knowledge.

Per the architecture decision, Onyx adopts that model on a **Halo2 / PLONKish** proving stack. This
*retires the CryptoNote cryptographic core* (ring signatures, one-time keys, key images) while
**reusing Bytecoin's peripheral infrastructure** (P2P, database, serialization, RPC, and the Jade-era
hardening: Dandelion++, RandomX, config plumbing, the batch-verification path). Onyx is therefore best
understood as a **new protocol (block/tx version 6) that ships inside the existing node**, with a
bridge from the legacy chain — not a fork of CryptoNote semantics.

Naming continues the gemstone line: Amethyst (V4) → Jade (V5) → **Onyx (V6)**.

## 2. State model

Three structures define consensus state; the first two replace CryptoNote's output set + key-image
set, the third is what makes the chain programmable.

- **Note commitment tree** — an append-only, fixed-depth incremental Merkle tree (Zcash Orchard-style)
  over a ZK-friendly hash (Sinsemilla / Poseidon). Each leaf is a commitment to a *note*. Only the
  root(s) ("anchors") and the frontier are needed for consensus; full nodes keep recent roots so
  spenders can prove membership against a recent anchor.
- **Nullifier set** — the set of spent-note nullifiers. A nullifier is a PRF of (note, spending
  authority) that is unlinkable to the commitment but unique per note. Inserting a nullifier that
  already exists is a double-spend and is rejected. This is the structural successor to key images
  (the uniqueness guarantee we verified at `src/Core/BlockChainState.cpp:56,167,734`).
- **A note** carries: an asset/program id, a value (homomorphic commitment), an owner address, a
  randomness/rho field, and an **arbitrary application-state payload** (bytes / a state commitment).
  The payload is what lets a note represent a token balance, an NFT, or contract storage — the basis
  for programmability.

Consensus state in the DB (reuse `src/platform/DB*`): the commitment tree frontier + a ring buffer of
recent anchors, the nullifier set, and the program/verifying-key registry (§5).

## 3. Transaction model

An Onyx transaction is an **action bundle**: a list of *spends* (input notes, each contributing a
nullifier + a membership proof against an anchor) and *outputs* (new note commitments), accompanied by
**one ZK proof** that the whole bundle satisfies:

1. **Value balance** — committed input value − output value − fee = 0 (Pedersen/homomorphic), per
   asset id. (Generalizes Jade's confidential-amount balance check.)
2. **Ownership / authorization** — each spend is authorized by the note's spending key (spend
   authorization signature, RedDSA-style, bound into the proof).
3. **Membership** — each input note's commitment is in the tree at the referenced anchor.
4. **Nullifier correctness** — each nullifier is correctly derived from its note.
5. **Program predicate (§5)** — the application circuit(s) for the involved asset/program ids accept
   the transition.

Default is **shielded-only**. A transparent **bridge pool** (one- or two-way "shield/deshield") exists
for migration and exchange liquidity, and is the only place values are ever in the clear.

## 4. Cryptographic stack (Halo2 / PLONKish)

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Proof system | **Halo2 (PLONKish, IPA)** | No trusted setup; recursion/accumulation for scaling; battle-tested in Zcash Orchard. |
| Curve | **Pasta cycle (Pallas/Vesta)** | Supports efficient recursion (the cycle), no pairings, Orchard-proven. (BN254 only if an EVM bridge is later required — handled by a separate bridge, not the core.) |
| In-circuit hash | **Poseidon** (state) / **Sinsemilla** (tree) | ZK-friendly; minimal constraints. |
| Value commitment | Homomorphic Pedersen over Pallas | Enables the in-the-clear balance check on commitments. |
| Note encryption | Ephemeral-key + **ChaCha20-Poly1305** | In-band secret distribution (Zcash-style); reuse `src/crypto/chacha.*`. |
| Spend authorization | **RedDSA** (re-randomizable) | Unlinkable per-spend authorization keys. |
| Key hierarchy | Spend key → nullifier key + **viewing keys** (incoming/outgoing/full) | Selective disclosure & auditability without spend power (supersedes the legacy view-key model). |
| Non-circuit hash / PoW | Keccak; **RandomX** (Jade Phase 5) | Unchanged where ZK isn't needed; PoW stays laptop-mineable. |

**Quantum posture (honest).** Halo2/Pasta security rests on discrete log — it is **not** post-quantum,
the same caveat as essentially all deployed programmable-privacy chains. A STARK/hash-based backend is
the PQ-friendlier path but the privacy-circuit ecosystem is less mature. Onyx therefore keeps a
**proof-system abstraction** (`§7`, the `IProofSystem` seam) so a STARK/PQ proving backend can be added
later without touching the state machine — this is the concrete continuation of finding Q-1. Onyx is
*quantum-agile*, not quantum-proof; the docs must say exactly that.

## 5. Programmability model

Onyx programmability follows the **Aztec/Aleo private-function model**, not the EVM shared-state model,
because shared mutable state is fundamentally at odds with privacy.

- A **program** is a set of ZK circuits ("functions") plus a **verifying key**, registered on-chain by
  id (the program/verifying-key **registry** in consensus state). A note tagged with a program id may
  only be created/spent by a transaction carrying a valid proof for one of that program's functions.
- **Private execution (default):** the user runs the program circuit **client-side**, producing a
  proof; the chain only verifies it. State is the user's own notes (token balances, NFTs, app data).
  This gives full-privacy smart contracts (private tokens, private DEX order notes, private identity).
- **Shared/public state (opt-in):** for the minority of applications that need shared mutable state
  (e.g. a public AMM pool), Onyx provides a public state tree updated by proven transitions, with the
  explicit, documented privacy tradeoff. Kept deliberately secondary.
- **Composability:** a transaction may invoke multiple functions; recursion (Halo2 accumulation) lets
  one proof attest to a call tree, enabling private contract-to-contract calls.

**Developer surface.** Writing raw Halo2 circuits is not a viable public API. The plan is a high-level
language compiled to PLONKish circuits. Options, in order of preference:
1. Adopt/port an existing frontend (e.g. an **ACIR→Halo2** backend, or a Leo-like DSL) so app authors
   write ordinary code, not constraints.
2. Ship an audited **standard library** of circuits (fungible token, NFT, vesting, multisig,
   shielded swap) so most users never write a circuit.
A custom circuit compiler is itself a multi-quarter sub-project and must not block the value-transfer
phases.

The fail-closed v1 language, canonical IR, resource-analysis and deterministic-key boundary is defined
in `docs/Onyx-Compiler-Specification.md`. That document is a prerequisite specification, not an
activation claim; the current implementation still accepts only compiled-in reviewed programs.

## 6. Consensus & node integration

What is **reused** vs **replaced**:

| Subsystem | Disposition |
|-----------|-------------|
| P2P / Levin protocol (`src/Core/Node*`, `src/p2p`) | Reuse; add Dandelion++ (Jade Phase 1) and Onyx tx/proof messages. |
| Database (`src/platform/DB*`) | Reuse; new column families for tree frontier, anchors, nullifiers, program registry. |
| Serialization (`src/seria`, `ser_members`) | Reuse; add Onyx tx/proof types via the existing **version-dispatch seam** at `ser_members(TransactionSignatures)` (`src/CryptoNote.cpp:240`) and `ser_members(OutputKey)` (`:279`). |
| Batch verification (`src/Core/Multicore.cpp`, `m_ring_checker`) | **Re-target**: the ring-signature batch becomes a **proof-verification batch** (`IProofSystem::verify`). Same threading model. |
| Block validation (`validate_tx_semantic`, `redo_block`) | **Replace** the ring/amount logic with: verify each tx proof against a recent anchor; check+insert nullifiers; append output commitments; advance the tree root. The Jade ring-size and confidential-amount rules become a transitional/legacy path. |
| PoW (`src/crypto/slow-hash*`, `hash.hpp`) | Reuse; RandomX (Jade Phase 5). PoS is a possible later governance decision, out of scope here. |
| RPC / wallet (`src/Core/Wallet*`, `rpc_api`) | Heavy changes: wallet scans with viewing keys, builds note witnesses, runs the prover; new RPC for proofs/programs. |
| CryptoNote core (`src/crypto/crypto.cpp` ring sigs, key images, stealth addr) | **Retired** for V6 (kept only to validate the legacy chain and the bridge). |

Block validation flow (Onyx):
```
for each tx in block:
    require tx.anchor in recent_roots
    verify_proof(program_vk_set, tx.bundle, tx.proof)        # batched in Multicore
    for nf in tx.nullifiers: require nf not in nullifier_set  # double-spend guard
    for nf in tx.nullifiers: nullifier_set.insert(nf)
    for cm in tx.commitments: tree.append(cm)
recompute/anchor tree.root()
```

## 7. Scaffolding seam (this branch)

A concrete anchor for the integration is committed alongside this doc:
`src/Core/zk/IProofSystem.hpp` — an abstract proof backend (`verify` / `verifying-key` types) and a
brief README. It is intentionally **not wired into the build** yet (so it cannot break compilation); it
fixes the interface the Halo2 backend and the consensus state machine will meet at, and the place a
future STARK/PQ backend slots in.

## 8. Migration from Jade

- **V6 "Onyx" hard fork**, gated at a future `UPGRADE_HEIGHT_V6` using the exact mechanism we used for
  Jade (`upgrade_heights` in `src/Core/Currency.cpp`, version constants in `src/CryptoNoteConfig.hpp`).
- **Dual state during transition:** legacy CryptoNote/Jade UTXOs remain spendable; a **bridge** shields
  legacy coins into the Onyx note tree (deshield back if a two-way bridge is chosen). New issuance and
  programs are Onyx-native. Legacy transfer is eventually deprecated by governance.
- The implemented one-way bridge deliberately discloses the migrated legacy amount and amount-stack
  index. A one-member CryptoNote ownership proof consumes its key image while Halo2 proves that the
  encrypted native Onyx note contains exactly that amount less the explicit miner fee. Both state
  changes share the block delta and undo snapshot; there is no deshield path in this phase.
- The Jade work (consensus ring-size enforcement, confidential amounts, Dandelion++, RandomX) is **not
  wasted**: it both hardens the chain users live on until Onyx is ready, and several pieces
  (confidential-amount commitments, the batch-verify path, the version seam, Dandelion++, RandomX)
  carry directly into Onyx.

## 9. Phased roadmap (each phase: testnet-first, external audit before mainnet height is set)

| Phase | Deliverable | Analogue |
|-------|-------------|----------|
| **O0** | Proof-system abstraction (`IProofSystem`) + vendored Halo2 backend harness; Poseidon/Sinsemilla + Pasta vendored and unit-tested | infra |
| **O1** | Note commitment tree + nullifier set + note format + encryption; **shielded value transfer only** (no programs) | Zcash Sapling/Orchard equivalent on Bytecoin infra |
| **O2** | Key hierarchy + viewing keys + wallet (scan, witness, prove, send) | Orchard wallet |
| **O3** | Legacy→Onyx **bridge** (shield/deshield) | transition |
| **O4** | **Programmability**: program/verifying-key registry, app/asset notes, standard circuit library (token, NFT, swap) | Aztec/Aleo private functions |
| **O5** | Developer language/compiler (ACIR→Halo2 or Leo-like) + SDK | Noir/Leo |
| **O6** | Recursion/scaling (Halo2 accumulation), optional public-state layer, PQ-agility backend | scaling + Q-1 |

## 10. Effort, team, and the non-negotiables

This is a **multi-quarter program requiring applied cryptographers**, not a one-person sprint. The
hard, unavoidable constraints:
- **No hand-rolled consensus crypto.** Vendor peer-reviewed Halo2/Poseidon/Sinsemilla; commission
  **external audits** of the protocol and every circuit before it gates value on mainnet.
- **Testnet/stagenet first** for every phase (`upgrade_heights={1,...}` activation), mainnet heights set
  only post-audit.
- **Honest claims.** Onyx targets best-in-class *programmable privacy*; it is **not** "unbreakable" and
  **not** quantum-proof — only quantum-agile. Overclaiming is itself a failure mode.

## 11. Acceptance criteria (per phase, summarized)

- O1: a shielded transfer testnet where amounts, sender, and receiver are hidden; double-spends
  (duplicate nullifiers) rejected; proofs batch-verify within a laptop node's budget.
- O4: a private fungible-token program deployable and transferable end-to-end with client-side proving.
- All phases: reproducible builds, circuit test vectors, and a written audit sign-off before any
  mainnet activation height is committed.
