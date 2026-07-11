# Onyx protocol implementation specification

Status: draft consensus specification. Constants and encodings are frozen for development only.
Mainnet activation is prohibited until independent cryptographic and consensus audits approve a
versioned release of this document.

## 1. Safety model

Onyx V6 is a new shielded protocol carried by the Bytecoin node. It does not claim perfect,
unbreakable, or post-quantum security. Consensus fails closed on unknown versions, proof backends,
programs, encodings, and resource-limit violations.

Consensus invariants:

1. Every accepted spend references a retained anchor.
2. Every nullifier is canonical, unique within its transaction, and absent from chain state.
3. Every note commitment occupies exactly one deterministic leaf index.
4. The proof binds the network, version, anchor, ordered spends and outputs, fee, programs, and expiry.
5. Applying then undoing a block restores identical shielded state.
6. Explicit limits apply before allocations or expensive cryptography.

## 2. Canonical primitives and domains

- Scalars and field elements are exactly 32 canonical little-endian bytes.
- Hashes and identifiers are exactly 32 bytes.
- Integers use canonical unsigned varints and reject non-minimal forms.
- Lists preserve wire order; consensus hashes never sort implicitly.
- Network id and protocol version occur in every consensus transcript.

| Purpose | Domain |
|---|---|
| Note commitment | `bytecoin.onyx.v6.note` |
| Nullifier | `bytecoin.onyx.v6.nullifier` |
| Merkle leaf | `bytecoin.onyx.v6.merkle.leaf` |
| Merkle node | `bytecoin.onyx.v6.merkle.node` |
| Transaction sighash | `bytecoin.onyx.v6.tx` |
| Proof transcript | `bytecoin.onyx.v6.proof` |
| Key derivation | `bytecoin.onyx.v6.keys` |
| Note encryption | `bytecoin.onyx.v6.note-encryption` |
| Program id | `bytecoin.onyx.v6.program` |

No domain constant may be reused for another purpose.

## 3. Consensus objects and development limits

- Merkle depth: 32.
- Retained anchors: 100 blocks, including intermediate transaction roots.
- Maximum transaction bytes: 256 KiB; proof: 192 KiB.
- Maximum spends: 16; outputs: 16; distinct programs: 8.
- Maximum encrypted note payload: 4 KiB per output.
- Maximum expiry distance: 100 blocks.

`OnyxNotePlaintext` contains: format version, network id, program id, asset id, unsigned 64-bit
value, owner diversifier, owner transmission key, rho, randomness, memo length, and memo. Value is
private witness data and never serialized in the public transaction.

`OnyxOutput` contains a note commitment, ephemeral encryption key, encrypted note ciphertext, and
outgoing-view ciphertext. `OnyxSpend` contains a nullifier and randomized spend-authority key.
Membership paths, note plaintexts, spending keys, and randomness remain private witnesses.

`OnyxTransaction` contains: version, network id, anchor, expiry height, fee, ordered spends, ordered
outputs, ordered program calls, proof backend id, proof, and binding signature. Its id commits to the
complete canonical encoding, including ciphertext and proof.

## 4. State transition

Before proof verification, reject malformed or oversized objects, expiry violations, stale anchors,
duplicate nullifiers, non-canonical elements, unsupported backends, and unregistered programs.

Proof public inputs canonically encode:

`network_id || tx_version || anchor || expiry_height || fee || spends || outputs || program_calls`.

After a valid proof and binding signature:

1. Recheck nullifiers against block delta and persistent state.
2. Insert nullifiers into the delta in transaction order.
3. Append output commitments in transaction order.
4. Record intermediate roots for intra-block spends and retain the final root.
5. Commit the delta atomically with the block.

Undo data stores inserted nullifiers, previous frontier, evicted anchors, program changes, and prior
root. Reorganization tests compare serialized state before apply and after undo byte-for-byte.

## 5. Base transfer circuit

The circuit proves note membership, correct nullifiers, spend authorization, 64-bit value ranges,
per-asset conservation, output commitment construction, and registered program predicates. For the
native asset, `sum(inputs) = sum(outputs) + fee`. A binding signature covers the transaction sighash
and net value-commitment balance. The toy O0 verifier is forbidden on consensus paths.

## 6. Keys and encryption

The master seed derives separate spend, nullifier, incoming-view, outgoing-view, and diversifier keys
with explicit network and key-type separation. Incoming keys discover received notes; outgoing keys
recover sent-note metadata; full viewing keys combine both without spend authority.

Note encryption uses an audited AEAD with unique ephemeral keys. Associated data binds network id,
transaction preimage, output index, commitment, and ephemeral key. Wallets never mark a note
spendable before its commitment is confirmed in the canonical tree.

## 7. Programs

`ProgramId = H(domain_program || manifest || verifying_key_hash)`. Registry entries include version,
backend, verifying-key hash/bytes, public-input schema hash, maximum cost, activation height, and
optional deactivation height. Unknown or inactive programs fail closed. Initial audited programs are
native transfer, fungible asset, NFT, vesting, multisignature custody, and atomic swap.

## 8. Fork and migration

- V6 activates only at `UPGRADE_HEIGHT_V6`; earlier blocks reject V6 objects.
- Mempool policy evaluates the next block version.
- The bridge consumes a legacy output once and creates equal native Onyx value minus explicit fee.
- Bridge nullifiers bind the legacy outpoint to prevent replay.
- Deshielding, if enabled, is a separate audited circuit and explicit public output.
- Reorganizations across activation clear and deterministically rebuild the mempool.
- Mainnet activation constants remain unreachable placeholders until audit sign-off.

## 9. Resource accounting

Cheap checks precede cryptography. Proof cost, verifying-key bytes, ciphertext bytes, state writes,
and tree appends contribute to weight and fees. Blocks cap aggregate proof bytes/count, nullifiers,
outputs, program calls, and verification cost. Failed batch verification must preserve attribution or
safely retry individual proofs.

## 10. Phase gates

| Phase | Exit gate |
|---|---|
| O0 | Exact pins; committed Cargo vendor tree; locked offline build; panic-safe bounded FFI; three-platform CI; KAT, malformed-input, sanitizer, and fuzz tests. |
| O1 | Canonical objects, tree, anchors, nullifier set, apply/undo, persistence and reorg vectors. |
| O2 | Transfer circuit, binding signature, negative vectors, benchmark budgets, independent review. |
| O3 | Wallet derivation, scanning, witnesses, proving, recovery, backups, RPC and devnet transfer. |
| O4 | One-way legacy shield bridge, supply invariants, migration tools, replay/reorg tests and supply audit. |
| O5 | Program registry, resource accounting, audited standard programs and SDK tests. |
| O6 | Dandelion++, proxy transport, RandomX transition, backend agility, reproducible release and operational testnet. |
| Release | Two independent audits, no unresolved critical/high findings, public testnet soak, signed reproducible builds, incident/rollback plan, and governance approval. |

## 11. Required tests

Every object requires canonical round-trip, truncation, trailing-data, non-minimal, oversize,
duplicate, unknown-version, and cross-network tests. State transitions require apply/undo,
crash-recovery, reorg, duplicate-nullifier, stale-anchor, intra-block-anchor, and deterministic-root
vectors. Circuits require valid vectors plus independently mutated public inputs, witnesses, proofs,
signatures, commitments, nullifiers, fees, programs, and ciphertext bindings.

