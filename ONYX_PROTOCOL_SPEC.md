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
| Note commitment | Poseidon fixed-length tag `4` |
| Nullifier | Poseidon tag `3` |
| Merkle leaf | Poseidon tag `1` |
| Merkle node | Poseidon tag `2` |
| Transaction sighash | `bytecoin.onyx.v6.tx` |
| Proof transcript | `bytecoin.onyx.v6.proof` |
| Key derivation | `bytecoin.onyx.v6.keys` |
| Note encryption | `bytecoin.onyx.v6.note-encryption` |
| Program id | `bytecoin.onyx.v6.program` |

The native asset identifier is
`SHA-256("bytecoin.onyx.v6.native-asset") = 7d3423482b6e8a242fc0e5a2f6a54b36cf4f0342a953ea93ec7025cd7c955be3`.

No domain constant may be reused for another purpose.

## 3. Consensus objects and development limits

- Merkle depth: 32.
- Retained anchors: 100 blocks, including intermediate transaction roots.
- Maximum transaction bytes: 256 KiB; proof: 192 KiB.
- Maximum spends: 16; outputs: 16; distinct programs: 8.
- Maximum encrypted note payload: 4 KiB per output.
- Maximum expiry distance: 100 blocks.

`OnyxNotePlaintext` contains: format version, network id, program id, asset id, unsigned 64-bit
value, owner diversifier, owner transmission key, RedPallas spend-authority key, rho, randomness,
memo length, and memo. Value is private witness data and never serialized in the public transaction.
The Poseidon note commitment binds every consensus field through fixed 31-byte field packing, except
that the canonical spend-authority encoding is decoded and committed as its affine `(x, y)` field
coordinates. Invalid or identity authority points are rejected. Memo bytes are excluded from the
consensus commitment and instead integrity-protected by the authenticated note ciphertext.

`OnyxOutput` contains a note commitment, non-identity value commitment, ephemeral encryption key,
encrypted note ciphertext, and outgoing-view ciphertext. `OnyxSpend` contains a nullifier,
non-identity value commitment, and randomized spend-authority key. The
spent commitment remains a private witness shared directly between note-opening and Merkle-path
constraints.

Value commitments use `cv = [value]V + [rcv]R`, where
`V = hash_to_curve("bytecoin.onyx.v6.value-commitment", "v")` and `R` is the frozen Orchard
RedPallas binding generator. Their canonical compressed encodings are public; values and trapdoors
remain private. Identity and non-canonical commitment encodings fail before proof verification.
For native notes, `rcv` is the note plaintext randomness field. The note commitment binds it and
authenticated encryption delivers it to the recipient, so every received note includes the
value-commitment opening required for a later spend.

The binding signing key is `bsk = sum(rcv_inputs) - sum(rcv_outputs)`. Verifiers derive
`bvk = sum(cv_inputs) - sum(cv_outputs) - [fee]V`; circuit-enforced balance cancels the value terms,
so `bvk = [bsk]R`. A RedPallas Binding signature over a separately domain-separated digest of the
complete transaction preimage, backend identifier, and proof is mandatory and follows the ordered
spend signatures in the authorized wire encoding.
Membership paths, note plaintexts, spending keys, and randomness remain private witnesses.

`OnyxTransaction` contains: version, network id, anchor, expiry height, fee, ordered spends, ordered
outputs, ordered program calls, proof backend id, proof, and binding signature. Its id commits to the
complete canonical encoding, including ciphertext and proof.

## 4. State transition

Before proof verification, reject malformed or oversized objects, expiry violations, stale anchors,
duplicate nullifiers, non-canonical elements, unsupported backends, and unregistered programs.

Proof public inputs canonically encode:

`network_id || tx_version || anchor || expiry_height || fee || spends || outputs || program_calls`.

The base-transfer proving system uses a versioned circuit family keyed by the public
`(spend_count, output_count)` pair. Each member has an immutable shape and verifying-key identifier;
counts outside `1..=16` fail before key selection. Within a member, the instance layout is fee;
one shared anchor followed by ordered nullifiers; ordered output commitments; and ordered affine
`(rk_x, rk_y)` randomized-authority coordinates; ordered input value-commitment coordinates; then
ordered output value-commitment coordinates. The ECC range table is loaded once and shared by all
slots.

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

The base-transfer circuit is native-only: both asset limbs in every input and output note commitment
are constrained to the frozen native identifier. Generalized assets use separately registered
program circuits and may not enter the native balance equation.

Spend authorization is prepared before proving: a private base-field randomizer is converted
canonically into a Pallas scalar, `rk = ak + [alpha] SpendAuthG` is written into the transaction, the
proof binds `rk` to the private `ak` committed in the spent note, and only then does the randomized
RedPallas key sign the final transaction-and-proof digest.

## 6. Keys and encryption

The master seed derives separate spend, nullifier, incoming-view, outgoing-view, and diversifier keys
with explicit network and key-type separation. Incoming keys discover received notes; outgoing keys
recover sent-note metadata; full viewing keys combine both without spend authority.

The canonical full-viewing-key encoding is versioned and contains the network id, incoming and
outgoing viewing secrets, diversifier derivation key, nullifier key, and public spend-authority key.
It never contains the spend scalar. Full and view-only scanners consume this same encoding, yielding
identical addresses, note recovery, nullifier detection, commitment roots, and witnesses.

Note encryption uses an audited AEAD with unique ephemeral keys. Associated data binds network id,
transaction preimage, output index, commitment, and ephemeral key. Wallets never mark a note
spendable before its commitment is confirmed in the canonical tree.

The transaction encryption-binding digest is SHA-256 over its domain plus version, network, anchor,
expiry, fee, ordered spends, ordered `(note commitment, value commitment)` output pairs, and program
calls. Ephemeral keys and ciphertext bytes are excluded to avoid a construction cycle; the AEAD
associated data binds both separately with the digest and output index. Bridge envelopes use the
equivalent bridge-specific digest over their stable legacy statement and sole output commitments.

## 7. Programs

`ProgramId = H(domain_program || manifest || verifying_key_hash)`. Registry entries include version,
backend, verifying-key hash/bytes, public-input schema hash, maximum cost, activation height, and
optional deactivation height. Unknown or inactive programs fail closed. Initial audited programs are
native transfer, fungible asset, NFT, vesting, multisignature custody, and atomic swap.

## 8. Fork and migration

- Onyx protocol and transaction format V6 activate only at `UPGRADE_HEIGHT_ONYX`; earlier blocks
  reject V6 objects. Core block major version 6 is reserved by collective-mining builds, so two
  simultaneous upgrade entries skip directly from Jade block V5 to Onyx block V7.
- Mempool policy evaluates the next block version.
- The bridge consumes a legacy output once and creates equal native Onyx value minus explicit fee.
- A bridge publicly identifies one legacy output by `(amount, amount-stack-index)`, carries its
  key image, and includes a one-member CryptoNote ring signature over the complete bridge proof
  statement. Consensus resolves the exact legacy public key, verifies the signature/key-image
  relation, and records that key image in the ordinary legacy spent set atomically with appending
  the bridged note. Thus bridge-vs-legacy and bridge-vs-bridge replay use the same spent-state rule.
- The bridge Halo2 circuit proves `legacy_amount = hidden_native_note_value + explicit_fee`, binds
  the network, constructs the sole output note commitment, and binds the same value to its public
  value commitment. It cannot create transparent outputs or deshield value.
- Deshielding, if enabled, is a separate audited circuit and explicit public output.
- Reorganizations across activation clear and deterministically rebuild the mempool.
- Mainnet activation constants remain unreachable placeholders until audit sign-off.

## 9. Resource accounting

Cheap checks precede cryptography. Proof cost, verifying-key bytes, ciphertext bytes, state writes,
and tree appends contribute to weight and fees. Blocks cap aggregate proof bytes/count, nullifiers,
outputs, program calls, and verification cost. Failed batch verification must preserve attribution or
safely retry individual proofs.

The version-2 consensus snapshot also commits rollback-safe public supply counters. A bridge adds
its disclosed legacy amount to `total_bridged`, adds its fee to `total_fees`, and increases
`circulating_supply` by `legacy_amount - fee`. A transfer adds its fee to `total_fees` and reduces
circulating supply by that fee. Decoding rejects any snapshot that does not satisfy
`circulating_supply = total_bridged - total_fees`. Empty version-1 snapshots migrate with zero counters.
Nodes expose these values, the commitment count/root, and block height through
`get_onyx_supply_audit` for independent reconciliation. Only an empty version-1 activation
snapshot upgrades directly; a nonempty version-1 snapshot has no trustworthy historical counters
and must be rebuilt by deterministic chain replay.

Version-3 snapshots append the canonical program/verifying-key registry. Version-2 accounting
snapshots migrate with an empty registry. Native transfer and bridge circuits constrain note program
ids to the zero/native program and reject nonempty program-call lists until a registered,
function-specific proof verifier is available.

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
