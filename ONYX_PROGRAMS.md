# Onyx Program Registry and Execution Gate

The consensus snapshot contains a canonical, sorted program registry. Each immutable entry binds:

- a canonical manifest;
- proof backend identifier;
- activation and optional deactivation heights;
- ordered function identifiers;
- each function's verifying-key bytes, public-input schema hash, and maximum verification cost.

The program identifier is a domain-separated SHA-256 digest of the complete canonical entry. Registry
decoding recomputes every identifier, rejects duplicates and unsorted functions, bounds manifests,
verifying keys, functions, entries, total registry bytes, and aggregate call cost, and rejects trailing
or noncanonical data. Registration returns an undo delta and is serialized in version-3 Onyx
consensus snapshots.

## Current execution gate

The native transfer and bridge circuits are restricted to the zero/native program identifier. Native
transfer verification rejects any nonempty `programs` list before cryptographic verification.

The first executable standard program is `onyx.standard.private-fungible-token/v1`, using backend
`halo2-ipa-pasta-onyx-token-v1`. It provides the fixed transfer family `(1..=2 spends,
1..=2 outputs)`. Each shape has a distinct function id, schema hash, verification-cost ceiling, and
deterministic Halo2 VK descriptor. The descriptor commits to the vendored Halo2 pinned key, circuit
size, Merkle depth, and exact shape; the verifier regenerates that audited circuit and requires an
exact descriptor match before accepting the proof.

Token notes constrain both program-id limbs and both asset-id limbs to the called program id. The
circuit proves membership, nullifier correctness, spend authority, note openings, value commitments,
and `sum(inputs) = sum(outputs)`. Token transfers have zero native fee until a mixed native+program
bundle circuit is activated. The sole call's public-data hash is the canonical empty transfer payload.
Changing the program id, asset id, shape, schema, VK descriptor, activation height, or payload hash
invalidates verification.

Stateless semantic verification checks the compiled standard predicate so transactions can be parsed
and prevalidated. Snapshot-aware consensus application additionally requires the exact active registry
entry and enforces both per-transaction and cumulative per-block verification-cost limits before
changing nullifiers or the commitment tree. Mempool admission dry-runs the transition against the
current snapshot, preventing state-invalid or unregistered calls from being retained.

## Consensus deployment

Envelope type `2` deploys the compiled standard private-fungible-token family. The deployment contains
the canonical manifest, activation and optional deactivation heights, and an authorized native funding
transfer. That transfer must pay at least `100000` atomic units and contain exactly one reserved call
(`function_id = 0xffffffff`). The call binds the manifest, network, activation window, and recomputed
Program ID; changing any of them invalidates the spend and binding signatures.

The deployment must activate between the following block and 100,000 blocks after inclusion. Consensus
verifies the native Halo2 funding proof, consumes its nullifiers, appends its change commitments, charges
the fee, accounts 5,000,000 verification-cost units, and registers the program in one cloned snapshot.
Any failure commits none of those effects. Duplicate Program IDs are rejected both by state and by a
dedicated mempool conflict index, which is rebuilt on reorganization. Seed and view-only wallet scanners
scan the embedded funding transfer so change recovery remains identical to an ordinary native transfer.

## Capped private issuance

Mintable token manifests use canonical `ONXM` version-1 metadata containing a nonidentity RedPallas
issuer key, a positive `u64` maximum supply, and bounded printable metadata. Legacy manifests remain
transfer-only; a manifest beginning with `ONXM` must decode canonically or deployment fails. Mintable
programs add immutable one- and two-output issuance functions with shape-specific schema hashes and VK
descriptors.

Envelope type `3` contains a zero-spend, zero-fee authorized transaction, public issued amount and
monotonic sequence, private per-output values, an issuance Halo2 proof, a value-binding signature, and
a separate issuer signature. The proof constrains each encrypted output note and value commitment to
the called Program ID and proves that private output values sum to the public issued amount. Issuance
uses the distinct binding equation `issued*V - sum(outputs) = -sum(rcv)*R`; the ordinary transfer
equation remains unable to create value.

Snapshot version 5 stores a canonical sorted `(Program ID, issued supply, next sequence)` ledger.
Application requires the active registered issuance function, exact next sequence, retained anchor,
valid issuer/proof/binding signatures, and checked cumulative supply at or below the immutable cap.
Outputs and ledger updates commit atomically. The mempool permits at most one pending issuance per
Program ID and rebuilds that index after reorganizations. Full and view-only scanners recover issuance
outputs, while native status balances exclude them; exact `(Program ID, asset ID)` balance queries
prevent cross-asset unit confusion. The wallet builder derives the sequence/cap from a consensus
view reconstructed from accepted deployment and issuance envelopes before proving. Wallet snapshot
version 2 persists the bounded canonical registry and issuance ledger alongside notes and witnesses,
so walletd does not download or trust a daemon-supplied raw consensus snapshot. The
`create_onyx_token_issuance` RPC also checks issuer ownership, activation, expiry, remaining cap, and
pending same-program sequence conflicts.

Walletd exposes the same locally reconstructed public state through `get_onyx_program_status`. The
method reports the immutable issuer and cap, accepted issued and remaining supply, next consensus
sequence, activation window, and canonical metadata. Its `active` field is evaluated at the next
possible inclusion height. This is an introspection API only: builders and callers still fail closed
when the program is missing, inactive, unauthorized, over cap, or has a pending sequence conflict.

A program call becomes executable only after its audited function circuit supplies all of the
following:

1. a proof backend and verifier matching the registered verifying key;
2. public inputs matching the registered schema hash;
3. note program/asset identifiers constrained inside the circuit;
4. transaction-level binding of ordered calls and public-data hashes;
5. verification cost within the entry and block limits;

The generic program-context v1 foundation now supplies a canonical transaction projection, inclusion
window, optional private-state transition commitments, a fixed 22-field circuit ABI, and a frozen schema
hash. Contextual envelope version 1 canonically carries the authorized transaction and exactly one ordered
context per call. Its signed proof field is a bounded versioned bundle containing a named base proof and one
ordered program proof per context. `apply_contextual_transaction` validates all contexts before state mutation.
The verification API authenticates the complete bundle, dispatches a fixed native or single-program-asset base
proof, enforces registry activation and cost, regenerates the exact export-bound compiler descriptor, and checks
each ordered compiler proof over the 22-field context plus a public true result. Consensus C ABI activation and
standard-circuit audits have not landed, so the existing token-family dispatch remains the only activated program
path.

The four approved follow-on standards now share a versioned native application-data decoder. It derives typed
public suffixes for NFT identity/nonces, vesting schedules, multisig policy thresholds, and swap hashlock/timeout
branches. Every profile requires an authenticated changing state commitment, and timelocks are checked against
the context inclusion window validated by consensus. This closes the caller-supplied-height/state ambiguity at
the standard ABI boundary. Canonical source packages for all four profiles now lower through the real compiler
backend. NFT proves current-owner knowledge; vesting proves beneficiary knowledge and unlock height; multisig
reconstructs a fixed 16-slot, active-participant-distinct policy while counting action-bound approvals; swap separates preimage claim from
timed refund. Each package reproduces its export descriptor and passes a randomized positive proof plus a
policy-specific rejected witness. They remain outside the activated allowlist until deployment, wallet, audit
and testnet gates land.

Standard token programs also register eight fixed mixed-transfer shapes. Each proof composes an
independent token lane (one or two spends/outputs, zero fee, exact Program ID) with a native lane (one
or two spends, one change output, public miner fee). Transaction ordering is token spends then native
spends and token outputs then native change. One authorization transcript covers every nullifier,
commitment, program call, proof byte, and the fee. This permits normal miner fees without allowing
token value to offset native value or vice versa.

Only the standard token transfer, mixed native-fee transfer, and capped issuance functions currently
satisfy these consensus execution gates. Every other call continues to fail closed. Walletd now
constructs the canonical capped-token manifest, derives the issuer from its Onyx seed, funds the
deployment from shielded native notes, binds the reserved deployment call into both authorization
signatures, returns the Program ID, and reserves pending deployment nullifiers. SDK vectors are
included, while independent audit coverage remains required before the fungible-token phase is
eligible for production activation.

For offline integration, the bounded C ABI function `onyx_token_program_descriptor` constructs the
canonical `ONXM` policy manifest and previews the Program ID at consensus Merkle depth 32. The ID
commits to the activation window and exact standard function descriptors, so changing any input
changes the ID. This helper neither funds nor authorizes deployment; walletd remains the supported
deployment path. Canonical manifest and reduced-depth circuit vectors live in
`vendor/onyx-zk/test_vectors.md`.
