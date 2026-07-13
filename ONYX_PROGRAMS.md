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

A program call becomes executable only after its audited function circuit supplies all of the
following:

1. a proof backend and verifier matching the registered verifying key;
2. public inputs matching the registered schema hash;
3. note program/asset identifiers constrained inside the circuit;
4. transaction-level binding of ordered calls and public-data hashes;
5. verification cost within the entry and block limits;

Only the standard token-transfer functions currently satisfy these consensus execution gates. Every
other call continues to fail closed. Consensus deployment/activation transactions, private issuance,
mixed-fee bundles, wallet construction, SDK vectors, and independent audit coverage remain required
before the fungible-token phase is deployable or eligible for production activation.
