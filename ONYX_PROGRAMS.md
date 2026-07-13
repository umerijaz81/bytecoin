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
transfer verification rejects any nonempty `programs` list before cryptographic verification. This is
intentional: registration metadata alone does not prove a program predicate.

A program call becomes executable only after its audited function circuit supplies all of the
following:

1. a proof backend and verifier matching the registered verifying key;
2. public inputs matching the registered schema hash;
3. note program/asset identifiers constrained inside the circuit;
4. transaction-level binding of ordered calls and public-data hashes;
5. verification cost within the entry and block limits;
6. wallet proving, scanning, SDK vectors, and independent audit coverage.

Until those gates are implemented for a function, calls fail closed. This prevents a transaction from
using signed-but-unproved program metadata to create program-tagged notes.
