# Onyx private-program compiler specification

Status: design draft; no consensus activation or user-supplied program is authorized by this file.

This specification defines the boundary that an Onyx developer-language compiler must satisfy before
arbitrary private programs can be considered for the program registry. The current node continues to
accept only compiled-in, reviewed standard programs. Unknown backends, intermediate-representation
versions, functions, schemas and verifying-key descriptors fail closed.

## 1. Security objectives

The compiler must produce the same canonical artifact for the same source package, compiler version,
target profile and dependency lock on every supported host. It must not infer consensus behavior from
host integers, locale, filesystem order, wall-clock time, random state, environment variables or
absolute paths. Its output is untrusted until the independent artifact verifier has reproduced every
digest and checked every declared resource bound.

The language and intermediate representation are deliberately not general purpose. They prohibit
unbounded work, dynamic allocation, recursion, ambient I/O, nondeterministic data and undefined
behavior. Privacy is not inferred from a source-level name: every public input and disclosure is part
of the canonical interface and must be visible in the manifest.

## 2. Compilation package

A source package contains only UTF-8 files with canonical `/` paths and a lock file. Paths must be
relative, Unicode NFC, case-sensitive, free of `.` and `..` segments, and sorted by their UTF-8 byte
encoding. Symlinks, devices, archives inside archives and duplicate normalized paths are rejected.
Source text permits LF line endings only and rejects a byte-order mark, NUL and non-shortest UTF-8.

The package manifest commits to:

- language edition and compiler semantic version;
- the exact compiler build digest and target profile;
- package name/version and the ordered source-file digest list;
- immutable dependency package and artifact digests;
- exported function names and explicit public/private parameter modes;
- requested maximum rows, advice/fixed/instance columns and proof bytes.

Compilation has no network access. Dependencies must already be present in a content-addressed store,
and an undeclared file or environment input is an error.

## 3. Source language v1

The v1 type system contains `bool`, unsigned integers `u8`, `u16`, `u32`, `u64`, the Onyx Pasta base
field `field`, fixed byte strings `bytes<N>`, fixed arrays `[T; N]` and nonrecursive records. Array and
record sizes are compile-time constants. There are no signed integers, floats, strings, pointers,
references, implicit numeric conversions, unions, exceptions or user-defined destructors.

Arithmetic is checked. Integer overflow, underflow, division by zero, invalid shift counts and field-
to-integer values outside the destination range create constraints that make the proof unsatisfiable;
they may not wrap silently. Field division requires an explicit nonzero constraint. Boolean values
are constrained to zero or one.

Control flow is limited to:

- `if`/`else`, lowered to constrained selection with both branch shapes statically known;
- `for i in 0..N`, where `N` is a manifest-bounded compile-time constant;
- calls whose statically constructed call graph is acyclic.

`while`, recursion, dynamic dispatch, indirect calls, concurrency, assembly and mutable global state
are rejected. A function may access only its parameters and local values. Compiler intrinsics are
versioned and selected from the target profile; an unknown intrinsic is an error.

When an IR contains multiple exported functions, proof and descriptor creation MUST name one export exactly.
The export name is domain-separated, length-bound and SHA-256 committed into both the circuit's fixed identity
and descriptor v2. An unnamed request is valid only when the IR has exactly one export. A bundle with backend
artifacts contains exactly one descriptor for every export declared by its canonical package manifest.

The non-registrable compiler-v1 profile currently fixes three Pasta-field intrinsics using
`P128Pow5T3` and the two-input constant-length domain: `poseidon_hash(a,b) = H(a,b)`,
`merkle_root(left,right) = H(2,H(left,right))`, and
`nullifier(key,rho,position) = H(3,H(H(key,rho),position))`. Tags `2` and `3` match the approved
membership circuit. Any signature or domain change requires a new target-profile digest.

## 4. Canonical Onyx IR v1

The compiler lowers typed source into a single-static-assignment, acyclic control-flow graph. Values
are numbered in dominance order. Blocks, phi/select inputs, constants, functions and exports use
canonical source-independent ordering. Debug information is a separate non-consensus artifact.

The instruction set is closed:

1. typed constants and copies;
2. checked integer add, subtract, multiply, divide, remainder, shifts and comparisons;
3. Pasta-field add, subtract, multiply, inverse-with-nonzero and equality;
4. boolean operations and typed select;
5. fixed array/record construction and constant- or bounded-index access;
6. target-profile intrinsics for canonical hashing, commitments, signatures, Merkle membership,
   nullifier derivation and note encryption bindings;
7. assertions and range constraints;
8. direct calls to an earlier function in the acyclic call order.

Every integer and length is encoded as canonical unsigned LEB128 with shortest encoding. Field values
use canonical 32-byte little-endian Pasta encodings and must be below the modulus. Text is length-
prefixed UTF-8 NFC. Maps are forbidden; repeated fields are sorted where this specification declares
them sorted. Decoders reject duplicate entries, unknown mandatory tags, trailing bytes, noncanonical
integers and values exceeding profile bounds before allocating proportional memory.

The IR artifact begins with domain `ONXIR`, version `1`, target-profile digest, ordered type table,
ordered function table, export table and instruction stream. Its identifier is:

```text
ir_id = SHA-256("bytecoin.onyx.ir.v1" || canonical_ir_bytes)
```

## 5. Public interface and state discipline

Each exported function declares an ordered public-input schema and an ordered private-witness schema.
The public schema is hashed using the existing Onyx program-registry domain and becomes the exact
schema hash in the registry descriptor. Changing order, type, visibility or a bound changes the hash.

Programs cannot read chain state implicitly. Anchors, nullifiers, commitments, program/asset ids,
fees, activation network and any public-state root are explicit typed inputs constrained by a
versioned intrinsic. Note creation and consumption use linear capabilities: each input capability is
consumed at most once and every created value is assigned to exactly one output or an explicitly
public fee/burn lane. Asset domains cannot be cast or cancelled against one another.

The v1 compiler does not enable shared mutable public state, cross-program recursion, proof
aggregation, dynamic verifying keys or runtime-selected circuits. Those require new target profiles
and independent review.

## 6. Resource analysis

Before circuit generation, the compiler computes conservative upper bounds for expanded calls, loop
iterations, IR instructions, constraints, rows, columns, lookups, public inputs, witness bytes,
proving memory, verifier work and proof bytes. Analysis uses checked `u64` arithmetic; overflow is a
compile error. No user annotation may reduce a compiler-derived bound.

The target profile supplies hard maxima. Compilation fails before proving-key generation when any
bound is exceeded. The emitted cost record contains both the derived bounds and the final backend
measurements. Registry cost is the greater of the independently recomputed static bound and measured
backend bound, never a caller-provided estimate.

## 7. Deterministic Halo2 lowering

The initial target is the exact pinned `halo2-ipa-pasta` Onyx backend. The target profile commits to
the vendored dependency-tree digest, Pasta parameters, transcript, commitment/hash domains, circuit
size policy and compiler passes. Pass order is fixed; parallel execution must not affect ordering.

Key generation uses no secret randomness. Any blinding material required to derive public circuit
parameters is generated from a domain-separated transcript containing the target-profile digest and
`ir_id`. Proving randomness remains wallet-local and is never part of compilation.

The verifying-key descriptor contains the target profile, `ir_id`, export id, canonical public schema,
resource record, circuit shape and verifying-key digest. A registry entry is valid only if the node's
approved backend regenerates the same descriptor byte-for-byte. Supplying arbitrary verifying-key
bytes without a matching approved compiler/profile descriptor is rejected.

## 8. Reproducible artifact bundle

The compiler emits a canonical directory containing:

- normalized source-package manifest and dependency lock;
- canonical IR and its digest;
- public/private schemas for each export;
- resource-analysis report;
- circuit and verifying-key descriptors;
- compiler provenance, target-profile digest and dependency-tree digest;
- deterministic positive vectors and negative mutation vectors;
- a manifest of SHA-256 hashes for every file.

The bundle contains no timestamps, absolute paths, usernames, hostnames or unordered serialization.
Two builds in distinct paths must compare byte-for-byte. A separately built verifier parses the
bundle under strict size limits, recompiles from the normalized source package and rejects any digest,
schema, resource or descriptor difference.

## 9. Diagnostics and failure behavior

Diagnostics are not consensus artifacts. They use stable error codes and source-relative locations;
human wording may evolve. The compiler exits nonzero and emits no registrable bundle after any parse,
type, canonicalization, resource, dependency, backend or reproduction error. Partial files are written
only to an isolated temporary directory and atomically renamed after verification.

The node and wallet never invoke the compiler while validating blocks. They consume only an audited,
governance-approved target profile and exact registered descriptors. Compiler compromise must not let
an attacker substitute a descriptor that the node cannot independently regenerate.

## 10. Qualification and activation gates

An implementation is not production eligible until all of the following are complete:

1. parser, type checker, canonical IR, resource analyzer, Halo2 lowering and independent verifier;
2. differential and mutation testing for every instruction and canonical decoder rule;
3. parser/IR/backend fuzzing with valid structured seeds and sustained sanitizer runs;
4. byte-identical bundles from independent Linux, macOS and Windows builders;
5. audited standard-library packages demonstrating value conservation and disclosure boundaries;
6. two independent compiler/circuit reviews with no unresolved critical or high findings;
7. public testnet proving, verification, reorg, malformed-bundle and denial-of-service soak;
8. explicit governance approval of one compiler build digest and target-profile digest.

Until those gates are attached to the release evidence, arbitrary programs remain disabled and the
compiled-in standard-program allowlist remains the only executable Onyx program surface.
