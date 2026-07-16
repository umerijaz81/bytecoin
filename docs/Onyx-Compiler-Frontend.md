# Onyx compiler frontend v1 alpha

The repository now contains an executable, deterministic frontend for the bounded language specified
in `docs/Onyx-Compiler-Specification.md`:

```text
python tools/onyx/compiler_v1.py --print-build-digest
python tools/onyx/compiler_v1.py --print-target-profile-digest
python tools/onyx/compiler_v1.py <package-directory> <new-output-directory> \
  --dependency-store <content-addressed-directory>
python tools/onyx/verify_compiler_bundle_v1.py <output-directory>
```

This is an alpha engineering boundary and cannot register or execute an arbitrary Onyx program. Its
provenance explicitly sets `registrable` to `false`. Consensus continues to recognize only the
compiled-in standard-program allowlist.

## Package boundary

A package contains exactly `onyx-package.json`, `onyx.lock` and its manifest-declared source files.
All JSON must use the compiler's canonical UTF-8 encoding (sorted keys, no insignificant whitespace,
LF terminator). Source paths and files are digest-bound, UTF-8 NFC, LF-only, relative, byte-sorted and
free of symlinks, case-fold collisions and undeclared ambient inputs. The manifest pins both the exact
compiler build and target-profile digest.

Dependencies are selected only from an explicitly supplied store whose child directory is the locked
SHA-256 tree digest. Each canonical `onyx-library.json`, identity, version, sorted source list, file
digest, namespace prefix and complete tree digest is independently checked. Dependency counts and
aggregate bytes are bounded; unlisted files and symlinks fail closed. The call graph across libraries
and application code is placed in deterministic lexicographic topological order, and recursion is
rejected. Exact library trees are copied into the output bundle, so the verifier recompiles offline
from the bundle rather than consulting the original store.

The implemented language accepts explicitly public/private parameters, `bool`, checked `u8`/`u16`/
`u32`/`u64`, Pasta `field`, canonical fixed byte strings with lowercase hex construction, fixed-array construction and
bounded indexing, canonical nonrecursive records with ordered construction/field access, immutable
`let`, assertions, one final return, statically bounded `for`, constrained `if`/`else`, three closed
cryptographic intrinsics and direct calls to earlier name-sorted functions.
Loops are expanded with a cumulative package bound. Conditional instructions carry an explicit
dominating boolean guard so checked arithmetic and assertions can be gated by a future circuit
backend. Recursion, backward calls, `while`, mutable globals, indirect calls, implicit casts, unknown
intrinsics and nested returns are rejected.

The remaining versioned cryptographic intrinsics are not implemented yet; using them fails compilation.
This is intentionally recorded as remaining work rather than silently assigning host-language
semantics.

## Artifact and verifier

The compiler executes manifest-declared positive and negative vectors with a checked reference IR
evaluator, then atomically emits those results, normalized sources, schemas, a target profile,
conservative resources, provenance, file hashes and canonical binary `ONXIR` v1. Intrinsic-bearing
vectors fail closed until the Halo2-backed evaluator is available; an expected-negative vector cannot
hide an unsupported evaluator operation. The IR uses shortest-form unsigned LEB128,
closed type/opcode tables, dominance-ordered value ids, explicit guards and acyclic name-ordered
calls. Its identifier is domain-separated SHA-256.

The separate verifier does not trust the resource JSON. It bounds and decodes every field, checks
canonical integers/text, SSA dominance, guards, opcode arity and operand/result types, reconstructs
the call graph, recomputes expanded instruction/constraint/row/column/witness/memory/proof bounds,
checks every artifact digest, recompiles from the normalized package in a fresh absolute path and
requires every output byte to match.

## Halo2 compiler alpha backend

`vendor/onyx-zk/src/compiler_backend.rs` independently decodes canonical `ONXIR` inside the pinned
Rust/Halo2 dependency boundary. Its executable profile accepts explicitly selected exported
functions over Pasta `field`, `bool`, and checked `u8`/`u16`/`u32`/`u64` values. A package may contain
acyclic direct helper calls: the backend independently verifies earlier-target signatures and deterministically
inlines their parameters, constraints, assertions and return values into the selected exported circuit. The
library and CLI proof APIs require an exact entry name for multi-export IR; unnamed APIs remain available only
when the IR has exactly one export. Guarded control flow is normalized independently in
the backend: guarded operands select constraint-safe neutral values, the original arithmetic gadget remains
fully enabled, and its result is selected against the canonical type-zero. Guarded assertions become Boolean
implications, and call guards propagate through every inlined callee constraint. Thus inactive division-by-zero,
overflow and failing assertions are neutral, while activating the same path restores every original failure.
The circuit constrains public parameters and
the returned value as instances, copies every operand through Halo2 equality constraints, range-checks
booleans, and implements field add/subtract/multiply, boolean not/and/or, equality/inequality with an
inverse witness, and assertion gates. Unsigned values are bit-decomposed and reconstruction-bound;
add/subtract/multiply fail on overflow or underflow, ordering uses a range-constrained borrow,
division/remainder enforce the complete nonzero Euclidean relation, and dynamic shifts constrain the
shift count and power-of-two construction. Field division requires a nonzero denominator inverse.

Canonical arrays, name-sorted nonrecursive records and fixed byte strings are flattened recursively into
ordered scalar leaves. This applies to public/private parameters, return values, direct-call arguments and
results, guarded values, byte literals, constructors and record projections. Dynamic array indexing asserts the
`u64` index bound and uses an equality/selection network for every leaf, so no host-side unchecked lookup enters
the circuit. Public composite parameters and returns expose their leaves in canonical layout order. The bounded
backend `prove` command accepts canonical 32-byte Pasta encodings and is used by integration tests to create a
real composite proof and reject a mutated return leaf.

The versioned intrinsic set uses the pinned Orchard/Pasta `P128Pow5T3` permutation and `ConstantLength<2>`
domain. `poseidon_hash(a,b)` is the plain two-input hash; `merkle_root(left,right)` is
`H(2,H(left,right))`; and `nullifier(key,rho,position)` is `H(3,H(H(key,rho),position))`, matching
the membership circuit's node/nullifier tags. The original two-input alpha nullifier signature was corrected
before registration because it could not bind note position. A separate bounded Python Grain-LFSR/MDS reference
implementation reproduces the pinned constants and evaluator vectors; real Halo2 proofs cross-check all three
intrinsics against it.

The Rust backend also exposes bounded `create_compiler_proof` and `verify_compiler_proof` APIs. Proof
creation requires every declared parameter plus the public parameters and return value in canonical
order, rejects arity, boolean and public-witness mismatches before proving, and self-verifies the
freshly randomized proof before returning it. Verification derives its key from witnessless canonical
IR. Profile and full IR digests are committed into fixed circuit columns, so even an artifact metadata
mutation changes the verification key. Positive round trips and negative altered-output, altered-IR,
corrupted-proof and public-witness vectors run in the locked Rust test shard.

The `onyx-compiler-backend` executable reads IR only from standard input and emits a fixed-length
v2 descriptor containing the circuit size, profile digest, IR digest, domain-separated export-name digest and
a domain-separated digest of the pinned Halo2 verifying key. Passing `--backend-executable` to the frontend
embeds one descriptor per manifest export and per-export backend measurements. Verification requires an
explicitly supplied backend executable, requires the descriptor set to equal the declared exports, regenerates
every VK descriptor from bundled IR, recompiles the whole bundle and byte-compares it. The
descriptor remains `compiler-alpha-not-registrable`; unsupported IR cannot omit constraints silently.

The locked three-platform core workflow runs positive reproduction plus negative manifest, source,
IR, resource, call-graph and unsupported-language tests. `tests/onyx_compiler/golden-v1.json` freezes
the exact compiler/profile/IR/artifact digests so platform drift fails visibly.

## Remaining activation boundary

The scalar, checked-integer, composite and intrinsic subset now lowers to Halo2 and independently regenerates
per-export descriptors, but the complete release process is not finished.
Structured fuzzing, standard-library packages, independent builds, external audits and public testnet
soak remain mandatory before governance can approve any compiler/profile digest.
