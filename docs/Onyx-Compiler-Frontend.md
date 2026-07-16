# Onyx compiler frontend v1 alpha

The repository now contains an executable, deterministic frontend for the bounded language specified
in `docs/Onyx-Compiler-Specification.md`:

```text
python tools/onyx/compiler_v1.py --print-build-digest
python tools/onyx/compiler_v1.py --print-target-profile-digest
python tools/onyx/compiler_v1.py <package-directory> <new-output-directory>
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
compiler build and target-profile digest. The current alpha fails closed on nonempty dependency locks
until content-addressed dependency import is implemented.

The implemented language accepts explicitly public/private parameters, `bool`, checked `u8`/`u16`/
`u32`/`u64`, Pasta `field`, bounded byte-string/array interface types, fixed-array construction and
bounded indexing, immutable `let`, assertions, one final return, statically bounded `for`, constrained
`if`/`else`, three closed cryptographic intrinsics and direct calls to earlier name-sorted functions.
Loops are expanded with a cumulative package bound. Conditional instructions carry an explicit
dominating boolean guard so checked arithmetic and assertions can be gated by a future circuit
backend. Recursion, backward calls, `while`, mutable globals, indirect calls, implicit casts, unknown
intrinsics and nested returns are rejected.

Record operations, byte-string construction, dependency import and the remaining versioned
cryptographic intrinsics are not implemented yet; using them fails compilation. This is intentionally
recorded as remaining work rather than silently assigning host-language semantics.

## Artifact and verifier

The compiler atomically emits normalized sources, schemas, a target profile, conservative resources,
provenance, file hashes and canonical binary `ONXIR` v1. The IR uses shortest-form unsigned LEB128,
closed type/opcode tables, dominance-ordered value ids, explicit guards and acyclic name-ordered
calls. Its identifier is domain-separated SHA-256.

The separate verifier does not trust the resource JSON. It bounds and decodes every field, checks
canonical integers/text, SSA dominance, guards, opcode arity and operand/result types, reconstructs
the call graph, recomputes expanded instruction/constraint/row/column/witness/memory/proof bounds,
checks every artifact digest, recompiles from the normalized package in a fresh absolute path and
requires every output byte to match.

The locked three-platform core workflow runs positive reproduction plus negative manifest, source,
IR, resource, call-graph and unsupported-language tests. `tests/onyx_compiler/golden-v1.json` freezes
the exact compiler/profile/IR/artifact digests so platform drift fails visibly.

## Remaining activation boundary

The frontend does not yet lower IR into Halo2 constraints, generate or independently regenerate a
verifying key, construct proofs, or supply backend measurements. Those stages, structured fuzzing,
standard-library packages, independent builds, external audits and public testnet soak remain
mandatory before governance can approve any compiler/profile digest.
