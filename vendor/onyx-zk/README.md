# onyx-zk — Onyx (V6) zero-knowledge backend (Rust)

Vendored Halo2/PLONKish (Pasta) proving stack exposed to the C++ node through a small C ABI
(`include/onyx_zk.h`). Backs `cn::zk::Halo2ProofSystem` (`src/Core/zk`). This is **wrappers only** —
no bespoke cryptography. See `../../ONYX_ARCHITECTURE.md` and `../../ONYX_O0_PLAN.md`.

## What it exposes (Onyx phase O0)

- `onyx_poseidon_hash2` — Orchard Poseidon (P128Pow5T3, arity 2) over the Pallas base field.
- `onyx_sinsemilla_hash` — Sinsemilla hash over a fixed test domain.
- `onyx_toy_prove` / `onyx_toy_verify` — a toy `a*b = public` circuit, present only to validate the
  prove→verify pipeline and the FFI boundary end-to-end. **Not** a protocol circuit; real circuits
  (notes, nullifiers, programs) arrive in O1/O4.

It deliberately contains **no** notes, nullifiers, value transfer, or consensus logic.

## Build

```
# Rust-only checks (fast iteration):
cargo test --release        # runs Poseidon/Sinsemilla + toy round-trip tests, prints KATs

# Produces target/release/libonyx_zk.a (staticlib) for linking into the C++ tests/node,
# wired via CMake (Corrosion) behind the OFF-by-default option ONYX_ZK (see ONYX_O0_PLAN.md, D3).
```

Toolchain: developed against Rust 1.94. Pin with a `rust-toolchain.toml` before CI bring-up.

## Reproducible / offline builds

Before any mainnet use, vendor the full dependency graph and build offline:

```
cargo vendor vendor/          # writes the dep sources here; commit Cargo.lock + this tree
cargo build --release --offline
```

`PROVENANCE.md` records every crate with its version and checksum. Dependency versions are pinned in
`Cargo.toml`; upgrades are explicit, reviewed changes.

## Memory ownership across the FFI

Rust allocates buffers returned via out-params (`onyx_toy_prove`); the C++ side must release them
with `onyx_free`. The `--zk` C++ tests run under ASan in CI to catch boundary leaks.
