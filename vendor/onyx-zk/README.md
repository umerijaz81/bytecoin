# onyx-zk — Onyx (V6) zero-knowledge backend

This crate is the vendored Rust proof and wallet backend used by the C++ node and wallet through the
bounded C ABI in `include/onyx_zk.h`. Dependencies are exact-pinned in `Cargo.toml` and `Cargo.lock`,
their sources are committed under `vendor/`, and workspace configuration enforces locked offline
builds. The repository pins Rust 1.88.0 in `../../rust-toolchain.toml`.

## Implemented protocol surface

- Orchard-compatible Poseidon and Sinsemilla primitives plus the non-consensus O0 toy pipeline.
- Canonical Onyx notes, encryption, commitment tree, retained anchors, nullifiers, apply/undo state,
  wallet key derivation, full viewing keys, scanning, witness history, proving, and pending spends.
- Authorized native transfers, mixed private-token/native-fee transfers, and one-way legacy shielding.
- Canonical program registry and resource accounting, funded standard-token deployment, capped private
  issuance, issuer authorization, sequence/cap enforcement, and wallet-derived program status.
- Deterministic SDK descriptor construction through `onyx_token_program_descriptor`; canonical vectors
  are recorded in `test_vectors.md`.

Consensus callers must use the typed verification/application entry points. The toy verifier is only
an FFI smoke test and is never valid on a consensus path. Mainnet activation remains prohibited until
the external audit and release gates in `../../ONYX_PROTOCOL_SPEC.md` are satisfied.

## Reproducible build and test

```text
cargo check --release --locked --offline
cargo test --release --locked --offline
cargo build --release --locked --offline
```

CMake links the `staticlib` into Onyx-enabled node, wallet, and test targets behind `-DONYX_ZK=ON`.
CI exercises the locked offline crate on Linux, Windows, and macOS.

## SDK descriptor contract

`onyx_token_program_descriptor` accepts a canonical RedPallas issuer key, positive supply cap,
printable metadata (1–128 bytes), activation window, and circuit K. It returns the canonical `ONXM`
policy manifest and the Program ID for consensus Merkle depth 32. The Program ID commits to the
manifest, activation window, backend, exact function shapes, schemas, costs, and verifying-key
descriptors. Callers release the returned manifest with `onyx_free`.

Actual deployment still goes through `onyx_wallet_create_program_deployment`, which funds and signs
the reserved deployment call. A descriptor preview grants no authority and cannot register a program.
The versioned consumer contract and wallet RPC fixture are in `../../sdk/onyx/v1/`.

## FFI ownership and errors

Every input length is bounded and every exported function is panic-contained. Positive `1` means
success for protocol APIs; zero or negative values are fail-closed errors as documented by callers.
Buffers returned through out-parameters are Rust-owned and must be released exactly once with
`onyx_free(ptr, len)`.
