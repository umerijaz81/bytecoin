# Onyx O0 — Proof Backend Foundation: Detailed Scope

> Phase O0 of `ONYX_ARCHITECTURE.md`. Goal: stand up the zero-knowledge proving foundation behind
> the `IProofSystem` seam (`src/Core/zk/IProofSystem.hpp`) and prove it works **end-to-end through
> the C++ node's test harness** — vendored, version-pinned, and cross-checked against reference test
> vectors. O0 deliberately ships **no protocol logic** (no notes, no nullifiers, no value transfer —
> those are O1). It de-risks the single biggest unknown: making a real Halo2/PLONKish prover/verifier
> callable, reproducible, and testable from inside a C++/CMake project.

**Current implementation note:** the wrapper crate and lockfile are present, but the Cargo
dependency sources are not committed yet. Builds are locked, not offline-reproducible. The
vendoring and CI acceptance criteria below therefore remain open.

## Context: why O0 is mostly a build/FFI problem

Production-grade Halo2 (`halo2_proofs`, `halo2_gadgets` with Poseidon/Sinsemilla, the Pasta curves
via `pasta_curves`) exists only in **Rust**. Bytecoin is **C++ with a CMake build** (`CMakeLists.txt`,
targets `bytecoind`/`walletd`/`minerd`/`tests`; C-ABI crypto under `src/crypto`). So O0's hard part is
not "write a circuit" — it is **introducing a Rust toolchain and a stable, auditable FFI boundary**
into a previously pure-C/C++ project, and keeping the multi-platform release pipeline
(`azure-pipelines.yml`: Linux/macOS/Windows/Android) reproducible. This is a consequence of the
already-made Halo2/PLONKish decision, not a new choice.

## Decisions (recommended defaults; flag before O0 starts)

1. **FFI style — plain C ABI via `cbindgen` (recommended)**, not the `cxx` crate. The verify boundary
   is narrow (byte-buffers in, bool out) and the codebase is already full of `extern "C"` crypto
   shims, so a C ABI matches house style, minimizes build-time magic, and is the easiest surface to
   audit. `cxx` is more ergonomic for rich types we do not need here.
2. **CMake ↔ cargo — Corrosion (recommended)** (`corrosion-rs/corrosion`) to build the Rust staticlib
   as a first-class CMake target. Note: Corrosion needs CMake ≥3.15; the project declares
   `cmake_minimum_required(VERSION 3.0)`. O0 bumps the practical minimum (the sandbox already uses a
   modern CMake). Fallback: a hand-written `add_custom_command` invoking `cargo build`.
3. **Offline/vendored cargo** — vendor the full dependency graph with `cargo vendor` into
   `vendor/onyx-zk/vendor/` and commit `Cargo.lock`, so builds are reproducible and work in
   network-restricted environments (this sandbox blocked apt mirrors; cargo registry would fail the
   same way). Pin exact versions + checksums.
4. **Static linking** — the Rust crate compiles to a `staticlib` (`.a`) linked into the C++ targets,
   matching the project's `Boost_USE_STATIC_LIBS ON` posture.

## Deliverables

### D1 — Rust proving crate `vendor/onyx-zk/`
A workspace exposing a C ABI, with pinned, vendored dependencies:
- `halo2_proofs`, `halo2_gadgets` (Poseidon + Sinsemilla), `pasta_curves` — exact versions in
  `Cargo.lock`; provenance recorded in a `PROVENANCE.md` (crate, version, sha256, upstream commit).
- `crate-type = ["staticlib"]`; `cbindgen.toml` generating `onyx_zk.h`.
- **No bespoke cryptography.** Only thin wrappers over upstream gadgets + a toy circuit for the
  pipeline test (D3). All real circuits arrive in O1/O4.

### D2 — C ABI surface (`onyx_zk.h`, generated) + C++ adapter
Minimal, audit-sized surface:
```
// hashes (known-answer testable against the Rust reference)
int onyx_poseidon_hash(const uint8_t* in, size_t in_len, uint8_t out[32]);
int onyx_sinsemilla_hash(const uint8_t* in, size_t in_len, uint8_t out[32]);
// generic proof verify (backs IProofSystem::verify)
int onyx_verify(const uint8_t* vk, size_t vk_len,
                const uint8_t* proof, size_t proof_len,
                const uint8_t* public_inputs, size_t pi_len);  // 1=valid, 0=invalid, <0=malformed
// toy-circuit prove, for the round-trip pipeline test only
int onyx_toy_prove(uint64_t witness, uint8_t** proof_out, size_t* proof_len,
                   uint8_t** vk_out, size_t* vk_len);
void onyx_free(uint8_t* ptr, size_t len);  // free buffers returned across the boundary
```
- `src/Core/zk/Halo2ProofSystem.{hpp,cpp}` — `class Halo2ProofSystem : public IProofSystem`, implements
  `backend_id()` ("halo2-ipa-pasta") and `verify()`/`verify_batch()` by calling `onyx_verify`.
  Owns buffer lifetime via `onyx_free`. This is the only place C++ touches the FFI.

### D3 — CMake integration
- Add Corrosion; import `vendor/onyx-zk` as a target; link it into `tests` (and, in O1, the node).
- Gate behind an option `option(ONYX_ZK "Build the Onyx ZK backend (requires Rust/cargo)" OFF)` so the
  existing C++-only build stays green for anyone without a Rust toolchain. O0 CI turns it ON.

### D4 — Test vectors + harness wiring (`tests/zk/`)
Registered as `--zk` in `src/main_tests.cpp` (same pattern as `--jade`/`--blockchain`):
1. **Poseidon KATs** — fixed inputs → expected digests, cross-generated from the Rust reference and
   asserted byte-for-byte in C++.
2. **Sinsemilla KATs** — same.
3. **Round-trip** — C++ calls `onyx_toy_prove(w)`, then `Halo2ProofSystem::verify(...)` returns true;
   a tampered proof/public-input returns false; malformed bytes return the error code (not a crash).
4. **Batch** — `verify_batch` over a mix of valid/invalid items returns the correct per-item vector.

### D5 — Build & release notes
- `vendor/onyx-zk/README.md`: toolchain (pinned Rust version via `rust-toolchain.toml`), how to
  re-vendor, how to regenerate `onyx_zk.h`, and the offline-build procedure.
- Update `azure-pipelines.yml` notes for the Rust step on each platform (Android/macOS/Windows cross
  builds are the known pain points — see Risks).

## Acceptance criteria
- With `-DONYX_ZK=ON`, the project builds on Linux x86-64 and `./bin/tests --zk` passes (KATs +
  round-trip + batch).
- With `-DONYX_ZK=OFF` (default), the build is byte-for-byte unaffected; `IProofSystem.hpp` remains the
  only zk code compiled into the C++-only build (it is header-only and unreferenced).
- `Cargo.lock` committed; `cargo vendor` tree present; an offline build (no network) succeeds.
- `PROVENANCE.md` lists every crate with version + sha256.
- No hand-written cryptography in the crate; a reviewer can confirm wrappers-only.

## Risks & mitigations
| Risk | Mitigation |
|------|------------|
| **Multi-platform Rust cross-builds** (Android/macOS/Windows in azure-pipelines) — the biggest practical risk | Land Linux x86-64 first; add targets incrementally; pin `rust-toolchain.toml`; treat `-DONYX_ZK=OFF` as the always-green fallback during bring-up. |
| Network-restricted builds (no crates.io) | `cargo vendor` + committed `Cargo.lock`; build with `--offline`. |
| Halo2 / pasta version churn & breaking APIs | Exact pins; isolate all upstream contact in the wrapper crate; upgrades are explicit, reviewed PRs. |
| FFI memory-safety / leaks | Single ownership rule (Rust allocates, C++ frees via `onyx_free`); run the `--zk` tests under ASan in CI. |
| CMake minimum bump (3.0 → 3.15 for Corrosion) | Documented; `add_custom_command` fallback if a target environment is stuck on old CMake. |
| Introducing Rust raises contributor build burden | The OFF-by-default option keeps the coin buildable without Rust until Onyx nears activation. |

## Explicitly out of scope for O0 (these are O1+)
Notes, commitments, the Merkle tree, nullifiers, value commitments/balance, encryption, keys, wallet
scanning, any real application circuit, and any consensus wiring. O0 ends when a *toy* statement can be
proven in Rust and verified through `IProofSystem` from the C++ test harness, reproducibly.

## Effort & sequencing
Small applied-cryptography/Rust-FFI effort; the gating work is build/release engineering, not novel
crypto. Suggested order: D1 (crate + vendored deps, Linux) → D2 (C ABI + adapter) → D3 (Corrosion,
ONYX_ZK option) → D4 (`--zk` KATs + round-trip) → D5 (docs + first CI platform). Only after `--zk` is
green does O1 (the note/nullifier state model) begin. As with every phase: testnet-first and external
review before any of this gates value on mainnet.
