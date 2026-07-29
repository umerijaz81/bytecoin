# Onyx C++ proof-system adapter

This directory contains the C++ boundary between Bytecoin consensus/wallet code and the vendored
Rust Onyx backend:

- `IProofSystem.hpp` defines the active backend-neutral proof verification seam and rejects malformed
  batch shapes/null key slots without dereferencing them.
- `Halo2ProofSystem.hpp/.cpp` implements the current Halo2/IPA/Pasta backend over the bounded C ABI in
  `vendor/onyx-zk/include/onyx_zk.h`.

The adapter is integrated into CMake when `ONYX_ZK=ON`. Consensus uses typed verification and atomic
state-application methods for transfers, bridge operations, program deployments, and token issuance.
Wallet methods cover derivation, scanning, witness persistence, spend reservation, proving, asset
balances, and wallet-derived program status. Returned Rust buffers are copied and released on every
success and failure path.

The generic `verify()` override and toy prover exist only for O0 pipeline tests. They must not be used
to validate Onyx transaction envelopes. Unknown versions, backends, functions, malformed data, or
unsupported builds fail closed.

See `ONYX_PROTOCOL_SPEC.md`, `ONYX_PROGRAMS.md`, and `vendor/onyx-zk/README.md` for the canonical
protocol, registry, SDK, build, and activation constraints. The current backend is not post-quantum;
backend agility is a future fork and never an automatic security claim.
