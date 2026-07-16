# Onyx SDK compatibility profile v1

This profile freezes the developer-facing contract independently from consensus activation:

- C ABI version: `ONYX_ZK_ABI_VERSION == 1`, verified at runtime with `onyx_abi_version()`.
- Consensus protocol family: Onyx V6; unknown envelope and function versions fail closed.
- Program descriptor: `onyx_token_program_descriptor` at fixed Merkle depth 32.
- Wallet RPC request/response field contract: `wallet-rpc.json`.
- Golden JSON-RPC request/response objects for every method: `fixtures/wallet-rpc.json`.
- Canonical cryptographic and descriptor bytes: `../../../vendor/onyx-zk/test_vectors.md`.
- Semantically versioned dependency-free Python wheel, descriptor binding and offline RPC codec:
  `../python/` (`bytecoin-onyx-sdk==1.0.0`).
- Semantically versioned dependency-free JavaScript/TypeScript package and offline RPC codec:
  `../typescript/` (`@bytecoin/onyx-sdk@1.0.0`).

ABI v1 callers must release every successful returned buffer with `onyx_free`. A future incompatible
signature, ownership, encoding, or error-contract change requires a new ABI number and compatibility
profile. Adding a function without changing existing contracts is backward-compatible, but consumers
must still feature-detect by their linked library version rather than assuming a symbol is available.

The descriptor helper is CPU-intensive because the Program ID commits to the exact standard Halo2
verifying-key descriptors. Cache results by all inputs. Never accept a Program ID computed at a test
Merkle depth, and never treat an offline descriptor as a registered or authorized deployment.
