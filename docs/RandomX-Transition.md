# RandomX v2 proof-of-work transition

The dormant Jade hard fork switches proof of work from CryptoNight to vendored RandomX v2 at
`RANDOMX_SWITCH_HEIGHT`. Mainnet remains unchanged because the placeholder activation height must not
be lowered until independent review, public testnet soak and release governance are complete.

## Consensus contract

- Blocks before the switch use the historical CryptoNight hashing blob and implementation unchanged.
- RandomX blocks use the same canonical block hashing blob as input and `RANDOMX_FLAG_V2` output as
  the 256-bit difficulty hash.
- The RandomX key is an ancestor block hash. Epochs are 2,048 blocks and the selected key block is
  delayed by 64 blocks: `floor((height - 64) / 2048) * 2048`, clamped to genesis.
- Validation derives the key from the candidate block's parent branch. It never substitutes the
  active-chain block at that height, so a valid side chain and a reorganization use their own key.
- `get_block_template` returns `pow_algorithm` and `pow_seed_hash`; the bundled miner rejects unknown
  algorithm identifiers and uses the exact seed returned by the node.

The implementation pins upstream RandomX `v2.0.1` (`aaafe71322df6602c21a5c72937ac284724ae561`),
the corrected release that avoids a
rare invalid-hash condition on ARM/RISC-V. Provenance is recorded in
`vendor/randomx/BYTECOIN_VENDOR.md`. Updating this dependency is consensus-sensitive.

## Validation

Run `tests --randomx` for the repository-specific v2 known-answer vector and cached-seed check. The
Jade test verifies the fork/version boundary and the delayed epoch rule. Release qualification must
also run upstream RandomX tests plus node/miner vectors on x86-64, ARM64 and RISC-V, deep side-chain
and reorg tests across key epochs, corrupt-template tests, long sync and mining benchmarks.

The bundled miner uses RandomX light mode because it is intentionally single-threaded. Production
mining should add a reviewed full-memory dataset manager with bounded initialization and explicit
large-page/JIT policy; changing fast versus light mode must not change hashes.
