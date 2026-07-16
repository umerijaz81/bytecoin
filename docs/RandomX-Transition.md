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
Jade test verifies the fork/version boundary and delayed epoch rule; `tests --blockchain` includes the
branch-derived seed/reorganization integration. CI also runs pinned upstream v2 vectors plus the
full-memory equality test on x86-64 and ARM64, and contains a RISC-V/QEMU vector gate. Remaining
release qualification includes independent review, longer/deeper randomized reorg and sync runs,
corrupt-template tests, published mining throughput/power benchmarks and public testnet soak.

The bundled miner uses one shared 2,080 MiB full-memory dataset by default. Dataset initialization is
bounded by `--randomx-init-threads`, hashing uses persistent workers selected by `--threads`, and each
worker owns its own VM while the immutable dataset remains shared. `--randomx-large-pages` is an
explicit require-or-fail policy: it never silently falls back. Low-memory verification/mining remains
available as `--randomx-light --threads=1`; multiple light workers are rejected because each would
otherwise allocate a separate 256 MiB cache. A seed change destroys the old workers and dataset before
building the next epoch, and a VM refuses to hash with a seed different from its dataset.

The repository full-memory test initializes the dataset in parallel, hashes the same consensus vector
through two VMs concurrently, compares both with light mode and rejects a mismatched seed. The locked
CI gate passes on Ubuntu x86-64, Windows x86-64 and macOS ARM64. Its July 2026 qualification step took
19, 18 and 26 seconds respectively; those are initialization-plus-vector test timings, not mining
throughput benchmarks.

The consensus integration suite lowers only the test instance's activation/epoch parameters, mines
two branches that fork before their seed block, validates the side branch across the next seed epoch
and reorganizes to it. This exercises the actual block serializer, validator and ancestor lookup. The
production defaults and dormant activation height remain unchanged.
