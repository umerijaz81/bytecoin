# Jade (V5) Upgrade — Implementation Status & Integration Seams

This is the working tracker for evolving Bytecoin into a hardened, fully-private, laptop-mineable
coin. It records what is **implemented now** (Tier A) and the **exact seams + vendoring/test plan**
for the consensus-critical cryptography still to come (Tier B). See `SECURITY_PRIVACY_AUDIT.md` for
the findings these phases address.

All consensus-breaking changes activate under a single new hard-fork version, **Jade / V5**, gated
at `UPGRADE_HEIGHT_V5` (`src/CryptoNoteConfig.hpp`). The mainnet height is intentionally far in the
future so current Amethyst/V4 consensus is unchanged until a fork is scheduled and reviewed.

> **Non-negotiable rule:** consensus-critical crypto (range proofs, membership proofs, PQ
> signatures) is integrated from **peer-reviewed, vendored libraries**, never hand-rolled, and each
> Tier-B phase activates on testnet/stagenet first and requires external cryptographer review
> before a mainnet height is set. Overclaiming ("unbreakable", "quantum-proof") is itself a way the
> project stops being trustworthy — the docs must say *quantum-agile*, not quantum-proof.

## Tier A — implemented and tested in this branch

| Item | Where | Test |
|------|-------|------|
| V5/"jade" version scaffolding (`BLOCK_VERSION_JADE=5`, `TRANSACTION_VERSION_JADE=5`, `UPGRADE_HEIGHT_V5`, `RANDOMX_SWITCH_HEIGHT`, `MINIMUM_ANONYMITY_JADE=15`) | `src/CryptoNoteConfig.hpp`, `src/Core/Currency.{hpp,cpp}` (`upgrade_heights`, `jade_*_version`, `minimum_anonymity`) | `./bin/tests --blockchain` (unchanged) |
| **Consensus-enforced minimum ring size** (closes C-3): rejects rings `< minimum_anonymity+1` for V5+; raises floor to a ring of 16 | `validate_tx_semantic`, `src/Core/BlockChainState.cpp` (InputKey branch) | `./bin/tests --jade` |
| CSPRNG periodic reseed + deterministic-test guard (L-1) | `src/crypto/random.{c,h}` | covered by `--crypto` vectors staying stable |
| Archive omits peer source IPs by default (M-1) | `src/Core/Archive.{hpp,cpp}`, `BlockChain.cpp`, `Config.{hpp,cpp}` (`--archive-keep-source-addresses`) | build/link |
| Wallet-sync privacy mode hides wallet age + sparse_chain (M-2) | `src/Core/WalletSync.cpp`, `Config.{hpp,cpp}` (`--wallet-sync-privacy`) | build/link |

The headline result, from `./bin/tests --jade`:

```
  [jade] ring size 1 rejected: Ring size too small 1 minimum 16
  [jade] ring size 16 accepted
  [amethyst] ring size 1 still semantically valid (unchanged)
```

## Tier B — vendored crypto, testnet-first, needs review

Each phase below is consensus-critical and ships only after review. The seams are already in place
(version dispatch + dormant scaffolding), so the cryptographic cores can be dropped in without
re-architecting.

### Phase 3 — Confidential amounts (Bulletproofs+), closes C-1, C-2
- **Vendor:** an audited Bulletproofs+ / Pedersen implementation under `vendor/`. The curve
  building blocks already exist (`H` generator, `P3`, `sc_*` in `src/crypto/crypto.cpp`,
  `crypto_helpers.hpp`).
- **Dormant scaffolding to use:** `OUTPUT_AMOUNT_COMMITMENT_SIZE`, `tx_output_size_jade`
  (`src/Core/CryptoNoteTools.cpp`), `amount_commitments` (`src/Core/Multicore.hpp`).
- **Seam:** under V5, `OutputKey` (`src/CryptoNote.hpp`) carries a Pedersen `amount_commitment`
  instead of a cleartext `amount`; serialize via the version branch in `ser_members(OutputKey)`
  (`src/CryptoNote.cpp:279`). Replace the cleartext value test at `BlockChainState.cpp` (`sum(out)
  > sum(in)`) with a commitment-balance check + range-proof verification, batched in the existing
  `m_ring_checker` / `Multicore` path.
- **Decoys:** with amounts hidden, decoy selection moves from per-amount stacks
  (`TransactionBuilder.cpp`, `Currency::mixin_distribution`) to one global output set; the selection
  distribution must match the real spend-age distribution.
- **Test:** new `tests/crypto` vectors (balance, range-proof accept/reject, overflow attempts);
  testnet full sync.

### Phase 4 — Large-anonymity membership proofs (Triptych/Seraphis)
- **Vendor:** a reviewed Triptych/Seraphis (or Groth–Bootle one-of-many) reference.
- **Seam:** add a new signature variant to the `TransactionSignatures` boost::variant
  (`src/CryptoNote.hpp`) dispatched at `ser_members(TransactionSignatures)`
  (`src/CryptoNote.cpp:240`), replacing `RingSignatureAmethyst` for V5. Key-image uniqueness
  (`BlockChainState.cpp`) stays the double-spend guard; verification batched in `Multicore`.
- **Test:** membership-proof unit tests (valid spend, non-member rejection, key-image linkage,
  double-spend); laptop-class verification-cost benchmark.

### Phase 5 — RandomX PoW (laptop mineability)
- **Implemented, activation pending:** upstream RandomX v2.0.1 is pinned under `vendor/randomx` and
  selected only at the dormant Jade/height boundary. Node and miner share the canonical hashing blob,
  explicit RPC algorithm/seed fields and a 2,048-block epoch with a 64-block ancestor delay. Side-chain
  validation derives the seed from that branch. See `docs/RandomX-Transition.md`.
- **Remaining:** independent consensus review, full-memory multi-thread miner work, multi-architecture
  vectors, epoch-boundary reorg tests, benchmarks and public testnet activation/soak.

### Phase 6 — Post-quantum crypto-agility (addresses Q-1)
- **Seam:** the version/scheme dispatch at `ser_members(TransactionSignatures)`
  (`src/CryptoNote.cpp:240`) is generalized into an explicit signature-scheme id, so a vendored,
  standardized PQ signature (e.g. ML-DSA/Dilithium or a hash-based scheme) slots in as a spend-time
  authenticator. Commit hash-based bindings to public keys so funds aren't exposed until spend
  ("harvest-now-decrypt-later" mitigation). Full PQ *ring* privacy is open research industry-wide;
  scope = agility + PQ authenticator, **not** quantum-unbreakable privacy.

### Network privacy (transport, no consensus impact) — Dandelion++ & Tor
- **Dandelion++ (implemented, validation pending):** negotiated P2P v5 stem relay uses a stable random
  outbound peer per epoch, per-hop probabilistic fluff, a hop limit, randomized embargo timers and
  immediate loop/disconnect recovery. V4 peers retain diffusion compatibility. The default is on;
  `--disable-dandelion` opts out. See `docs/Dandelion-Relay.md` for the state machine and limitations.
- **Tor/I2P proxy (implemented, validation pending):** `--p2p-proxy=<ip:port>` routes every outbound
  P2P connection through a no-auth SOCKS5 proxy with numeric targets, no direct fallback and a bounded
  handshake. Remaining: Tor/I2P integration tests, hidden-service peer identities and independent
  DNS/direct-leak validation. See `docs/SOCKS5-Proxy.md`.

## Build / test (this environment)

```
cd build && cmake -DUSE_SQLITE=1 .. && make -j tests
./bin/tests --jade        # run from the build/ folder
```
(`USE_SQLITE=1` avoids the external LMDB clone. Toolchain note: a handful of missing
`<stdexcept>/<limits>/<memory>/<algorithm>` includes were added so the code builds under GCC 13.)
