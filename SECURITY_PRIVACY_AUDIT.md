# Bytecoin (BCN) Privacy & Security Audit

**Scope:** Privacy analysis of the live **amethyst** protocol (block major version 4,
`BLOCK_VERSION_AMETHYST = 4`). The `jade` amount-commitment code present in the tree is
inactive scaffolding and is *not* part of consensus on the current chain.

**Date:** 2026-06-10
**Methodology:** Source review of the cryptographic primitives (`src/crypto`),
consensus/validation (`src/Core/BlockChainState.cpp`, `Currency.cpp`), transaction
construction (`src/Core/TransactionBuilder.cpp`, `WalletNode.cpp`), and the P2P / RPC
layers (`src/Core/Node*.cpp`, `WalletSync.cpp`, `Archive.cpp`, `Config.cpp`).

> **Bottom line:** The cryptography and double-spend protection are sound. The *privacy
> model* is roughly a decade behind the state of the art. Transparent amounts, tiny
> per-denomination rings, a minimum ring size that consensus does not enforce, full
> ring collapse in remote-node mode, and no transaction-origin (network) privacy combine
> to make chain analysis highly tractable. Bytecoin should **not** be treated as a
> Monero-equivalent privacy shield.

---

## What is sound (no findings)

| Area | Evidence | Notes |
|------|----------|-------|
| Ring signature soundness | `src/crypto/crypto.cpp:358-530` | Amethyst Borromean-style ring signatures are correctly constructed. |
| RNG-bias resistance | `src/crypto/crypto.cpp:377` | Signing nonces are derived deterministically with `random_seed2 = secs_spend.at(0)`, a deliberate defense against a backdoored/biased RNG. |
| Double-spend protection | `src/Core/BlockChainState.cpp:56,167,734,901` | Key images are enforced unique chain-wide; reuse throws `ConsensusErrorOutputSpent`. |
| Key-image subgroup check | `src/crypto/crypto.cpp:133`; `BlockChainState.cpp:172` | Closes the historical CryptoNote small-subgroup key-image hole. Legacy malicious key images are listed in `crypto.cpp:136-159`. |
| Safe local bind defaults | `src/Core/Config.cpp:67,70` | `bytecoind` and `walletd` RPC bind to `127.0.0.1` by default. |
| Multicast disabled on mainnet | `src/Core/Config.cpp:63` | Prevents LAN peer-enumeration deanonymization. |

No coin-forging, signature-forging, or double-spend vector was found. **All findings below
are about linkability — tracing outputs to each other and to network identities.**

---

## Findings

### CRITICAL

#### C-1. Amounts are transparent (no RingCT / confidential transactions)
`OutputKey.amount` is stored in cleartext.

- `src/CryptoNote.hpp:58` — `struct OutputKey { Amount amount = 0; ... }`
- `src/Core/BlockChainState.cpp:140-143` — consensus validates the cleartext amount directly.

Every transaction value is visible on-chain. This is the root enabler of amount-correlation
chain analysis and forces the per-denomination ring structure in C-2.

**Remediation:** Activate confidential amounts (the dormant `jade` amount-commitment path)
with range proofs (Bulletproofs/Bulletproofs+) in a hard fork.

#### C-2. Rings are per-denomination
Because amounts are public, decoys must share the *exact* amount as the real output.

- `src/Core/TransactionBuilder.cpp:342-345` — decoys are drawn from `ra_response.outputs[uu.amount]`
  and rejected if `uu.amount != our_ra_outputs.back().amount`.

Anonymity sets fragment per-denomination; uncommon amounts get tiny or empty decoy pools,
and value flow can be followed by matching amounts across transactions.

**Remediation:** Subsumed by C-1 — confidential amounts allow a single global output set.

#### C-3. Minimum ring size is 3 and is NOT enforced by consensus
The minimum anonymity (`MINIMUM_ANONYMITY_AMETHYST = 3`, `src/CryptoNoteConfig.hpp:38`) is
applied **only wallet-side** (`src/Core/WalletNode.cpp:469`). The consensus/mempool semantic
validator never checks the number of ring members:

- `src/Core/BlockChainState.cpp:117-184` (`validate_tx_semantic`) — validates amounts, key-image
  uniqueness, and subgroup membership, but **never inspects `in->output_indexes.size()`**.
- `src/Core/BlockChainState.cpp:738` — `add_transaction` (mempool ingress) gates solely on
  `validate_tx_semantic`; no separate ring-size check.

**Impact:** A patched wallet can broadcast **zero-mixin (ring size 1) transactions** that the
network accepts as valid. These are fully traceable, and they poison *other* users' anonymity:
the node itself performs "chain-reaction" spent-output deduction
(`src/Core/BlockChainState.cpp:1268-1308`) that removes provably-spent outputs from the decoy
pool. See `poc/zero_mixin_loophole/` for a runnable demonstration.

**Remediation:** Reject `InputKey` with `output_indexes.size() < minimum_anonymity + 1` inside
`validate_tx_semantic` (consensus rule, requires hard fork to apply retroactively to new blocks).

#### C-4. Remote-node mode collapses the ring
A wallet using a third-party node requests decoys for the exact amounts it is about to spend
and then submits the final transaction through the *same* node:

- `src/Core/WalletNode.cpp:637-642` — `GetRandomOutputs` request carries `selector.get_ra_amounts()`
  (the real spend amounts).
- `src/Core/Node.cpp:339-355` — node returns the served decoys, indexed by amount.

The node served the decoys and later sees the broadcast transaction, so it can identify the
**real input as the ring member it did not serve**, fully deanonymizing the spend for a curious
or malicious node operator.

**Remediation:** Strongly prefer running a local node; document the remote-node deanonymization
risk prominently; consider client-side decoy selection from a locally synced output set.

#### C-5. Transaction-origin (network) privacy — partially remediated
The original implementation flooded locally submitted transactions to every peer immediately, which
made first-seen correlation to the originating IP straightforward. P2P protocol v5 now negotiates a
Dandelion++ stem message. A node chooses one outbound v5 stem peer for a rotating epoch, validates a
received stem transaction before forwarding it, and diffuses it on a probabilistic fluff decision,
the maximum-hop boundary, an embargo timeout, a loop, or downstream disconnect. Older peers receive
only the existing diffusion message, and a node with no eligible v5 peer safely falls back to it.

This reduces first-spy correlation but does not provide transport anonymity. A Sybil observer,
host/network telemetry, or a small adversarial topology can still identify origins. The implementation
also still requires multi-node adversarial simulation, sustained fuzzing, testnet soak, peer-scoring
work and independent review. Outbound connections can now use the fail-closed numeric-address SOCKS5
transport (`--p2p-proxy`). Real-daemon CI now proves successful SOCKS relay, rejection without direct
fallback and no local onion lookup using a DNS tripwire. Real Tor/I2P interoperability,
cross-platform packet capture and independent review remain release requirements.
`--disable-dandelion` is an explicit privacy-reducing compatibility/debug option.

### MEDIUM / LOW

#### M-1. Archive stores source IP per transaction
- `src/Core/Archive.cpp:49-69`, `src/Core/BlockChainState.cpp:699-702` — a persistent
  transaction→source-IP map, retrievable via the `GetArchive` RPC.

#### M-2. Wallet leaks creation timestamp and sparse chain on sync
- `src/Core/WalletSync.cpp:239-246` — `first_block_timestamp` (narrows wallet age) and
  `sparse_chain` (fingerprints client / infers visibility) are sent to the node.

#### L-1. CSPRNG seeded once, never reseeded
- `src/crypto/random.c:103-121` — the global Keccak sponge takes 32 bytes of system entropy at
  startup and is never re-mixed. Standard practice, but offers no defense-in-depth if the state
  is ever compromised in a long-running daemon.

#### L-2. Verbose peer-IP logging
- `src/Core/Node_P2PProtocolBytecoin.cpp:147-172`, `src/Core/Node.cpp:76,81` — peer addresses are
  logged at INFO/TRACE, building a local connection history.

---

## Severity summary

| ID | Severity | Title |
|----|----------|-------|
| C-1 | Critical | Transparent amounts (no RingCT) |
| C-2 | Critical | Per-denomination rings |
| C-3 | Critical | Min ring size 3, not consensus-enforced (zero-mixin accepted) |
| C-4 | Critical | Remote-node mode collapses the ring |
| C-5 | Critical, partially remediated | Dandelion++ implemented; transport anonymity and adversarial validation remain |
| M-1 | Medium | Archive stores source IP per transaction |
| M-2 | Medium | Wallet leaks creation timestamp + sparse chain |
| L-1 | Low | CSPRNG seeded once, never reseeded |
| L-2 | Low | Verbose peer-IP logging |
| Q-1 | Critical (industry-wide) | Not quantum-resistant — CRQC breaks supply integrity and privacy |

Supply integrity (counterfeiting) is **sound under classical assumptions** — no inflation vector
was found. See the dedicated section above.

---

## Supply integrity — can you counterfeit coins?

**Short answer: No, not under classical computing.** I looked specifically for inflation /
mint-from-nothing vectors. All standard CryptoNote counterfeiting paths are closed:

| Counterfeit vector | Status | Evidence |
|--------------------|--------|----------|
| Coinbase over-reward (miner mints extra) | **Blocked** | Block reward must *exactly* equal the deterministically computed emission: `if (miner_reward != info->reward) throw "Block reward mismatch"` (`BlockChainState.cpp:357`). Emission = `(money_supply - already_generated_coins) >> EMISSION_SPEED_FACTOR` (`Currency.cpp:265`), and the coinbase builder asserts `summary_amounts == block_reward` (`Currency.cpp:326`). |
| Output-sum integer overflow (the classic 2014 CryptoNote inflation CVE) | **Blocked** | Every amount accumulation goes through `add_amount`, which refuses on `uint64` overflow (`CryptoNoteTools.hpp:40-45`); used at `BlockChainState.cpp:142,165`. |
| Spending more than you put in (input/output imbalance) | **Blocked** | `if (summary_output_amount > summary_input_amount && !coinbase) throw` (`BlockChainState.cpp:177`). |
| Amount substitution (claim a big `input.amount` while referencing tiny real outputs) | **Blocked** | Outputs are stored and looked up keyed by `(amount, stack_index)`: `read_hidden_amount_map(input.amount, ...)` (`BlockChainState.cpp:1273,1290`). An input claiming amount A can only reference real outputs recorded under amount A. |
| Double-spend (reuse an output) | **Blocked** | Key images are unique chain-wide (`BlockChainState.cpp:56,167,734,901`). |
| Spending outputs you don't own (forging a ring signature) | **Blocked (classically)** | Ring signatures are batch-verified in `redo_block` via `m_ring_checker` (`BlockChainState.cpp:999-1008`) for all blocks above the latest hard checkpoint. Forging one requires solving the elliptic-curve discrete log — see quantum section. |

Blocks *below* the most recent hard checkpoint skip signature/output verification
(`check_sigs = !is_in_hard_checkpoint_zone`, `BlockChainState.cpp:998`). This is standard
fast-sync practice and not an inflation vector, since those blocks are pinned by checkpoint
hashes.

**Conclusion:** The monetary integrity of the chain is sound. No mint-from-nothing or
counterfeiting vector was found under classical cryptographic assumptions.

---

## Quantum resistance — Q-1 (CRITICAL, but industry-wide)

**Bytecoin is NOT quantum-resistant. A cryptographically-relevant quantum computer (CRQC)
breaks not just privacy but the money itself.**

Every security property rests on the elliptic-curve discrete-log problem (ECDLP) over
**ed25519 / Curve25519** (`src/crypto/bernstein/fe_25_5.c`, `fe_51.c` — field arithmetic mod
2²⁵⁵−19; all keys, signatures, key images, and stealth addresses use `ge_*`/`fe_*` group ops).
There is **zero** post-quantum cryptography in the tree — a search for Dilithium/Kyber/SPHINCS+/
XMSS/Lamport/Winternitz/lattice/Falcon returns nothing (the only `quantum` hits are BIP39
mnemonic words).

Shor's algorithm solves ECDLP in polynomial time, which means under a CRQC an attacker can:

1. **Counterfeit/steal at will (catastrophic).** Recover the secret spend key from any public
   key, then forge ring signatures with valid key images and spend *any* output. Because
   amounts are transparent (C-1), the attacker can target the largest UTXOs first. This is
   effectively unlimited counterfeiting.
2. **Drain any known address.** Addresses embed the public spend key `S` and view key `V`
   (`CryptoNote.hpp:141-153`); anyone holding an address can derive its keys and sweep it.
3. **Retroactively destroy privacy.** Recovering view keys unmasks every stealth address and
   de-anonymizes the entire historical chain.

What survives a CRQC: the **hash functions and PoW** (Keccak, CryptoNight) are only quadratically
weakened by Grover, so 256-bit outputs retain ~128-bit security — mining and block hashing are
fine. The problem is exclusively the signature/key system.

**Important context:** this is **not** a Bytecoin-specific flaw — Bitcoin, Monero, Ethereum, and
essentially every deployed ECDSA/EdDSA/ring-signature chain share it. No production cryptocurrency
is quantum-safe today. But the question was whether *this* chain is "unbreakable even with quantum
computers," and the answer is an unambiguous **no**, with no in-code migration path (no PQ scheme,
no hash-based fallback, no key-rotation mechanism).

**Remediation (long-horizon):** would require a hard fork to a post-quantum signature scheme
(e.g. hash-based or lattice-based), which is an unsolved problem for ring-signature privacy chains
industry-wide.

---

## Verdict

As a functioning CryptoNote currency, Bytecoin is competently engineered and the known
historical CryptoNote breaks are patched. As a **privacy** coin in 2026 it is weak: transparent
amounts + tiny per-denomination rings + a consensus-unenforced minimum ring size + remote-node
ring collapse + no network-origin privacy make its transaction graph highly analyzable. Treat its
privacy as *best-effort and breakable*, not as a strong guarantee.
