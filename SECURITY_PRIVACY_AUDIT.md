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

#### C-5. No transaction-origin (network) privacy
Transactions are flooded to all peers immediately, with no Dandelion(++) stem phase or relay
delay:

- `src/Core/Node.cpp:752-753` — on receipt, `broadcast(nullptr, raw_msg_v4)`.
- `src/Core/Node.cpp:382-386` — `broadcast()` sends to every peer at once.

A well-connected observer correlates first-seen propagation to the **originating IP address**.

**Remediation:** Implement Dandelion++ relay; document Tor/I2P usage.

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
| C-5 | Critical | No Dandelion / transaction-origin privacy |
| M-1 | Medium | Archive stores source IP per transaction |
| M-2 | Medium | Wallet leaks creation timestamp + sparse chain |
| L-1 | Low | CSPRNG seeded once, never reseeded |
| L-2 | Low | Verbose peer-IP logging |

## Verdict

As a functioning CryptoNote currency, Bytecoin is competently engineered and the known
historical CryptoNote breaks are patched. As a **privacy** coin in 2026 it is weak: transparent
amounts + tiny per-denomination rings + a consensus-unenforced minimum ring size + remote-node
ring collapse + no network-origin privacy make its transaction graph highly analyzable. Treat its
privacy as *best-effort and breakable*, not as a strong guarantee.
