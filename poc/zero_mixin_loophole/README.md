# PoC: Zero-Mixin / Consensus-Unenforced Ring Size (Finding C-3)

## Claim

Bytecoin's minimum ring size (`MINIMUM_ANONYMITY_AMETHYST = 3`) is enforced **only by the
wallet** when it *builds* a transaction. The consensus/mempool validator that decides whether to
*accept* a transaction never checks how many ring members an input has. Therefore a transaction
with **ring size 1 (zero mixin)** — a fully traceable, non-private spend — is accepted as valid
by the network.

A zero-mixin spend is not just self-harm: it lets anyone deterministically mark that output as
spent, and the node's own "chain-reaction" pass (`BlockChainState.cpp:1268-1308`) then removes it
from the decoy pool, shrinking the effective anonymity of *every other* ring that used it as a
decoy.

## The two code paths

**Enforcement exists only here (wallet, when building):**
```
src/Core/WalletNode.cpp:469
  const auto min_anonymity  = m_currency.minimum_anonymity(get_wallet_state().get_tip().major_version);
  const auto good_anonymity = std::max(min_anonymity, request.transaction.anonymity);
```
A modified wallet that ignores `min_anonymity` (or any third-party tool that crafts a raw tx) is
not subject to this.

**Acceptance is gated only here (consensus + mempool), with NO ring-size check:**
```
src/Core/BlockChainState.cpp:117  validate_tx_semantic(...)
  - checks output amount != 0
  - checks amount overflow
  - checks output pubkey / encrypted_secret subgroup membership
  - checks key-image uniqueness within the tx
  - checks key-image subgroup membership
  - checks sum(outputs) <= sum(inputs)
  - DOES NOT check in->output_indexes.size()   <-- the loophole

src/Core/BlockChainState.cpp:738  add_transaction(...) -> validate_tx_semantic(...)
  (mempool ingress gates solely on validate_tx_semantic; no ring-size check either)
```

## Reproduce — static proof (runs anywhere, no build)

`verify_no_ringsize_check.py` parses the *actual* body of `validate_tx_semantic` out of the
repository source and asserts:

1. the function inspects `output_indexes` only via `relative_output_offsets_to_absolute`
   (offset decoding), and
2. it contains **no** comparison of the ring-member count against `minimum_anonymity` /
   `MINIMUM_ANONYMITY_AMETHYST` / any size threshold, while
3. the wallet build path **does** reference `minimum_anonymity`.

```
python3 poc/zero_mixin_loophole/verify_no_ringsize_check.py
```
Expected: `PROVEN: consensus accepts ring size 1 (no minimum-ring-size check)`.

## Reproduce — dynamic proof (drop-in unit test)

`drop_in_test.cpp` is a ready-to-integrate test that builds a minimal `Transaction` with a single
`InputKey` whose `output_indexes` has length 1 (ring size 1) and runs it through the same
`validate_tx_semantic` logic, asserting it is accepted. Build instructions are in the file header.
It requires linking against the project core, so it is provided as a patch-in rather than a
standalone binary.

## Suggested fix

In `validate_tx_semantic`, inside the `InputKey` branch (around `src/Core/BlockChainState.cpp:162`):

```cpp
// Consensus-enforced minimum ring size (mirrors wallet-side minimum_anonymity).
if (block_major_version >= currency.amethyst_block_version &&
    in->output_indexes.size() < currency.minimum_anonymity(block_major_version) + 1)
    throw ConsensusError(common::to_string(
        "Ring size too small", in->output_indexes.size(),
        "minimum", currency.minimum_anonymity(block_major_version) + 1));
```

This must ship in a hard fork so the rule applies uniformly from a fixed height.
