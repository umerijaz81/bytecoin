# Onyx Legacy Migration Runbook

Onyx migration is a one-way shield operation. It consumes exactly one unlocked legacy output and
creates exactly one encrypted native-asset Onyx note. There is no implicit deshield path.

## Preconditions

- Run an Onyx-enabled `walletd` and synchronized `bytecoind` on the same configured network.
- Select one unlocked legacy output and record its exact amount and global stack index.
- Derive that output's secret key and canonical key image using the existing wallet or hardware
  signer. Never transmit the secret key.
- Obtain the destination from `get_onyx_status.address`.

## Construct, sign, finalize, relay

1. Call `create_onyx_bridge` with the destination, legacy amount, fee, stack index, key image,
   expiry, and optional encrypted memo.
2. Preserve the returned `unsigned_bridge` byte-for-byte.
3. Produce a one-member CryptoNote ring signature over `ownership_sighash`, using the selected
   output public key, its derived output secret key, and the supplied key image.
4. Call `finalize_onyx_bridge` with the unsigned bridge and 64-byte signature.
5. Persist the returned transaction hash and submit `binary_transaction` through
   `send_transaction`.
6. Wait for confirmation before treating the recovered Onyx note as spendable.

## Supply reconciliation

Call the node's `get_onyx_supply_audit` JSON-RPC method at a recorded block height. Its response
contains `total_bridged`, `total_fees`, `circulating_supply`, `commitment_count`, `program_count`,
`current_block_program_cost`, `commitment_root`, and `block_height`. Every valid snapshot satisfies:

```text
circulating_supply = total_bridged - total_fees
```

`total_bridged` is the gross value of consumed legacy outputs. `total_fees` includes bridge fees
and every subsequent shielded-transfer fee. Compare `total_bridged` against an independent scan of
accepted bridge transactions and their consumed legacy outputs. Archive the response, tip hash,
and software build identifier for each audit checkpoint.

## Consensus and recovery invariants

- The proof enforces `legacy_amount = note_value + fee`; zero-value and inflation attempts fail.
- The outer transaction and bridge envelope are canonical and network/expiry bound.
- Consensus independently resolves the legacy stack index, checks unlock status, recomputes the
  one-member ownership signature, and consumes the key image.
- The shielded commitment append and legacy key-image consumption occur in one block transition.
- Undo removes the key image and restores the previous serialized Onyx state. Replay on the active
  chain fails once the key image is spent.
- Wallet backups must include the Onyx seed and normal wallet database. Rescanning confirmed bridge
  envelopes deterministically rebuilds recovered notes and witnesses.

Before mainnet activation, operators must complete supply reconciliation, reorg/replay drills,
external review, and the release gates in `ONYX_PROTOCOL_SPEC.md`.
