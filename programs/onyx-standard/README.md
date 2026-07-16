# Onyx standard constraint programs v1

This directory contains canonical source packages for four non-activated standard programs. Each package pins
the compiler and target profile, has no ambient dependencies, and lowers through the independently decoded
`ONXIR`/Halo2 backend at circuit size `k=16`.

| Package | Export | Constraint summary |
|---|---|---|
| `nft` | `transfer` | Proves knowledge of the current owner secret bound to collection, token, serial and prior state; requires a distinct nonzero next state and nonce. |
| `vesting` | `release` | Proves beneficiary-secret knowledge bound to schedule and beneficiary; requires the consensus-bound inclusion floor to reach the unlock height. |
| `multisig` | `authorize` | Supports 1–16 pairwise-distinct participant slots, action-bound secret approvals, inactive-slot zeroing, policy reconstruction and threshold counting. |
| `swap` | `settle` | Supports a preimage-bound claim branch or a zero-preimage refund branch after the consensus-bound timeout. |

All four require canonical changing prior/next Pasta-field state commitments. The native contextual decoder
derives every public suffix from canonical application data; callers cannot inject height, state, policy, or
hashlock instances independently. The tracked integration test builds each package twice, independently verifies
the bundles and descriptors, creates real randomized proofs, and rejects policy-specific mutations including
insufficient approvals and duplicate participants.

```text
python tools/onyx/compiler_v1.py programs/onyx-standard/nft <new-output> \
  --backend-executable vendor/onyx-zk/target/release/onyx-compiler-backend --circuit-k 16
python tools/onyx/verify_compiler_bundle_v1.py <new-output> \
  --backend-executable vendor/onyx-zk/target/release/onyx-compiler-backend
```

These packages remain non-activated pending consensus deployment/registry plumbing, wallet proving flows, independent
circuit review, sustained fuzzing, and testnet release gates.

Canonical offline application-data builders are available in `bytecoin-onyx-sdk` and
`@bytecoin/onyx-sdk` version 1.1.0. They construct only the native decoder's exact version-1 encoding; they do
not prove, submit, or activate a transaction.
