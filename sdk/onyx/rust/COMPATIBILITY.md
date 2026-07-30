# Compatibility policy

Version 1.1.0 implements `bytecoin-onyx-wallet-rpc-v1`. Patch releases may fix validation defects
without accepting previously invalid input. Minor releases may add helpers and additive RPC methods
while preserving existing request, response, ownership and byte-encoding contracts. Any incompatible
contract requires a new major version and a new frozen compatibility profile.

The crate intentionally has no runtime dependencies and no transport. Applications must authenticate
their selected wallet RPC transport and must not interpret an offline descriptor or application-data
blob as an authorized on-chain deployment.
