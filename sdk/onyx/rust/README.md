# Bytecoin Onyx SDK for Rust

`bytecoin-onyx-sdk` 1.1.0 is the dependency-free Rust binding for the frozen
`bytecoin-onyx-wallet-rpc-v1` profile. It performs no network access. Applications decode JSON with
their chosen stack, pass `JsonValue` objects through `WalletRpcCodec`, and send validated requests
over an authenticated transport.

The crate also provides byte-identical canonical application-data builders for NFT, vesting,
1–16-participant multisig and claim/refund swap programs. Identifiers, canonical Pasta fields,
thresholds and unsigned heights are checked before bytes reach an RPC or native proof boundary.

```rust
use bytecoin_onyx_sdk::{vesting_application, JsonObject, JsonValue, WalletRpcCodec};

let request = WalletRpcCodec::request(
    "get_onyx_status",
    JsonObject::from([("address_index".into(), JsonValue::from(0_u64))]),
    JsonValue::from("status-1"),
)?;
let application = vesting_application(&[3; 32], &[4; 32], 150_000)?;
# Ok::<(), bytecoin_onyx_sdk::SdkError>(())
```

Run the locked offline tests with:

```text
cargo test --locked --offline --manifest-path sdk/onyx/rust/Cargo.toml
```
