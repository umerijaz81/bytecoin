# Onyx Python SDK binding

`bytecoin-onyx-sdk` is the dependency-free Python distribution for ABI/profile v1. It exposes the
offline capped-token descriptor helper, fail-closed wallet RPC codec, and canonical application-data builders
for the four standard programs. It deliberately does not
hide wallet RPC or transaction relay behind implicit network behavior.

Build the deterministic wheel without downloading dependencies or requiring setuptools:

```text
python -m pip wheel --no-deps --no-build-isolation sdk/onyx/python
```

```python
from bytecoin_onyx import OnyxSdk, WalletRpcCodec, vesting_application

sdk = OnyxSdk("path/to/onyx_sdk.dll")
descriptor = sdk.token_program_descriptor(
    issuer=bytes.fromhex("...64 hex characters..."),
    max_supply=1_000_000,
    metadata="symbol=TEST;decimals=8",
    activation_height=123_500,
    deactivation_height=0,
    circuit_k=20,
)
print(descriptor.program_id.hex())

codec = WalletRpcCodec()
request = codec.request("get_onyx_status", {"address_index": 0}, request_id="status")
# Send `request` with an authenticated transport chosen by the application, decode JSON, then:
# result = codec.validate_response("get_onyx_status", response, request_id="status")

application_data = vesting_application(
    schedule_id=bytes.fromhex("...64 hex characters..."),
    beneficiary=bytes.fromhex("...64 hex characters..."),
    unlock_height=150_000,
)
```

The normal repository build emits a static Rust library for the C++ node. Applications using Python
must package the same exported C ABI as a shared library. The binding rejects an ABI mismatch, checks
all scalar/length constraints before crossing FFI, copies returned bytes, and calls `onyx_free`
exactly once on success.

The checked-in package is semantically versioned as `1.1.0`. `COMPATIBILITY.md` defines what may
change in patch/minor releases. The packaged wallet RPC profile is byte-for-byte compared with the
source profile, and `../v1/fixtures/wallet-rpc.json` covers every v1 method.

Run the binding tests without a native library:

```text
python -m unittest discover -s sdk/onyx/python -p "test_*.py"
```
