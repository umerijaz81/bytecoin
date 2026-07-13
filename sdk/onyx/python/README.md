# Onyx Python SDK binding

`onyx_sdk.py` is a dependency-free Python 3 binding for ABI profile v1. It currently exposes the
offline capped-token descriptor helper and deliberately does not hide wallet RPC or transaction relay
behind implicit network behavior.

```python
from onyx_sdk import OnyxSdk

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
```

The normal repository build emits a static Rust library for the C++ node. Applications using Python
must package the same exported C ABI as a shared library. The binding rejects an ABI mismatch, checks
all scalar/length constraints before crossing FFI, copies returned bytes, and calls `onyx_free`
exactly once on success.

Run the binding tests without a native library:

```text
python -m unittest discover -s sdk/onyx/python -p "test_*.py"
```
