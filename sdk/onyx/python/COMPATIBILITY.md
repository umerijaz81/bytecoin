# Compatibility policy

`bytecoin-onyx-sdk` follows semantic versioning independently from chain activation.

- Major version 1 implements Onyx SDK profile v1 and requires `ONYX_ZK_ABI_VERSION == 1`.
- Patch releases may fix validation or documentation without accepting new wire fields.
- Minor releases may add helpers or newly standardized RPC methods while preserving every existing
  signature, field name, ownership rule and encoded byte.
- Removing or reinterpreting a symbol/field, changing buffer ownership, or accepting a different
  consensus encoding requires a new package major version and ABI/profile directory.

The Python package performs no implicit network access. Applications choose their own authenticated
transport, use `WalletRpcCodec.request` to construct a bounded request, and pass the decoded response
to `WalletRpcCodec.validate_response`. Unknown methods and fields fail closed.
