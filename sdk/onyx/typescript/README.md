# Bytecoin Onyx SDK for JavaScript and TypeScript

`@bytecoin/onyx-sdk` 1.0.0 implements the frozen
`bytecoin-onyx-wallet-rpc-v1` profile. It has no runtime dependencies and performs no network access.
Applications select an authenticated JSON transport, construct exact requests with `WalletRpcCodec`,
and validate decoded responses before using them.

```js
import { WalletRpcCodec } from "@bytecoin/onyx-sdk";

const codec = new WalletRpcCodec();
const request = codec.request("get_onyx_status", { address_index: 0 }, "status-1");
// Send request through the application's transport, then:
const result = codec.validateResponse("get_onyx_status", decodedResponse, "status-1");
```

Unknown methods, missing or additional fields, mismatched identifiers, malformed error objects and
non-JSON-RPC responses fail closed. This package is a transport/contract binding; proof construction
and descriptor derivation remain native operations exposed by the versioned Onyx C ABI.
