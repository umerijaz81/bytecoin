import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { WalletRpcCodec, WalletRpcError, PROFILE_NAME } from "./index.js";

const fixtures = JSON.parse(
  await readFile(new URL("../v1/fixtures/wallet-rpc.json", import.meta.url), "utf8"),
);
const codec = new WalletRpcCodec();
assert.equal(fixtures.profile, PROFILE_NAME);
assert.equal(fixtures.cases.length, codec.methods.length);

for (const entry of fixtures.cases) {
  const { method, params, id } = entry.request;
  assert.deepEqual(codec.request(method, params, id), entry.request);
  assert.deepEqual(codec.validateResponse(method, entry.response, id), entry.response.result);
}

assert.throws(() => codec.request("unknown", {}), RangeError);
assert.throws(
  () => codec.request("get_onyx_status", { address_index: 0, extra: true }),
  /unknown extra/,
);
assert.throws(
  () => codec.validateResponse("get_onyx_status", fixtures.cases[0].response, "wrong"),
  /does not match/,
);
assert.throws(
  () => codec.validateResponse("get_onyx_status", { jsonrpc: "2.0", id: 1, error: { code: -1, message: "no" } }),
  WalletRpcError,
);
assert.equal(
  WalletRpcCodec.canonicalJson({ z: { b: 2, a: 1 }, a: true }),
  '{"a":true,"z":{"a":1,"b":2}}',
);
console.log("Onyx TypeScript SDK golden and negative tests passed");
