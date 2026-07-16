import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  WalletRpcCodec, WalletRpcError, PROFILE_NAME, PASTA_FP_MODULUS,
  STANDARD_SCHEMA_HASHES, multisigApplication, nftApplication, swapApplication,
  vestingApplication,
} from "./index.js";

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
const repeated = (value) => new Uint8Array(32).fill(value);
const field = (value) => {
  const result = new Uint8Array(32);
  result[0] = value;
  return result;
};
assert.equal(
  Buffer.from(nftApplication(repeated(1), repeated(2), 128n, 1n)).toString("hex"),
  `0101${"01".repeat(32)}${"02".repeat(32)}800101`,
);
assert.equal(
  Buffer.from(vestingApplication(repeated(3), repeated(4), 300n)).toString("hex"),
  `0102${"03".repeat(32)}${"04".repeat(32)}ac02`,
);
assert.equal(
  Buffer.from(multisigApplication(field(5), repeated(6), 2, 3)).toString("hex"),
  `0103${Buffer.from(field(5)).toString("hex")}${"06".repeat(32)}0203`,
);
assert.equal(
  Buffer.from(swapApplication(repeated(7), field(5), 9, true)).toString("hex"),
  `0104${"07".repeat(32)}${Buffer.from(field(5)).toString("hex")}0901`,
);
assert.equal(Object.keys(STANDARD_SCHEMA_HASHES).length, 4);
assert.throws(() => nftApplication(new Uint8Array(32), repeated(2), 0, 1), /nonzero/);
assert.throws(() => nftApplication(repeated(1), repeated(2), 0, 0), /positive/);
assert.throws(
  () => multisigApplication(Uint8Array.from(Buffer.from(PASTA_FP_MODULUS.toString(16).padStart(64, "0"), "hex")).reverse(), repeated(1), 1, 1),
  /canonical Pasta/,
);
assert.throws(() => multisigApplication(field(1), repeated(1), 3, 2), /threshold/);
assert.throws(() => swapApplication(repeated(1), field(1), 0, 1), /boolean/);
console.log("Onyx TypeScript SDK golden and negative tests passed");
