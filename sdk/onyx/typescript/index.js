import profile from "./wallet-rpc-v1.json" with { type: "json" };

export const PROFILE_NAME = "bytecoin-onyx-wallet-rpc-v1";
export const STANDARD_APPLICATION_VERSION = 1;
export const PASTA_FP_MODULUS = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
export const STANDARD_SCHEMA_HASHES = Object.freeze({
  nft: "204730978f788b8d1e458ee81c1c12ff39d0444f174fe9d192246d80890bb132",
  vesting: "c36efa02930c2551179a949214f1a181720ddd8364e44a197c7a0b756cd0862c",
  multisig: "8703b1c751de7881667f76507fdf7f04a30399da2c4b1bb27f8b91e86a5ba589",
  swap: "8738062476880a23afdd40b5c64c8ec2120d8c6981315dba90776266ddde4fce",
});

function checkedBytes32(value, name, field = false) {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new TypeError(`${name} must be exactly 32 bytes`);
  }
  let integer = 0n;
  for (let index = 31; index >= 0; index -= 1) integer = (integer << 8n) | BigInt(value[index]);
  if (integer === 0n) throw new RangeError(`${name} must be nonzero`);
  if (field && integer >= PASTA_FP_MODULUS) {
    throw new RangeError(`${name} must be a canonical Pasta field encoding`);
  }
  return new Uint8Array(value);
}

function checkedUint64(value, name, positive = false) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new RangeError(`${name} number must be a safe integer`);
    value = BigInt(value);
  }
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) {
    throw new RangeError(`${name} must be a uint64 bigint or safe integer`);
  }
  if (positive && value === 0n) throw new RangeError(`${name} must be positive`);
  return value;
}

function varint(value) {
  const result = [];
  do {
    let byte = Number(value & 0x7fn);
    value >>= 7n;
    if (value) byte |= 0x80;
    result.push(byte);
  } while (value);
  return Uint8Array.from(result);
}

function concatBytes(...values) {
  const output = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function nftApplication(collectionId, tokenId, serial, transferNonce) {
  return concatBytes(
    Uint8Array.of(STANDARD_APPLICATION_VERSION, 1),
    checkedBytes32(collectionId, "collectionId"),
    checkedBytes32(tokenId, "tokenId"),
    varint(checkedUint64(serial, "serial")),
    varint(checkedUint64(transferNonce, "transferNonce", true)),
  );
}

export function vestingApplication(scheduleId, beneficiary, unlockHeight) {
  return concatBytes(
    Uint8Array.of(STANDARD_APPLICATION_VERSION, 2),
    checkedBytes32(scheduleId, "scheduleId"),
    checkedBytes32(beneficiary, "beneficiary"),
    varint(checkedUint64(unlockHeight, "unlockHeight")),
  );
}

export function multisigApplication(policyCommitment, actionDigest, threshold, participantCount) {
  threshold = checkedUint64(threshold, "threshold", true);
  participantCount = checkedUint64(participantCount, "participantCount", true);
  if (participantCount > 16n || threshold > participantCount) {
    throw new RangeError("threshold must not exceed a participantCount in [1, 16]");
  }
  return concatBytes(
    Uint8Array.of(STANDARD_APPLICATION_VERSION, 3),
    checkedBytes32(policyCommitment, "policyCommitment", true),
    checkedBytes32(actionDigest, "actionDigest"),
    varint(threshold),
    varint(participantCount),
  );
}

export function swapApplication(swapId, hashlock, timeoutHeight, refund) {
  if (typeof refund !== "boolean") throw new TypeError("refund must be a boolean");
  return concatBytes(
    Uint8Array.of(STANDARD_APPLICATION_VERSION, 4),
    checkedBytes32(swapId, "swapId"),
    checkedBytes32(hashlock, "hashlock", true),
    varint(checkedUint64(timeoutHeight, "timeoutHeight")),
    Uint8Array.of(Number(refund)),
  );
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactFields(value, expected, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object`);
  const actual = Object.keys(value);
  const missing = expected.filter((field) => !Object.hasOwn(value, field)).sort();
  const allowed = new Set(expected);
  const unknown = actual.filter((field) => !allowed.has(field)).sort();
  if (missing.length || unknown.length) {
    const details = [];
    if (missing.length) details.push(`missing ${missing.join(", ")}`);
    if (unknown.length) details.push(`unknown ${unknown.join(", ")}`);
    throw new TypeError(`${label} fields: ${details.join("; ")}`);
  }
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (isObject(value)) {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export class WalletRpcError extends Error {
  constructor(code, message, data = undefined) {
    super(`wallet RPC error ${code}: ${message}`);
    this.name = "WalletRpcError";
    this.code = code;
    this.data = data;
  }
}

export class WalletRpcCodec {
  constructor() {
    if (profile.profile !== PROFILE_NAME || !isObject(profile.methods)) {
      throw new Error("packaged Onyx wallet RPC profile is invalid");
    }
  }

  get methods() {
    return Object.freeze(Object.keys(profile.methods).sort());
  }

  request(method, params = {}, requestId = 1) {
    const contract = profile.methods[method];
    if (!contract) throw new RangeError(`method ${JSON.stringify(method)} is not in ${PROFILE_NAME}`);
    exactFields(params, contract.request_fields, `invalid ${method} request`);
    return { jsonrpc: "2.0", id: requestId, method, params: { ...params } };
  }

  validateResponse(method, response, requestId = undefined) {
    const contract = profile.methods[method];
    if (!contract) throw new RangeError(`method ${JSON.stringify(method)} is not in ${PROFILE_NAME}`);
    if (!isObject(response) || response.jsonrpc !== "2.0" || !Object.hasOwn(response, "id")) {
      throw new TypeError("wallet RPC response must be a JSON-RPC 2.0 object with an id");
    }
    if (requestId !== undefined && response.id !== requestId) {
      throw new TypeError("wallet RPC response id does not match the request");
    }
    if (Object.hasOwn(response, "error")) {
      exactFields(response, ["jsonrpc", "id", "error"], "wallet RPC error response");
      const error = response.error;
      if (!isObject(error) || !Number.isInteger(error.code) || typeof error.message !== "string") {
        throw new TypeError("wallet RPC error object is malformed");
      }
      const unknown = Object.keys(error).filter((key) => !["code", "message", "data"].includes(key));
      if (unknown.length) throw new TypeError("wallet RPC error object has unknown fields");
      throw new WalletRpcError(error.code, error.message, error.data);
    }
    exactFields(response, ["jsonrpc", "id", "result"], "wallet RPC result response");
    exactFields(response.result, contract.response_fields, `invalid ${method} result`);
    return { ...response.result };
  }

  static canonicalJson(value) {
    if (!isObject(value)) throw new TypeError("canonical JSON root must be an object");
    return JSON.stringify(canonicalize(value));
  }
}
