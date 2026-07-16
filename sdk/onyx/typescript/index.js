import profile from "./wallet-rpc-v1.json" with { type: "json" };

export const PROFILE_NAME = "bytecoin-onyx-wallet-rpc-v1";

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
