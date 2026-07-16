"""Fail-closed, transport-independent codec for Onyx wallet RPC profile v1."""

from __future__ import annotations

import importlib.resources
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


PROFILE_NAME = "bytecoin-onyx-wallet-rpc-v1"


@dataclass(frozen=True)
class WalletRpcError(RuntimeError):
    code: int
    message: str
    data: Any = None

    def __str__(self) -> str:
        return f"wallet RPC error {self.code}: {self.message}"


def _load_profile() -> dict[str, Any]:
    resource = importlib.resources.files("bytecoin_onyx").joinpath("wallet_rpc_v1.json")
    profile = json.loads(resource.read_text(encoding="utf-8"))
    if profile.get("profile") != PROFILE_NAME or not isinstance(profile.get("methods"), dict):
        raise RuntimeError("packaged Onyx wallet RPC profile is invalid")
    return profile


class WalletRpcCodec:
    """Build and validate JSON-compatible objects without selecting a network transport."""

    def __init__(self) -> None:
        self._profile = _load_profile()

    @property
    def methods(self) -> tuple[str, ...]:
        return tuple(sorted(self._profile["methods"]))

    def request(self, method: str, params: Mapping[str, Any] | None = None, *, request_id: Any = 1) -> dict[str, Any]:
        contract = self._profile["methods"].get(method)
        if contract is None:
            raise ValueError(f"method {method!r} is not in {PROFILE_NAME}")
        if params is None:
            params = {}
        if not isinstance(params, Mapping):
            raise TypeError("params must be a mapping")
        expected = set(contract["request_fields"])
        missing = sorted(expected - set(params))
        unknown = sorted(set(params) - expected)
        if missing or unknown:
            details = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if unknown:
                details.append("unknown " + ", ".join(unknown))
            raise ValueError(f"invalid {method} request fields: {'; '.join(details)}")
        return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}

    def validate_response(self, method: str, response: Mapping[str, Any], *, request_id: Any = None) -> dict[str, Any]:
        contract = self._profile["methods"].get(method)
        if contract is None:
            raise ValueError(f"method {method!r} is not in {PROFILE_NAME}")
        if not isinstance(response, Mapping) or response.get("jsonrpc") != "2.0":
            raise ValueError("wallet RPC response must be a JSON-RPC 2.0 mapping")
        if "id" not in response:
            raise ValueError("wallet RPC response id is missing")
        if request_id is not None and response.get("id") != request_id:
            raise ValueError("wallet RPC response id does not match the request")
        if "error" in response:
            if set(response) != {"jsonrpc", "id", "error"}:
                raise ValueError("wallet RPC error response has unknown or conflicting fields")
            error = response["error"]
            if not isinstance(error, Mapping) or not isinstance(error.get("code"), int) or not isinstance(error.get("message"), str):
                raise ValueError("wallet RPC error object is malformed")
            if not set(error).issubset({"code", "message", "data"}):
                raise ValueError("wallet RPC error object has unknown fields")
            raise WalletRpcError(error["code"], error["message"], error.get("data"))
        if set(response) != {"jsonrpc", "id", "result"}:
            raise ValueError("wallet RPC result response has unknown or missing envelope fields")
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise ValueError("wallet RPC response result must be a mapping")
        expected = set(contract["response_fields"])
        missing = sorted(expected - set(result))
        unknown = sorted(set(result) - expected)
        if missing or unknown:
            details = []
            if missing:
                details.append("missing " + ", ".join(missing))
            if unknown:
                details.append("unknown " + ", ".join(unknown))
            raise ValueError(f"invalid {method} result fields: {'; '.join(details)}")
        return dict(result)

    @staticmethod
    def canonical_json(value: Mapping[str, Any]) -> str:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
