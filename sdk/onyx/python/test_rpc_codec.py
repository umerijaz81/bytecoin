import json
import pathlib
import re
import unittest

from bytecoin_onyx import PROFILE_NAME, WalletRpcCodec, WalletRpcError


HERE = pathlib.Path(__file__).resolve().parent
PROFILE_SOURCE = HERE.parent / "v1" / "wallet-rpc.json"
PROFILE_PACKAGED = HERE / "bytecoin_onyx" / "wallet_rpc_v1.json"
FIXTURES = HERE.parent / "v1" / "fixtures" / "wallet-rpc.json"


class WalletRpcCodecTests(unittest.TestCase):
    def setUp(self):
        self.codec = WalletRpcCodec()

    def test_packaged_profile_matches_source_contract(self):
        source = json.loads(PROFILE_SOURCE.read_text(encoding="utf-8"))
        packaged = json.loads(PROFILE_PACKAGED.read_text(encoding="utf-8"))
        self.assertEqual(source, packaged)
        self.assertEqual(source["profile"], PROFILE_NAME)
        self.assertEqual(tuple(sorted(source["methods"])), self.codec.methods)

    def test_package_version_matches_project_metadata(self):
        from bytecoin_onyx import __version__

        project = (HERE / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version = "([^"]+)"$', project, flags=re.MULTILINE)
        self.assertIsNotNone(version)
        self.assertEqual(version.group(1), __version__)

    def test_all_golden_requests_and_responses(self):
        fixture = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertEqual(fixture["profile"], PROFILE_NAME)
        self.assertEqual(len(fixture["cases"]), len(self.codec.methods))
        for case in fixture["cases"]:
            request = case["request"]
            with self.subTest(method=request["method"]):
                self.assertEqual(
                    request,
                    self.codec.request(request["method"], request["params"], request_id=request["id"]),
                )
                self.assertEqual(
                    case["response"]["result"],
                    self.codec.validate_response(
                        request["method"], case["response"], request_id=request["id"]
                    ),
                )
                self.assertEqual(
                    self.codec.canonical_json(request),
                    json.dumps(request, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
                )

    def test_unknown_fields_and_incomplete_results_fail_closed(self):
        with self.assertRaises(ValueError):
            self.codec.request("get_onyx_status", {"unexpected": True})
        with self.assertRaises(ValueError):
            self.codec.request("create_onyx_transaction", {"address": "onyx1"})
        with self.assertRaises(ValueError):
            self.codec.validate_response(
                "get_onyx_status", {"jsonrpc": "2.0", "id": 1, "result": {"balance": 1}}
            )
        with self.assertRaises(ValueError):
            self.codec.validate_response(
                "get_onyx_asset_balance",
                {"jsonrpc": "2.0", "id": 1, "result": {"balance": 1, "unspent_note_count": 1, "extra": 1}},
            )
        with self.assertRaises(ValueError):
            self.codec.validate_response(
                "get_onyx_status",
                {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "ambiguous"}},
            )

    def test_json_rpc_errors_are_typed(self):
        with self.assertRaises(WalletRpcError) as raised:
            self.codec.validate_response(
                "get_onyx_status",
                {"jsonrpc": "2.0", "id": 3, "error": {"code": -5, "message": "inactive"}},
                request_id=3,
            )
        self.assertEqual(raised.exception.code, -5)


if __name__ == "__main__":
    unittest.main()
