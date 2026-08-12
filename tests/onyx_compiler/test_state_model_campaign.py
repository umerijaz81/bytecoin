import unittest

from tools.onyx.state_model_campaign import parse_seed, parse_summary


class StateModelCampaignTests(unittest.TestCase):
    def test_summary_requires_every_operation_family(self):
        seed = 0x1234
        fields = {
            "seed": f"0x{seed:016x}",
            "requested_steps": "100",
            "trace_steps": "90",
            "checkpoints": "70",
            "snapshot_bytes": "512",
            "root": "ab" * 32,
            "bridge": "2",
            "transfer": "3",
            "deployment": "2",
            "issuance": "1",
            "contextual": "1",
            "rejection": "4",
            "undo": "5",
            "fork": "6",
            "reopen": "7",
        }
        line = "test state_model ... ONYX_STATE_MODEL_RESULT " + " ".join(
            f"{key}={value}" for key, value in fields.items()
        )
        parsed = parse_summary(line, seed, 100)
        self.assertEqual(parsed["seed"], "0x0000000000001234")
        self.assertEqual(parsed["trace_steps"], 90)
        fields["fork"] = "0"
        invalid = "ONYX_STATE_MODEL_RESULT " + " ".join(
            f"{key}={value}" for key, value in fields.items()
        )
        with self.assertRaisesRegex(ValueError, "zero coverage: fork"):
            parse_summary(invalid, seed, 100)

    def test_seed_parser_is_bounded_and_nonzero(self):
        self.assertEqual(parse_seed("0xffffffffffffffff"), (1 << 64) - 1)
        for value in ("0", "0x10000000000000000"):
            with self.assertRaises(Exception):
                parse_seed(value)


if __name__ == "__main__":
    unittest.main()
