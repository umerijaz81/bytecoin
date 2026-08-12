import argparse
import unittest

from tools.onyx.state_model_campaign import (
    minimized_requested_steps,
    parse_divergence,
    parse_seed,
    parse_summary,
    resource_checks,
)


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

    def test_divergence_parser_derives_minimal_requested_prefix(self):
        output = (
            "thread panicked at 'Onyx state-model divergence: commitment root mismatch; "
            "seed=0x0000000000001234; step=37; "
            "shortest_prefix=[Bridge { height: 1 }]'\n"
        )
        divergence = parse_divergence(output)
        self.assertEqual(
            divergence,
            {
                "message": "commitment root mismatch",
                "seed": "0x0000000000001234",
                "step": 37,
            },
        )
        self.assertEqual(minimized_requested_steps(divergence), 38)
        self.assertEqual(
            minimized_requested_steps({"message": "early", "seed": "0x1", "step": 3}),
            10,
        )

    def test_resource_checks_enforce_every_configured_ceiling(self):
        args = argparse.Namespace(
            timeout_per_seed=10.0,
            max_seed_cpu_seconds=5.0,
            max_seed_rss_mib=64.0,
            max_seed_output_mib=1.0,
        )
        measured = {
            "elapsed_seconds": 9.0,
            "cpu_seconds": 4.0,
            "peak_rss_bytes": 63 * 1024 * 1024,
            "sample_count": 2,
            "output": "ok",
        }
        self.assertTrue(all(resource_checks(args, measured).values()))
        measured["cpu_seconds"] = 6.0
        self.assertFalse(resource_checks(args, measured)["cpu_time_within_limit"])


if __name__ == "__main__":
    unittest.main()
