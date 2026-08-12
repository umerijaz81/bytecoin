import argparse
import unittest

from tools.onyx.snapshot_corruption_campaign import parse_result
from tools.onyx.snapshot_limit_campaign import checks


class SnapshotCorruptionCampaignTests(unittest.TestCase):
    def test_result_requires_identity_and_complete_classification(self):
        seed = 0x1234
        parsed = parse_result(
            "test ... ONYX_SNAPSHOT_CORRUPTION_RESULT "
            f"seed=0x{seed:016x} cases=100 targeted=6 rejected=80 "
            "accepted_current=20 accepted_migrated=0 max_input_bytes=1083",
            seed,
            100,
        )
        self.assertEqual(parsed["rejected"], 80)
        with self.assertRaisesRegex(ValueError, "do not sum"):
            parse_result(
                "ONYX_SNAPSHOT_CORRUPTION_RESULT "
                f"seed=0x{seed:016x} cases=100 targeted=6 rejected=79 "
                "accepted_current=20 accepted_migrated=0 max_input_bytes=1083",
                seed,
                100,
            )

    def test_shared_resource_checks_require_samples(self):
        args = argparse.Namespace(
            timeout_per_case=10.0,
            max_case_cpu_seconds=None,
            max_case_rss_mib=None,
            max_case_output_mib=None,
        )
        measured = {
            "elapsed_seconds": 1.0,
            "cpu_seconds": 1.0,
            "peak_rss_bytes": 0,
            "output_bytes": 10,
            "sample_count": 0,
        }
        self.assertFalse(checks(args, measured)["resource_samples_observed"])


if __name__ == "__main__":
    unittest.main()
