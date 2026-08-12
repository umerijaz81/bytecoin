import argparse
import unittest

from tools.onyx.snapshot_limit_campaign import checks, parse_result


class SnapshotLimitCampaignTests(unittest.TestCase):
    def test_result_requires_exact_limit_and_identity(self):
        parsed = parse_result(
            "test ... ONYX_SNAPSHOT_LIMIT_RESULT "
            "kind=nullifiers count=1000000 snapshot_bytes=32000051",
            "nullifiers",
        )
        self.assertEqual(parsed["count"], 1_000_000)
        with self.assertRaisesRegex(ValueError, "kind mismatch"):
            parse_result(
                "ONYX_SNAPSHOT_LIMIT_RESULT "
                "kind=anchors count=1000000 snapshot_bytes=35000000",
                "nullifiers",
            )

    def test_resource_checks_fail_closed(self):
        args = argparse.Namespace(
            timeout_per_case=10.0,
            max_case_cpu_seconds=8.0,
            max_case_rss_mib=256.0,
            max_case_output_mib=1.0,
        )
        measured = {
            "elapsed_seconds": 9.0,
            "cpu_seconds": 7.0,
            "peak_rss_bytes": 255 * 1024 * 1024,
            "output_bytes": 100,
            "sample_count": 3,
        }
        self.assertTrue(all(checks(args, measured).values()))
        measured["peak_rss_bytes"] = 257 * 1024 * 1024
        self.assertFalse(checks(args, measured)["peak_rss_within_limit"])


if __name__ == "__main__":
    unittest.main()
