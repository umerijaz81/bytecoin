#!/usr/bin/env python3

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "onyx_verifier_load", ROOT / "tools" / "onyx_verifier_load.py"
)
LOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOAD)
sys.path.insert(0, str(ROOT / "tests" / "network"))
PROCESS_SPEC = importlib.util.spec_from_file_location(
    "onyx_verifier_load_process",
    ROOT / "tests" / "network" / "test_onyx_verifier_load_process.py",
)
PROCESS = importlib.util.module_from_spec(PROCESS_SPEC)
PROCESS_SPEC.loader.exec_module(PROCESS)


class OnyxVerifierLoadUnitTests(unittest.TestCase):
    def test_transaction_inputs_are_canonical_distinct_hex(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plain = root / "plain.hex"
            wrapped = root / "wrapped.json"
            plain.write_text("00 aa\n", encoding="utf-8")
            wrapped.write_text('{"binary_transaction":"01bb"}\n', encoding="utf-8")
            transactions = LOAD.read_transactions([plain, wrapped])
            self.assertEqual([transaction["bytes"] for transaction in transactions], [2, 2])
            self.assertNotEqual(transactions[0]["sha256"], transactions[1]["sha256"])
            duplicate = root / "duplicate.hex"
            duplicate.write_text("00aa", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate transaction"):
                LOAD.read_transactions([plain, duplicate])

    def test_metrics_default_to_zero_and_responses_classify(self):
        metrics = LOAD.normalized_metrics({"result": {"onyx_verifier_acquired": 7}})
        self.assertEqual(metrics["onyx_verifier_acquired"], 7)
        self.assertEqual(metrics["onyx_verifier_active"], 0)
        self.assertEqual(metrics["onyx_verifier_precheck_conflicts"], 0)
        self.assertEqual(metrics["onyx_verifier_abandoned_rpcs"], 0)
        self.assertEqual(metrics["onyx_verifier_pending_retries"], 0)
        self.assertEqual(metrics["onyx_verifier_retry_sources"], 0)
        self.assertEqual(metrics["onyx_verifier_retry_requests"], 0)
        self.assertEqual(LOAD.classify({"result": {}}), "accepted")
        self.assertEqual(
            LOAD.classify({"error": {"code": LOAD.VERIFIER_BUSY}}), "verifier_busy"
        )
        self.assertEqual(LOAD.classify({"transport_error": "timeout"}), "transport_error")

    def test_current_process_sampling_is_nonzero(self):
        sample = LOAD.process_sample(os.getpid())
        self.assertGreater(sample["rss_bytes"], 0)
        self.assertGreaterEqual(sample["cpu_seconds"], 0)

    def test_reciprocal_retry_counters_allow_one_alternate_body_race(self):
        def bounded(requests, rejections):
            return PROCESS.reciprocal_retry_counters_bounded(
                {
                    "retry_requests_before": 4,
                    "retry_requests_after_retry": 4 + requests,
                    "rejected_global_before": 7,
                    "rejected_global_after_retry": 7 + rejections,
                }
            )

        self.assertTrue(bounded(1, 1))
        self.assertTrue(bounded(1, 2))
        self.assertTrue(bounded(2, 2))
        self.assertTrue(bounded(2, 3))
        self.assertFalse(bounded(0, 1))
        self.assertFalse(bounded(1, 3))
        self.assertFalse(bounded(3, 3))


if __name__ == "__main__":
    unittest.main()
