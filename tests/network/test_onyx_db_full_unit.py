import unittest

from tests.network.test_onyx_db_full_process import fault_case_passed


class OnyxDiskFullQualificationUnitTests(unittest.TestCase):
    def test_requires_sqlite_full_and_exact_pretransaction_state(self) -> None:
        passing = {
            "fault": {"sqlite_primary_code": 13},
            "recovery": {"return_code": 0},
            "independent_before": {"exact_before": True},
            "independent_after": {"integrity": "ok", "exact_before": True},
            "input_image": {"size": 8192, "sha256": "a" * 64},
            "output_image": {"size": 8192, "sha256": "a" * 64},
        }
        self.assertTrue(fault_case_passed(passing))
        for section, field, value in (
            ("fault", "sqlite_primary_code", 10),
            ("recovery", "return_code", 89),
            ("independent_after", "integrity", "malformed"),
            ("independent_after", "exact_before", False),
        ):
            failing = {key: dict(item) for key, item in passing.items()}
            failing[section][field] = value
            self.assertFalse(fault_case_passed(failing))
        changed = {key: dict(item) for key, item in passing.items()}
        changed["output_image"]["sha256"] = "b" * 64
        self.assertFalse(fault_case_passed(changed))


if __name__ == "__main__":
    unittest.main()
