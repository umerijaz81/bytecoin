import unittest

from tests.network.test_onyx_db_ioerr_process import fault_case_passed


class OnyxIoFaultQualificationUnitTests(unittest.TestCase):
    def test_requires_exact_fault_identity_and_recovery(self) -> None:
        passing = {
            "expected_extended_code": 778,
            "expected_target": "journal",
            "expected_operation": "write",
            "expected_stage": "state",
            "fault": {
                "sqlite_primary_code": 10,
                "sqlite_extended_code": 778,
                "trigger_count": 1,
                "target": "journal",
                "operation": "write",
                "stage": "state",
            },
            "recovery": {"return_code": 0},
            "independent_before": {"exact_before": True},
            "independent_after": {"integrity": "ok", "exact_before": True},
        }
        self.assertTrue(fault_case_passed(passing))
        mutations = (
            ("fault", "sqlite_primary_code", 13),
            ("fault", "sqlite_extended_code", 1034),
            ("fault", "trigger_count", 0),
            ("fault", "target", "database"),
            ("fault", "operation", "sync"),
            ("fault", "stage", "commit"),
            ("recovery", "return_code", 89),
            ("independent_before", "exact_before", False),
            ("independent_after", "integrity", "corrupt"),
            ("independent_after", "exact_before", False),
        )
        for section, field, value in mutations:
            failing = {key: dict(item) if isinstance(item, dict) else item for key, item in passing.items()}
            failing[section][field] = value
            self.assertFalse(fault_case_passed(failing))


if __name__ == "__main__":
    unittest.main()
