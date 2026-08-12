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
                "partial_bytes": 0,
                "requested_bytes": 0,
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
            ("fault", "partial_bytes", 1),
            ("fault", "requested_bytes", 512),
            ("recovery", "return_code", 89),
            ("independent_before", "exact_before", False),
            ("independent_after", "integrity", "corrupt"),
            ("independent_after", "exact_before", False),
        )
        for section, field, value in mutations:
            failing = {key: dict(item) if isinstance(item, dict) else item for key, item in passing.items()}
            failing[section][field] = value
            self.assertFalse(fault_case_passed(failing))

    def test_partial_write_requires_persisted_prefix(self) -> None:
        case = {
            "expected_extended_code": 778,
            "expected_target": "database",
            "expected_operation": "partial-write",
            "expected_stage": "commit",
            "fault": {
                "sqlite_primary_code": 10,
                "sqlite_extended_code": 778,
                "trigger_count": 1,
                "target": "database",
                "operation": "partial-write",
                "stage": "commit",
                "partial_bytes": 2048,
                "requested_bytes": 4096,
            },
            "recovery": {"return_code": 0},
            "independent_before": {"exact_before": True},
            "independent_after": {"integrity": "ok", "exact_before": True},
        }
        self.assertTrue(fault_case_passed(case))
        case["fault"]["partial_bytes"] = 0
        self.assertFalse(fault_case_passed(case))

    def test_first_and_final_byte_cut_points_are_exact(self) -> None:
        base = {
            "expected_extended_code": 778,
            "expected_target": "wal",
            "expected_operation": "partial-write",
            "expected_stage": "commit",
            "fault": {
                "sqlite_primary_code": 10,
                "sqlite_extended_code": 778,
                "trigger_count": 1,
                "target": "wal",
                "operation": "partial-write",
                "stage": "commit",
                "partial_bytes": 1,
                "requested_bytes": 32,
            },
            "recovery": {"return_code": 0},
            "independent_before": {"exact_before": True},
            "independent_after": {"integrity": "ok", "exact_before": True},
        }
        first = {**base, "name": "ioerr-wal-partial-first"}
        self.assertTrue(fault_case_passed(first))
        first["fault"]["partial_bytes"] = 2
        self.assertFalse(fault_case_passed(first))
        final = {**base, "name": "ioerr-wal-partial-final", "fault": dict(base["fault"])}
        final["fault"]["partial_bytes"] = 31
        self.assertTrue(fault_case_passed(final))
        final["fault"]["partial_bytes"] = 30
        self.assertFalse(fault_case_passed(final))


if __name__ == "__main__":
    unittest.main()
