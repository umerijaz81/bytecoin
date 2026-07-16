#!/usr/bin/env python3

from __future__ import annotations

import os
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "onyx"))
import structured_fuzz_v1  # noqa: E402


class StructuredCompilerFuzzTests(unittest.TestCase):
    def test_grammar_directed_differential_campaign(self) -> None:
        backend_value = os.environ.get("ONYX_COMPILER_BACKEND")
        backend = pathlib.Path(backend_value) if backend_value else None
        structured_fuzz_v1.run_campaign(48, backend=backend, backend_cases=8)

    def test_generation_is_seeded_bounded_and_reproducible(self) -> None:
        first = structured_fuzz_v1.generate_cases(64, 12345)
        second = structured_fuzz_v1.generate_cases(64, 12345)
        self.assertEqual(first, second)
        self.assertNotEqual(first, structured_fuzz_v1.generate_cases(64, 12346))
        with self.assertRaises(ValueError):
            structured_fuzz_v1.generate_cases(0)
        with self.assertRaises(ValueError):
            structured_fuzz_v1.generate_cases(10_001)


if __name__ == "__main__":
    unittest.main()
