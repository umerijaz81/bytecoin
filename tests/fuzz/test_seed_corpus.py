#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import re
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "generate_seed_corpus", ROOT / "tools" / "fuzz" / "generate_seed_corpus.py"
)
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


class SeedCorpusTest(unittest.TestCase):
    def test_all_harness_selectors_have_a_seed(self) -> None:
        seeds = GENERATOR.seeds()
        selectors = {seed[0] for seed in seeds}
        harness = (ROOT / "src" / "main_fuzzer.cpp").read_text(encoding="utf-8")
        harness_selectors = {int(value) for value in re.findall(r"\bcase\s+(\d+)\s*:", harness)}
        self.assertEqual(harness_selectors, set(GENERATOR.SELECTORS))
        self.assertEqual(harness_selectors, selectors)
        self.assertTrue(all(seeds))
        self.assertIn(b"\x8a\x80\x80\x40", seeds)
        self.assertTrue(any(seed.startswith(b"\x00" + GENERATOR.KV_HEADER) for seed in seeds))
        self.assertTrue(any(b"\x01a\x08\x01\x01a\x08\x02" in seed for seed in seeds))
        self.assertIn(b"\xc8{\"method\":\"a\",\"\\u006dethod\":\"b\"}", seeds)

    def test_generation_is_deterministic_and_preserves_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            finding = output / "crash-regression"
            finding.write_bytes(b"do-not-delete")
            first_count = GENERATOR.write_corpus(output)
            first = {
                path.name: path.read_bytes()
                for path in output.iterdir()
                if path.name != finding.name
            }
            second_count = GENERATOR.write_corpus(output)
            second = {
                path.name: path.read_bytes()
                for path in output.iterdir()
                if path.name != finding.name
            }
            self.assertEqual(first_count, second_count)
            self.assertEqual(first, second)
            self.assertEqual(b"do-not-delete", finding.read_bytes())
            for name, data in first.items():
                self.assertEqual(hashlib.sha256(data).hexdigest(), name)


if __name__ == "__main__":
    unittest.main()
