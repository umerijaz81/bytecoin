#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "verify_binary_reproducibility",
    ROOT / "tools" / "release" / "verify_binary_reproducibility.py",
)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class BinaryReproducibilityTest(unittest.TestCase):
    def populate(self, directory: pathlib.Path, suffix: str = "") -> None:
        for program in VERIFIER.PROGRAMS:
            (directory / program).write_bytes((program + suffix).encode())

    def test_identical_binaries_pass(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self.populate(pathlib.Path(first))
            self.populate(pathlib.Path(second))
            result = VERIFIER.compare(pathlib.Path(first), pathlib.Path(second))
            self.assertEqual(list(VERIFIER.PROGRAMS), [entry["name"] for entry in result])

    def test_binary_difference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            self.populate(pathlib.Path(first))
            self.populate(pathlib.Path(second))
            (pathlib.Path(second) / "walletd").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "walletd is not reproducible"):
                VERIFIER.compare(pathlib.Path(first), pathlib.Path(second))


if __name__ == "__main__":
    unittest.main()
