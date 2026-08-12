import pathlib
import tempfile
import unittest

from tests.network.test_onyx_db_corruption_process import mutate_journal, mutate_main


class OnyxDatabaseCorruptionUnitTests(unittest.TestCase):
    def test_payload_mutation_is_bounded_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "blockchain.sqlite"
            path.write_bytes(b"prefix" + b"snapshot-after" + b"suffix")
            result = mutate_main(path, "state-payload-flip")
            self.assertEqual(result["size"], len(b"prefixsnapshot-aftersuffix"))
            self.assertNotEqual(path.read_bytes(), b"prefixsnapshot-aftersuffix")

    def test_journal_truncation_records_input_and_output_sizes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "blockchain.sqlite-journal"
            path.write_bytes(bytes(range(32)))
            result = mutate_journal(path, "truncate-half")
            self.assertEqual(result["original_size"], 32)
            self.assertEqual(result["size"], 16)


if __name__ == "__main__":
    unittest.main()
