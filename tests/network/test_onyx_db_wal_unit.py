import pathlib
import tempfile
import unittest

from tests.network.test_onyx_db_wal_process import (
    AFTER,
    BEFORE,
    WAL_FRAME_HEADER_SIZE,
    WAL_HEADER_SIZE,
    mutate_wal,
    wal_layout,
)


def synthetic_wal() -> bytes:
    page_size = 512
    header = bytearray(WAL_HEADER_SIZE)
    header[0:4] = bytes.fromhex("377f0682")
    header[8:12] = page_size.to_bytes(4, "big")
    first_header = bytearray(WAL_FRAME_HEADER_SIZE)
    first_header[0:4] = (1).to_bytes(4, "big")
    first_header[4:8] = (2).to_bytes(4, "big")
    first_page = bytearray(page_size)
    first_page[10 : 10 + len(BEFORE)] = BEFORE
    second_header = bytearray(WAL_FRAME_HEADER_SIZE)
    second_header[0:4] = (2).to_bytes(4, "big")
    second_header[4:8] = (2).to_bytes(4, "big")
    second_page = bytearray(page_size)
    second_page[20 : 20 + len(AFTER)] = AFTER
    second_page[60 : 60 + len(BEFORE)] = BEFORE
    return bytes(header + first_header + first_page + second_header + second_page)


class OnyxWalQualificationUnitTests(unittest.TestCase):
    def test_layout_records_frames_and_commit_boundaries(self) -> None:
        layout = wal_layout(synthetic_wal())
        self.assertEqual(layout["page_size"], 512)
        self.assertEqual(layout["complete_frames"], 2)
        self.assertEqual(layout["trailing_bytes"], 0)
        self.assertEqual(
            layout["commit_ends"],
            [WAL_HEADER_SIZE + WAL_FRAME_HEADER_SIZE + 512, len(synthetic_wal())],
        )

    def test_mutations_are_bounded_and_deterministic(self) -> None:
        original = synthetic_wal()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name in (
                "header-magic-flip",
                "header-checksum-flip",
                "frame-checksum-flip",
                "truncate-empty",
                "truncate-header",
                "truncate-first-commit",
                "truncate-final-byte",
                "state-payload-flip",
                "undo-payload-flip",
                "append-garbage",
            ):
                first = root / f"{name}-first"
                second = root / f"{name}-second"
                first.write_bytes(original)
                second.write_bytes(original)
                first_result = mutate_wal(first, name)
                second_result = mutate_wal(second, name)
                self.assertEqual(first.read_bytes(), second.read_bytes())
                self.assertEqual(first_result["sha256"], second_result["sha256"])
                self.assertNotEqual(first.read_bytes(), original)
                self.assertLessEqual(first.stat().st_size, len(original) + 16)


if __name__ == "__main__":
    unittest.main()
