import unittest

from bytecoin_onyx.standard_programs import (
    PASTA_FP_MODULUS,
    STANDARD_SCHEMA_HASHES,
    multisig_application,
    nft_application,
    swap_application,
    vesting_application,
)


class StandardProgramBuilderTests(unittest.TestCase):
    def test_builders_match_canonical_wire_profile(self):
        self.assertEqual(
            nft_application(bytes([1]) * 32, bytes([2]) * 32, 128, 1).hex(),
            "0101" + "01" * 32 + "02" * 32 + "8001" + "01",
        )
        self.assertEqual(
            vesting_application(bytes([3]) * 32, bytes([4]) * 32, 300).hex(),
            "0102" + "03" * 32 + "04" * 32 + "ac02",
        )
        field = (5).to_bytes(32, "little")
        self.assertEqual(
            multisig_application(field, bytes([6]) * 32, 2, 3).hex(),
            "0103" + field.hex() + "06" * 32 + "0203",
        )
        self.assertEqual(
            swap_application(bytes([7]) * 32, field, 9, True).hex(),
            "0104" + "07" * 32 + field.hex() + "0901",
        )
        self.assertEqual(len(STANDARD_SCHEMA_HASHES), 4)

    def test_rejects_unsafe_values(self):
        with self.assertRaises(ValueError):
            nft_application(bytes(32), bytes([2]) * 32, 0, 1)
        with self.assertRaises(ValueError):
            nft_application(bytes([1]) * 32, bytes([2]) * 32, 0, 0)
        with self.assertRaises(ValueError):
            multisig_application((PASTA_FP_MODULUS).to_bytes(32, "little"), bytes([1]) * 32, 1, 1)
        with self.assertRaises(ValueError):
            multisig_application((1).to_bytes(32, "little"), bytes([1]) * 32, 3, 2)
        with self.assertRaises(ValueError):
            swap_application(bytes([1]) * 32, (1).to_bytes(32, "little"), 0, 1)


if __name__ == "__main__":
    unittest.main()
