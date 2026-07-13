import ctypes
import unittest

from onyx_sdk import ABI_VERSION, OnyxSdk, OnyxSdkError


class FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class FakeLibrary:
    def __init__(self, abi_version=ABI_VERSION):
        self._manifest = None
        self.freed = []
        self.onyx_abi_version = FakeFunction(lambda: abi_version)
        self.onyx_token_program_descriptor = FakeFunction(self._descriptor)
        self.onyx_free = FakeFunction(self._free)

    def _descriptor(self, issuer, max_supply, metadata, metadata_len, activation, deactivation, k,
                    manifest_out, manifest_len_out, program_id_out):
        del issuer, max_supply, metadata, metadata_len, activation, deactivation, k
        value = bytes.fromhex("4f4e584d010203")
        self._manifest = (ctypes.c_uint8 * len(value)).from_buffer_copy(value)
        manifest_out._obj.contents = ctypes.cast(self._manifest, ctypes.POINTER(ctypes.c_uint8)).contents
        manifest_len_out._obj.value = len(value)
        for index in range(32):
            program_id_out[index] = index
        return 1

    def _free(self, pointer, length):
        self.freed.append((ctypes.addressof(pointer.contents), int(length)))


class OnyxSdkTests(unittest.TestCase):
    def test_rejects_incompatible_abi(self):
        with self.assertRaises(OnyxSdkError):
            OnyxSdk(library=FakeLibrary(ABI_VERSION + 1))

    def test_descriptor_copies_and_frees_native_manifest(self):
        native = FakeLibrary()
        sdk = OnyxSdk(library=native)
        result = sdk.token_program_descriptor(
            bytes(range(32)), 1_000_000, "symbol=TEST", 10, 20, 14
        )
        self.assertEqual(result.manifest, bytes.fromhex("4f4e584d010203"))
        self.assertEqual(result.program_id, bytes(range(32)))
        self.assertEqual(len(native.freed), 1)
        self.assertEqual(native.freed[0][1], len(result.manifest))

    def test_validates_before_calling_native(self):
        sdk = OnyxSdk(library=FakeLibrary())
        with self.assertRaises(ValueError):
            sdk.token_program_descriptor(b"short", 1, "TEST", 1)
        with self.assertRaises(ValueError):
            sdk.token_program_descriptor(bytes(32), 1, "bad\nmetadata", 1)
        with self.assertRaises(ValueError):
            sdk.token_program_descriptor(bytes(32), 1, "TEST", 20, 20)


if __name__ == "__main__":
    unittest.main()
