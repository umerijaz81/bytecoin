"""Dependency-free Python binding for the version-1 Onyx descriptor ABI."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from os import PathLike
from typing import Any


ABI_VERSION = 1
_U8_PTR = ctypes.POINTER(ctypes.c_uint8)


class OnyxSdkError(RuntimeError):
    """The native Onyx SDK rejected an operation or violated its ABI contract."""


@dataclass(frozen=True)
class TokenProgramDescriptor:
    manifest: bytes
    program_id: bytes


class OnyxSdk:
    """Checked wrapper around ``onyx_token_program_descriptor``.

    ``library`` is injectable for tests. Normal callers pass a path to the Onyx shared library.
    The repository build primarily emits a static library, so applications may expose the same C ABI
    from their own shared SDK target without changing this binding.
    """

    def __init__(self, path: str | PathLike[str] | None = None, *, library: Any | None = None):
        if (path is None) == (library is None):
            raise ValueError("provide exactly one of path or library")
        self._library = library if library is not None else ctypes.CDLL(str(path))
        self._configure_signatures()
        version = int(self._library.onyx_abi_version())
        if version != ABI_VERSION:
            raise OnyxSdkError(f"unsupported Onyx ABI version {version}; expected {ABI_VERSION}")

    def _configure_signatures(self) -> None:
        self._library.onyx_abi_version.argtypes = []
        self._library.onyx_abi_version.restype = ctypes.c_uint32
        self._library.onyx_token_program_descriptor.argtypes = [
            _U8_PTR,
            ctypes.c_uint64,
            _U8_PTR,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_uint32,
            ctypes.POINTER(_U8_PTR),
            ctypes.POINTER(ctypes.c_size_t),
            _U8_PTR,
        ]
        self._library.onyx_token_program_descriptor.restype = ctypes.c_int
        self._library.onyx_free.argtypes = [_U8_PTR, ctypes.c_size_t]
        self._library.onyx_free.restype = None

    def token_program_descriptor(
        self,
        issuer: bytes,
        max_supply: int,
        metadata: bytes | str,
        activation_height: int,
        deactivation_height: int = 0,
        circuit_k: int = 20,
    ) -> TokenProgramDescriptor:
        issuer = bytes(issuer)
        metadata = metadata.encode("ascii") if isinstance(metadata, str) else bytes(metadata)
        if len(issuer) != 32:
            raise ValueError("issuer must be exactly 32 bytes")
        if not 1 <= max_supply <= 0xFFFF_FFFF_FFFF_FFFF:
            raise ValueError("max_supply must be a positive uint64")
        if not 1 <= len(metadata) <= 128 or any(byte < 0x20 or byte > 0x7E for byte in metadata):
            raise ValueError("metadata must contain 1-128 printable ASCII bytes")
        for name, value in (
            ("activation_height", activation_height),
            ("deactivation_height", deactivation_height),
        ):
            if not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
                raise ValueError(f"{name} must be a uint64")
        if deactivation_height and deactivation_height <= activation_height:
            raise ValueError("deactivation_height must follow activation_height")
        if not 10 <= circuit_k <= 20:
            raise ValueError("circuit_k must be in [10, 20]")

        issuer_buffer = (ctypes.c_uint8 * 32).from_buffer_copy(issuer)
        metadata_buffer = (ctypes.c_uint8 * len(metadata)).from_buffer_copy(metadata)
        manifest_ptr = _U8_PTR()
        manifest_len = ctypes.c_size_t()
        program_id = (ctypes.c_uint8 * 32)()
        rc = int(
            self._library.onyx_token_program_descriptor(
                issuer_buffer,
                max_supply,
                metadata_buffer,
                len(metadata),
                activation_height,
                deactivation_height,
                circuit_k,
                ctypes.byref(manifest_ptr),
                ctypes.byref(manifest_len),
                program_id,
            )
        )
        if rc != 1:
            raise OnyxSdkError(f"Onyx token descriptor failed with native error {rc}")
        if not manifest_ptr or manifest_len.value == 0:
            raise OnyxSdkError("Onyx token descriptor returned an invalid manifest buffer")
        try:
            manifest = ctypes.string_at(manifest_ptr, manifest_len.value)
        finally:
            self._library.onyx_free(manifest_ptr, manifest_len.value)
        return TokenProgramDescriptor(manifest=manifest, program_id=bytes(program_id))
