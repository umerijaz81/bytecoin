"""Canonical application-data builders for Onyx standard programs."""

from __future__ import annotations

from typing import Final


STANDARD_APPLICATION_VERSION: Final = 1
PASTA_FP_MODULUS: Final = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16
)
STANDARD_SCHEMA_HASHES: Final = {
    "nft": "204730978f788b8d1e458ee81c1c12ff39d0444f174fe9d192246d80890bb132",
    "vesting": "c36efa02930c2551179a949214f1a181720ddd8364e44a197c7a0b756cd0862c",
    "multisig": "8703b1c751de7881667f76507fdf7f04a30399da2c4b1bb27f8b91e86a5ba589",
    "swap": "8738062476880a23afdd40b5c64c8ec2120d8c6981315dba90776266ddde4fce",
}


def _bytes32(value: bytes, name: str, *, field: bool = False) -> bytes:
    value = bytes(value)
    if len(value) != 32:
        raise ValueError(f"{name} must be exactly 32 bytes")
    integer = int.from_bytes(value, "little")
    if integer == 0:
        raise ValueError(f"{name} must be nonzero")
    if field and integer >= PASTA_FP_MODULUS:
        raise ValueError(f"{name} must be a canonical Pasta field encoding")
    return value


def _uint64(value: int, name: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"{name} must be a uint64")
    if positive and value == 0:
        raise ValueError(f"{name} must be positive")
    return value


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def nft_application(collection_id: bytes, token_id: bytes, serial: int, transfer_nonce: int) -> bytes:
    """Build kind-1 NFT transfer data; nonce zero is never a valid transfer."""
    return (
        bytes((STANDARD_APPLICATION_VERSION, 1))
        + _bytes32(collection_id, "collection_id")
        + _bytes32(token_id, "token_id")
        + _varint(_uint64(serial, "serial"))
        + _varint(_uint64(transfer_nonce, "transfer_nonce", positive=True))
    )


def vesting_application(schedule_id: bytes, beneficiary: bytes, unlock_height: int) -> bytes:
    """Build kind-2 vesting release data."""
    return (
        bytes((STANDARD_APPLICATION_VERSION, 2))
        + _bytes32(schedule_id, "schedule_id")
        + _bytes32(beneficiary, "beneficiary")
        + _varint(_uint64(unlock_height, "unlock_height"))
    )


def multisig_application(
    policy_commitment: bytes,
    action_digest: bytes,
    threshold: int,
    participant_count: int,
) -> bytes:
    """Build kind-3 threshold-custody data for at most 16 distinct participants."""
    threshold = _uint64(threshold, "threshold", positive=True)
    participant_count = _uint64(participant_count, "participant_count", positive=True)
    if participant_count > 16 or threshold > participant_count:
        raise ValueError("threshold must not exceed a participant_count in [1, 16]")
    return (
        bytes((STANDARD_APPLICATION_VERSION, 3))
        + _bytes32(policy_commitment, "policy_commitment", field=True)
        + _bytes32(action_digest, "action_digest")
        + _varint(threshold)
        + _varint(participant_count)
    )


def swap_application(swap_id: bytes, hashlock: bytes, timeout_height: int, refund: bool) -> bytes:
    """Build kind-4 claim/refund data with a canonical Pasta-field hashlock."""
    if type(refund) is not bool:
        raise ValueError("refund must be a boolean")
    return (
        bytes((STANDARD_APPLICATION_VERSION, 4))
        + _bytes32(swap_id, "swap_id")
        + _bytes32(hashlock, "hashlock", field=True)
        + _varint(_uint64(timeout_height, "timeout_height"))
        + bytes((int(refund),))
    )
