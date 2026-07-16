"""Public API for Bytecoin Onyx SDK compatibility profile v1."""

from onyx_sdk import ABI_VERSION, OnyxSdk, OnyxSdkError, TokenProgramDescriptor

from .rpc import PROFILE_NAME, WalletRpcCodec, WalletRpcError
from .standard_programs import (
    PASTA_FP_MODULUS,
    STANDARD_APPLICATION_VERSION,
    STANDARD_SCHEMA_HASHES,
    multisig_application,
    nft_application,
    swap_application,
    vesting_application,
)

__all__ = [
    "ABI_VERSION",
    "OnyxSdk",
    "OnyxSdkError",
    "PASTA_FP_MODULUS",
    "PROFILE_NAME",
    "TokenProgramDescriptor",
    "STANDARD_APPLICATION_VERSION",
    "STANDARD_SCHEMA_HASHES",
    "WalletRpcCodec",
    "WalletRpcError",
    "multisig_application",
    "nft_application",
    "swap_application",
    "vesting_application",
]

__version__ = "1.1.0"
