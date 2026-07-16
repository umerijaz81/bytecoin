"""Public API for Bytecoin Onyx SDK compatibility profile v1."""

from onyx_sdk import ABI_VERSION, OnyxSdk, OnyxSdkError, TokenProgramDescriptor

from .rpc import PROFILE_NAME, WalletRpcCodec, WalletRpcError

__all__ = [
    "ABI_VERSION",
    "OnyxSdk",
    "OnyxSdkError",
    "PROFILE_NAME",
    "TokenProgramDescriptor",
    "WalletRpcCodec",
    "WalletRpcError",
]

__version__ = "1.0.0"
