export type JsonRpcId = string | number | null;
export type OnyxWalletMethod =
  | "get_onyx_status"
  | "get_onyx_asset_balance"
  | "get_onyx_program_status"
  | "create_onyx_transaction"
  | "create_onyx_token_transaction"
  | "create_onyx_program_deployment"
  | "create_onyx_token_issuance"
  | "create_onyx_bridge"
  | "finalize_onyx_bridge";

export const PROFILE_NAME: "bytecoin-onyx-wallet-rpc-v1";
export const STANDARD_APPLICATION_VERSION: 1;
export const PASTA_FP_MODULUS: bigint;
export const STANDARD_SCHEMA_HASHES: Readonly<{
  nft: string;
  vesting: string;
  multisig: string;
  swap: string;
}>;
export function nftApplication(
  collectionId: Uint8Array,
  tokenId: Uint8Array,
  serial: bigint | number,
  transferNonce: bigint | number,
): Uint8Array;
export function vestingApplication(
  scheduleId: Uint8Array,
  beneficiary: Uint8Array,
  unlockHeight: bigint | number,
): Uint8Array;
export function multisigApplication(
  policyCommitment: Uint8Array,
  actionDigest: Uint8Array,
  threshold: bigint | number,
  participantCount: bigint | number,
): Uint8Array;
export function swapApplication(
  swapId: Uint8Array,
  hashlock: Uint8Array,
  timeoutHeight: bigint | number,
  refund: boolean,
): Uint8Array;

export class WalletRpcError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown);
}

export class WalletRpcCodec {
  readonly methods: readonly OnyxWalletMethod[];
  request(
    method: OnyxWalletMethod,
    params?: Readonly<Record<string, unknown>>,
    requestId?: JsonRpcId,
  ): Record<string, unknown>;
  validateResponse(
    method: OnyxWalletMethod,
    response: Readonly<Record<string, unknown>>,
    requestId?: JsonRpcId,
  ): Record<string, unknown>;
  static canonicalJson(value: Readonly<Record<string, unknown>>): string;
}
