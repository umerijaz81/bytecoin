/* Onyx (V6) zero-knowledge backend — C ABI.
 *
 * Versioned, bounded boundary between the C++ node/wallet/SDK and the vendored Halo2/PLONKish
 * (Pasta) backend. Hand-authored so ownership, limits, and compatibility stay explicit. Backs
 * cn::zk::Halo2ProofSystem (src/Core/zk). See ONYX_PROTOCOL_SPEC.md.
 *
 * Return convention for predicate calls: 1 = valid, 0 = invalid, < 0 = malformed input / error.
 * Buffers returned via out-params are owned by the callee and MUST be released with onyx_free.
 * Structured consensus verification/extraction calls clear fixed outputs and element counts after
 * pointer/length validation and before any later failure. Counted arrays have no valid elements
 * when their returned count is zero. Deterministic key, hash, and toy-prover helpers likewise clear
 * fixed or allocated outputs once all output pointers are valid.
 */
#ifndef ONYX_ZK_H
#define ONYX_ZK_H

#include <stddef.h>
#include <stdint.h>

#define ONYX_ZK_ABI_VERSION 1u
/* Public allocation/input ceilings. Callers must reject returned lengths above the corresponding
 * ceiling before reading or copying callee-owned memory. */
#define ONYX_ZK_MAX_PROOF_BYTES (192u * 1024u)
#define ONYX_ZK_MAX_VK_BYTES (1024u * 1024u)
#define ONYX_ZK_MAX_AUTHORIZED_TRANSACTION_BYTES (384u * 1024u)
#define ONYX_ZK_MAX_PROGRAM_DEPLOYMENT_BYTES (384u * 1024u)
#define ONYX_ZK_MAX_TOKEN_ISSUANCE_BYTES (384u * 1024u)
#define ONYX_ZK_MAX_CONTEXTUAL_TRANSACTION_BYTES (512u * 1024u)
#define ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES (128u * 1024u * 1024u)
#define ONYX_ZK_MAX_TOKEN_METADATA_BYTES 128u

#ifdef __cplusplus
extern "C" {
#endif

/* Backend identity, e.g. "halo2-ipa-pasta vX.Y". Static string; do not free. */
const char *onyx_backend_id(void);
/* Numeric compatibility contract for this header and exported symbol set. */
uint32_t onyx_abi_version(void);

/* Orchard Poseidon (P128Pow5T3, arity 2) over the Pallas base field.
 * in: two 32-byte canonical little-endian field elements (64 bytes total).
 * out: 32-byte digest, cleared on failure after pointer validation. Returns 0 on success, <0 if an
 * input is not a canonical field element. Input/output aliasing is supported. */
int onyx_poseidon_hash2(const uint8_t in[64], uint8_t out[32]);

/* Sinsemilla hash over a fixed test domain. Input is limited to 4096 bytes and expanded LSB-first.
 * out: 32-byte digest (Pallas base field element). Returns 0 on success, <0 on the (negligible)
 * exceptional case or bad input. The output is cleared on failure after output-pointer validation;
 * input/output aliasing is supported. */
int onyx_sinsemilla_hash(const uint8_t *in, size_t in_len, uint8_t out[32]);

/* Toy circuit (knowledge of a, b with a*b = public), used only to validate the prove->verify
 * pipeline end-to-end. Writes a freshly-allocated proof, verifying key, and the 32-byte public
 * input. Returns 0 on success, <0 on error. After output-pointer validation, allocated outputs are
 * NULL/0 and public_out is zero until success. Release *proof_out and *vk_out with onyx_free. */
int onyx_toy_prove(uint64_t a, uint64_t b,
                   uint8_t **proof_out, size_t *proof_len,
                   uint8_t **vk_out, size_t *vk_len,
                   uint8_t public_out[32]);

/* Verify a toy-circuit proof against (vk, public_input). Proofs are limited to 192 KiB and
 * verifying keys to 1 MiB. 1 = valid, 0 = invalid, <0 = malformed. */
int onyx_toy_verify(const uint8_t *vk, size_t vk_len,
                    const uint8_t *proof, size_t proof_len,
                    const uint8_t public_input[32]);

/* Verify a canonical Rust-encoded AuthorizedTransaction using an explicitly selected, bounded
 * circuit family. This is the integration boundary used by the inactive V6 consensus adapter;
 * unsupported shapes/depths/K values fail closed. 1 = valid, 0 = invalid, <0 = malformed or
 * unsupported. Input is limited to 384 KiB. */
int onyx_verify_authorized_transfer(const uint8_t *encoded, size_t encoded_len,
                                    uint32_t merkle_depth, uint32_t circuit_k);

/* Verify once and, only on success, extract the public state delta. The authenticated backend id
 * selects native_k or token_k. Capacities are counts of 32-byte entries (not byte lengths).
 * Returns -4 for insufficient output capacity. */
int onyx_verify_and_extract_transfer(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth,
    uint32_t native_k, uint32_t token_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out, uint64_t *fee_out,
    uint8_t *nullifiers_out, size_t nullifier_capacity, size_t *nullifier_count_out,
	uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Authenticate a transfer and extract its signed public delta without verifying the Halo2 proof.
 * This is only for fee calculation, bookkeeping, and rejection filters; full verification remains
 * mandatory before acceptance. */
int onyx_extract_authenticated_transfer_delta(
    const uint8_t *encoded, size_t encoded_len,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out, uint64_t *fee_out,
    uint8_t *nullifiers_out, size_t nullifier_capacity, size_t *nullifier_count_out,
	uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Authenticate a transfer and reject nullifiers already spent in the snapshot without invoking
 * Halo2. Returns 1 eligible, 0 conflicting, or a negative value for malformed input/snapshot. */
int onyx_precheck_authenticated_transfer_state(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth);

/* Verify an authorized transfer, enforce network and expiry, and atomically advance the canonical
 * shielded-state snapshot. Pass NULL/0 for the first snapshot and a nonzero anchor window. The
 * returned snapshot must be released with onyx_free. -5 denotes a state-policy violation. */
int onyx_verify_apply_transfer(
    const uint8_t *snapshot, size_t snapshot_len, uint64_t anchor_window_blocks,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth,
    uint32_t native_k, uint32_t token_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out, uint64_t *fee_out);

/* Verify and apply a one-way legacy bridge. The caller must verify ownership_signature_out against
 * ownership_sighash_out and the disclosed legacy output key, and mark legacy_key_image_out spent in
 * the same database transaction as the returned snapshot. */
int onyx_verify_apply_bridge(
    const uint8_t *snapshot, size_t snapshot_len, uint64_t anchor_window_blocks,
    const uint8_t *encoded, size_t encoded_len, uint32_t circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out,
    uint64_t *legacy_amount_out, uint64_t *legacy_stack_index_out,
    uint8_t legacy_key_image_out[32], uint8_t ownership_sighash_out[32],
    uint8_t ownership_signature_out[64], uint64_t *fee_out);

/* Verify and extract a fee-funded standard-program deployment envelope. The funding circuit and
 * registered token-program execution circuit are independently pinned. Pinned non-token programs
 * ignore program_circuit_k after validating their committed artifact. */
int onyx_verify_program_deployment(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth,
    uint32_t funding_circuit_k, uint32_t program_circuit_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint64_t *fee_out, uint8_t program_id_out[32], uint8_t *nullifiers_out,
    size_t nullifier_capacity, size_t *nullifier_count_out, uint8_t *commitments_out,
    size_t commitment_capacity, size_t *commitment_count_out);

/* Authenticate deployment funding and recompute its canonical manifest-derived program id without
 * Halo2. This helper is for fee calculation, bookkeeping, and rejection-only admission filters. */
int onyx_extract_authenticated_program_deployment(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t program_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint64_t *fee_out, uint8_t program_id_out[32], uint8_t *nullifiers_out,
    size_t nullifier_capacity, size_t *nullifier_count_out, uint8_t *commitments_out,
    size_t commitment_capacity, size_t *commitment_count_out);

/* Verify, fee-fund, and atomically register a standard program in the state snapshot. */
int onyx_verify_apply_program_deployment(
    const uint8_t *snapshot, size_t snapshot_len, uint64_t anchor_window_blocks,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth,
    uint32_t funding_circuit_k, uint32_t program_circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out, uint64_t *fee_out,
    uint8_t program_id_out[32]);

/* Verify a token issuance proof/binding and extract its public state delta. */
int onyx_validate_token_issuance_structure(const uint8_t *encoded, size_t encoded_len);

int onyx_verify_and_extract_token_issuance(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint8_t program_id_out[32], uint64_t *sequence_out, uint64_t *issued_amount_out,
    uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Authenticate issuer, registry policy, binding signature, and issuance metadata, then cheaply
 * compare anchor, sequence, and cumulative cap with the snapshot. Full proof verification remains
 * mandatory. Returns 1 eligible, 0 state conflict, or a negative malformed/unauthorized result. */
int onyx_precheck_authenticated_token_issuance(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t *encoded, size_t encoded_len,
    uint32_t merkle_depth, uint32_t circuit_k, const uint8_t expected_network[16],
    uint64_t block_height, uint8_t network_out[16], uint8_t anchor_out[32],
    uint64_t *expiry_height_out, uint8_t program_id_out[32], uint64_t *sequence_out,
    uint64_t *issued_amount_out, uint8_t *commitments_out, size_t commitment_capacity,
    size_t *commitment_count_out);

/* Verify issuer/cap/sequence/registry/proof and atomically apply token issuance. */
int onyx_verify_apply_token_issuance(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out, uint8_t program_id_out[32],
    uint64_t *sequence_out, uint64_t *issued_amount_out);

/* Verify a pinned contextual standard-program bundle and atomically apply both its shielded-value
 * delta and prior->next program-state transition. The snapshot must already contain the deployed
 * registry entry. */
int onyx_verify_apply_standard_program_transaction(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint8_t *nullifiers_out, size_t nullifier_capacity, size_t *nullifier_count_out,
	uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Extract an authorization-checked contextual value delta for post-verification pool bookkeeping.
 * This does not verify program proofs or state and is never a consensus-admission substitute. */
int onyx_extract_authenticated_standard_program_delta(
    const uint8_t *encoded, size_t encoded_len,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint8_t *nullifiers_out, size_t nullifier_capacity, size_t *nullifier_count_out,
	uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out,
	uint8_t *state_keys_out, size_t state_key_capacity, size_t *state_key_count_out);

/* Authenticate a contextual envelope and cheaply compare its nullifiers/prior states with the
 * snapshot. Returns 1 eligible, 0 conflicting, or a negative value for malformed input/snapshot.
 * This is an admission filter only; full verification remains mandatory before acceptance. */
int onyx_precheck_authenticated_standard_program_state(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth);

/* Decode the rollback-safe consensus snapshot and return its public supply-accounting totals.
 * After all pointers are validated, every output is zeroed before any decode that can fail. */
int onyx_state_supply_audit(
    const uint8_t *snapshot, size_t snapshot_len,
    uint64_t *total_bridged_out, uint64_t *total_fees_out,
    uint64_t *circulating_supply_out, uint64_t *leaf_count_out,
    uint64_t *program_count_out, uint64_t *current_block_program_cost_out,
    uint8_t root_out[32]);

/* Query a stable standard-application identity in a depth-32 consensus snapshot. After all
 * pointers are validated, state_out and found_out are zeroed before any decode that can fail. */
int onyx_state_standard_program_state(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t program_id[32],
    const uint8_t *application, size_t application_len, uint8_t state_out[32],
    uint8_t *found_out);

/* Verify a bridge proof and extract the public legacy ownership statement without applying state. */
int onyx_verify_bridge(
    const uint8_t *encoded, size_t encoded_len, uint32_t circuit_k,
    uint64_t *legacy_amount_out, uint64_t *legacy_stack_index_out,
    uint8_t legacy_key_image_out[32], uint8_t ownership_sighash_out[32],
    uint8_t ownership_signature_out[64], uint64_t *fee_out);

/* Extract canonical bridge metadata without Halo2. Every returned field is covered by
 * ownership_sighash_out, but the caller must resolve the legacy output and verify the returned
 * ownership signature before using the metadata for an admission decision. */
int onyx_extract_bridge_metadata(
    const uint8_t *encoded, size_t encoded_len,
    uint64_t *legacy_amount_out, uint64_t *legacy_stack_index_out,
    uint8_t legacy_key_image_out[32], uint8_t ownership_sighash_out[32],
    uint8_t ownership_signature_out[64], uint64_t *fee_out);

/* Wallet/SDK constructors and queries below clear every fixed, scalar, and allocated output after
 * all output pointers are validated and before any input-dependent failure.
 *
 * Derive canonical Onyx address bytes: network[16] || diversifier[11] || transmission[32] ||
 * spend-authority[32]. */
int onyx_wallet_address(const uint8_t seed[32], const uint8_t network[16], uint32_t address_index,
                        uint8_t address_out[91]);
/* Canonical full viewing key (version + network + incoming/outgoing/diversifier/nullifier/public
 * spend-authority material); contains no spend scalar. */
int onyx_full_viewing_key(const uint8_t seed[32], const uint8_t network[16],
                          uint8_t viewing_key_out[177]);

/* Scan one confirmed transfer (type 0) or bridge (type 1), append every commitment, recover owned
 * notes, mark spends, and return a canonical wallet snapshot. program_k is used to reconstruct a
 * program-deployment artifact independently from its funding-transfer circuit_k. */
int onyx_wallet_scan(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t expected_network[16], uint8_t envelope_type, uint64_t block_height,
    uint32_t circuit_k, uint32_t program_k,
    const uint8_t *encoded, size_t encoded_len,
    uint8_t **snapshot_out, size_t *snapshot_len_out,
    uint64_t *balance_out, size_t *note_count_out, uint8_t root_out[32]);
int onyx_wallet_scan_viewing(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *viewing_key, size_t viewing_key_len, uint8_t envelope_type,
    uint64_t block_height, uint32_t circuit_k, uint32_t program_k,
    const uint8_t *encoded, size_t encoded_len,
    uint8_t **snapshot_out, size_t *snapshot_len_out,
    uint64_t *balance_out, size_t *note_count_out, uint8_t root_out[32]);
/* Mark owned nullifiers from a pending transfer without appending its unconfirmed outputs. */
int onyx_wallet_reserve_spends(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t expected_network[16], const uint8_t *encoded, size_t encoded_len,
    uint8_t **snapshot_out, size_t *snapshot_len_out);
int onyx_wallet_reserve_deployment_spends(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t expected_network[16], const uint8_t *encoded, size_t encoded_len,
    uint8_t **snapshot_out, size_t *snapshot_len_out);
int onyx_wallet_summary(const uint8_t *snapshot, size_t snapshot_len,
                        uint64_t *balance_out, size_t *note_count_out, uint8_t root_out[32]);
/* Return the confirmed unspent balance for one exact (program id, asset id) pair. */
int onyx_wallet_asset_balance(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t program_id[32], const uint8_t asset_id[32],
    uint64_t *balance_out, size_t *unspent_note_count_out);
/* Inspect one capped token program from the wallet-derived public consensus view. */
int onyx_wallet_token_program_status(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t program_id[32],
    uint64_t query_height, uint8_t issuer_out[32], uint64_t *max_supply_out,
    uint64_t *issued_supply_out, uint64_t *next_sequence_out,
    uint64_t *activation_height_out, uint64_t *deactivation_height_out,
    int *active_out, uint8_t **metadata_out, size_t *metadata_len_out);
/* SDK helper: construct the canonical capped-token policy manifest and preview the Program ID for
 * the production Merkle depth. A zero deactivation height means no scheduled deactivation. */
int onyx_token_program_descriptor(
    const uint8_t issuer[32], uint64_t max_supply,
    const uint8_t *metadata, size_t metadata_len,
    uint64_t activation_height, uint64_t deactivation_height, uint32_t circuit_k,
    uint8_t **manifest_out, size_t *manifest_len_out, uint8_t program_id_out[32]);

/* Build a proved/encrypted bridge with a zero ownership signature, returning the 32-byte message
 * the legacy wallet must sign. Finalize by injecting the resulting 64-byte CryptoNote signature. */
int onyx_wallet_create_bridge(
    const uint8_t seed[32], const uint8_t recipient[91], uint64_t expiry_height,
    uint64_t fee, uint64_t legacy_amount, uint64_t legacy_stack_index,
    const uint8_t legacy_key_image[32], const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **bridge_out, size_t *bridge_len_out, uint8_t ownership_sighash_out[32]);
#ifdef BYTECOIN_ONYX_INVALID_PROOF_TESTS
/* Non-distributable fixture: corrupt the completed bridge proof before returning the ownership
 * sighash, so an external legacy signature can authenticate those exact invalid proof bytes. */
int onyx_wallet_create_authenticated_invalid_proof_bridge(
    const uint8_t seed[32], const uint8_t recipient[91], uint64_t expiry_height,
    uint64_t fee, uint64_t legacy_amount, uint64_t legacy_stack_index,
    const uint8_t legacy_key_image[32], const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **bridge_out, size_t *bridge_len_out, uint8_t ownership_sighash_out[32]);
#endif
int onyx_wallet_finalize_bridge(
    const uint8_t *unsigned_bridge, size_t unsigned_bridge_len,
    const uint8_t ownership_signature[64], uint8_t **bridge_out, size_t *bridge_len_out);
/* Build a fee-funded deployment for the capped standard private-token program. A zero
 * deactivation height means no scheduled deactivation. Funding and registered token execution
 * use separately pinned circuit domains. */
int onyx_wallet_create_program_deployment(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], uint64_t max_supply,
    const uint8_t *metadata, size_t metadata_len,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t funding_circuit_k,
    uint32_t program_circuit_k,
    uint8_t **deployment_out, size_t *deployment_len_out, uint8_t program_id_out[32]);
#ifdef BYTECOIN_ONYX_INVALID_PROOF_TESTS
/* Non-distributable fixture: build a canonical deployment whose funding transcript is corrupted
 * before the real spend and binding signatures are produced. */
int onyx_wallet_create_authenticated_invalid_proof_program_deployment(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], uint64_t max_supply,
    const uint8_t *metadata, size_t metadata_len,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t funding_circuit_k,
    uint32_t program_circuit_k,
    uint8_t **deployment_out, size_t *deployment_len_out, uint8_t program_id_out[32]);
#endif
/* Build a fee-funded deployment for a pinned standard program. kind is 1=Nft,
 * 2=Vesting, 3=Multisig, or 4=Swap. Standard programs require circuit k=16. */
int onyx_wallet_create_standard_program_deployment(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], uint8_t kind,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t circuit_k,
    uint8_t **deployment_out, size_t *deployment_len_out, uint8_t program_id_out[32]);
/* Build a one-call contextual transaction for a deployed pinned standard program. application is
 * the canonical StandardApplication v1 encoding. witness is witness_count consecutive canonical
 * 32-byte Pasta fields (1 for NFT/vesting/swap; 48 for multisig). The call is a zero-fee, one-unit
 * native self-transfer that supplies the authorized base value layer. */
int onyx_wallet_create_standard_program_call(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len, const uint8_t seed[32],
    const uint8_t program_id[32], uint64_t inclusion_height, uint64_t valid_from_height,
    uint64_t expiry_height, const uint8_t *application, size_t application_len,
    const uint8_t prior_state[32], const uint8_t next_state[32],
    const uint8_t *witness, size_t witness_count, uint32_t circuit_k,
    uint8_t **transaction_out, size_t *transaction_len_out);
int onyx_wallet_create_token_issuance(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], const uint8_t recipient[91], const uint8_t program_id[32],
    uint64_t issued_amount, uint64_t inclusion_height, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **issuance_out, size_t *issuance_len_out, uint64_t *sequence_out);
#ifdef BYTECOIN_ONYX_INVALID_PROOF_TESTS
/* Non-distributable fixture: alter a completed issuance proof and then authenticate those exact
 * bytes with the real value-binding and registered issuer keys. Qualification binaries only. */
int onyx_wallet_create_authenticated_invalid_proof_token_issuance(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], const uint8_t recipient[91], const uint8_t program_id[32],
    uint64_t issued_amount, uint64_t inclusion_height, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **issuance_out, size_t *issuance_len_out, uint64_t *sequence_out);
#endif
int onyx_wallet_create_transfer(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t recipient[91], uint64_t amount, uint64_t fee, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **transaction_out, size_t *transaction_len_out);
#ifdef BYTECOIN_ONYX_INVALID_PROOF_TESTS
/* Non-distributable fixture: alter a completed Halo2 transcript and then authenticate those exact
 * bytes with the real spend and binding keys. This must only exist in qualification binaries. */
int onyx_wallet_create_authenticated_invalid_proof_transfer(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t recipient[91], uint64_t amount, uint64_t fee, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **transaction_out, size_t *transaction_len_out);
#endif
int onyx_wallet_create_mixed_token_transfer(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t recipient[91], const uint8_t program_id[32],
    uint64_t token_amount, uint64_t fee, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **transaction_out, size_t *transaction_len_out);

/* Release a buffer previously returned by this library. */
void onyx_free(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ONYX_ZK_H */
