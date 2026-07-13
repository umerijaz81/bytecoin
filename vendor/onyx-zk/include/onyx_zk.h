/* Onyx (V6) zero-knowledge backend — C ABI.
 *
 * Stable, audit-sized boundary between the C++ node and the vendored Halo2/PLONKish (Pasta) proving
 * stack. Hand-authored (not cbindgen-generated) because the surface is intentionally tiny. Backs
 * cn::zk::Halo2ProofSystem (src/Core/zk). See ONYX_ARCHITECTURE.md / ONYX_O0_PLAN.md.
 *
 * Return convention for predicate calls: 1 = valid, 0 = invalid, < 0 = malformed input / error.
 * Buffers returned via out-params are owned by the callee and MUST be released with onyx_free.
 */
#ifndef ONYX_ZK_H
#define ONYX_ZK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backend identity, e.g. "halo2-ipa-pasta vX.Y". Static string; do not free. */
const char *onyx_backend_id(void);

/* Orchard Poseidon (P128Pow5T3, arity 2) over the Pallas base field.
 * in: two 32-byte canonical little-endian field elements (64 bytes total).
 * out: 32-byte digest. Returns 0 on success, <0 if an input is not a canonical field element. */
int onyx_poseidon_hash2(const uint8_t in[64], uint8_t out[32]);

/* Sinsemilla hash over a fixed test domain. Input is limited to 4096 bytes and expanded LSB-first.
 * out: 32-byte digest (Pallas base field element). Returns 0 on success, <0 on the (negligible)
 * exceptional case or bad input. */
int onyx_sinsemilla_hash(const uint8_t *in, size_t in_len, uint8_t out[32]);

/* Toy circuit (knowledge of a, b with a*b = public), used only to validate the prove->verify
 * pipeline end-to-end. Writes a freshly-allocated proof, verifying key, and the 32-byte public
 * input. Returns 0 on success, <0 on error. Release *proof_out and *vk_out with onyx_free. */
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

/* Verify once and, only on success, extract the public state delta. Capacities are counts of
 * 32-byte entries (not byte lengths). Returns -4 for insufficient output capacity. */
int onyx_verify_and_extract_transfer(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out, uint64_t *fee_out,
    uint8_t *nullifiers_out, size_t nullifier_capacity, size_t *nullifier_count_out,
    uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Verify an authorized transfer, enforce network and expiry, and atomically advance the canonical
 * shielded-state snapshot. Pass NULL/0 for the first snapshot and a nonzero anchor window. The
 * returned snapshot must be released with onyx_free. -5 denotes a state-policy violation. */
int onyx_verify_apply_transfer(
    const uint8_t *snapshot, size_t snapshot_len, uint64_t anchor_window_blocks,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
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

/* Verify and extract a fee-funded standard-program deployment envelope. */
int onyx_verify_program_deployment(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint64_t *fee_out, uint8_t program_id_out[32], uint8_t *nullifiers_out,
    size_t nullifier_capacity, size_t *nullifier_count_out, uint8_t *commitments_out,
    size_t commitment_capacity, size_t *commitment_count_out);

/* Verify, fee-fund, and atomically register a standard program in the state snapshot. */
int onyx_verify_apply_program_deployment(
    const uint8_t *snapshot, size_t snapshot_len, uint64_t anchor_window_blocks,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out, uint64_t *fee_out,
    uint8_t program_id_out[32]);

/* Verify a token issuance proof/binding and extract its public state delta. */
int onyx_verify_and_extract_token_issuance(
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    uint8_t network_out[16], uint8_t anchor_out[32], uint64_t *expiry_height_out,
    uint8_t program_id_out[32], uint64_t *sequence_out, uint64_t *issued_amount_out,
    uint8_t *commitments_out, size_t commitment_capacity, size_t *commitment_count_out);

/* Verify issuer/cap/sequence/registry/proof and atomically apply token issuance. */
int onyx_verify_apply_token_issuance(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *encoded, size_t encoded_len, uint32_t merkle_depth, uint32_t circuit_k,
    const uint8_t expected_network[16], uint64_t block_height,
    uint8_t **snapshot_out, size_t *snapshot_len_out, uint8_t program_id_out[32],
    uint64_t *sequence_out, uint64_t *issued_amount_out);

/* Decode the rollback-safe consensus snapshot and return its public supply-accounting totals. */
int onyx_state_supply_audit(
    const uint8_t *snapshot, size_t snapshot_len,
    uint64_t *total_bridged_out, uint64_t *total_fees_out,
    uint64_t *circulating_supply_out, uint64_t *leaf_count_out,
    uint64_t *program_count_out, uint64_t *current_block_program_cost_out,
    uint8_t root_out[32]);

/* Verify a bridge proof and extract the public legacy ownership statement without applying state. */
int onyx_verify_bridge(
    const uint8_t *encoded, size_t encoded_len, uint32_t circuit_k,
    uint64_t *legacy_amount_out, uint64_t *legacy_stack_index_out,
    uint8_t legacy_key_image_out[32], uint8_t ownership_sighash_out[32],
    uint8_t ownership_signature_out[64], uint64_t *fee_out);

/* Derive canonical Onyx address bytes: network[16] || diversifier[11] || transmission[32] ||
 * spend-authority[32]. */
int onyx_wallet_address(const uint8_t seed[32], const uint8_t network[16], uint32_t address_index,
                        uint8_t address_out[91]);
/* Canonical full viewing key (version + network + incoming/outgoing/diversifier/nullifier/public
 * spend-authority material); contains no spend scalar. */
int onyx_full_viewing_key(const uint8_t seed[32], const uint8_t network[16],
                          uint8_t viewing_key_out[177]);

/* Scan one confirmed transfer (type 0) or bridge (type 1), append every commitment, recover owned
 * notes, mark spends, and return a canonical wallet snapshot. */
int onyx_wallet_scan(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t expected_network[16], uint8_t envelope_type,
    const uint8_t *encoded, size_t encoded_len,
    uint8_t **snapshot_out, size_t *snapshot_len_out,
    uint64_t *balance_out, size_t *note_count_out, uint8_t root_out[32]);
int onyx_wallet_scan_viewing(
    const uint8_t *snapshot, size_t snapshot_len,
    const uint8_t *viewing_key, size_t viewing_key_len, uint8_t envelope_type,
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

/* Build a proved/encrypted bridge with a zero ownership signature, returning the 32-byte message
 * the legacy wallet must sign. Finalize by injecting the resulting 64-byte CryptoNote signature. */
int onyx_wallet_create_bridge(
    const uint8_t seed[32], const uint8_t recipient[91], uint64_t expiry_height,
    uint64_t fee, uint64_t legacy_amount, uint64_t legacy_stack_index,
    const uint8_t legacy_key_image[32], const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **bridge_out, size_t *bridge_len_out, uint8_t ownership_sighash_out[32]);
int onyx_wallet_finalize_bridge(
    const uint8_t *unsigned_bridge, size_t unsigned_bridge_len,
    const uint8_t ownership_signature[64], uint8_t **bridge_out, size_t *bridge_len_out);
/* Build a fee-funded deployment for the capped standard private-token program. A zero
 * deactivation height means no scheduled deactivation. */
int onyx_wallet_create_program_deployment(
    const uint8_t *wallet_snapshot, size_t wallet_snapshot_len,
    const uint8_t seed[32], uint64_t max_supply,
    const uint8_t *metadata, size_t metadata_len,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t circuit_k,
    uint8_t **deployment_out, size_t *deployment_len_out, uint8_t program_id_out[32]);
int onyx_wallet_create_token_issuance(
    const uint8_t *consensus_snapshot, size_t consensus_snapshot_len,
    const uint8_t seed[32], const uint8_t recipient[91], const uint8_t program_id[32],
    uint64_t issued_amount, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **issuance_out, size_t *issuance_len_out, uint64_t *sequence_out);
int onyx_wallet_create_transfer(
    const uint8_t *snapshot, size_t snapshot_len, const uint8_t seed[32],
    const uint8_t recipient[91], uint64_t amount, uint64_t fee, uint64_t expiry_height,
    const uint8_t *memo, size_t memo_len, uint32_t circuit_k,
    uint8_t **transaction_out, size_t *transaction_len_out);
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
