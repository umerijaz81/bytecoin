// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.
//
// Onyx (V6) — C++ adapter over the vendored Halo2/PLONKish (Pasta) backend (vendor/onyx-zk).
// Compiled only when the build is configured with -DONYX_ZK=ON. See ONYX_ARCHITECTURE.md / O0 plan.

#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include "IProofSystem.hpp"

namespace cn {
namespace zk {

// IProofSystem backed by the vendored Halo2 C ABI (include/onyx_zk.h).
//
// The generic verify() override targets only the O0 toy pipeline. Consensus callers use the typed
// fail-closed transfer, bridge, deployment, and issuance methods below.
class Halo2ProofSystem : public IProofSystem {
public:
	struct VerifiedTransferDelta {
		std::array<uint8_t, 16> network{};
		std::array<uint8_t, 32> anchor{};
		uint64_t expiry_height = 0;
		uint64_t fee = 0;
		std::vector<std::array<uint8_t, 32>> nullifiers;
		std::vector<std::array<uint8_t, 32>> commitments;
	};
	struct VerifiedBridgeDelta {
		uint64_t legacy_amount = 0;
		uint64_t legacy_stack_index = 0;
		uint64_t fee = 0;
		std::array<uint8_t, 32> legacy_key_image{};
		std::array<uint8_t, 32> ownership_sighash{};
		std::array<uint8_t, 64> ownership_signature{};
	};
	struct VerifiedProgramDeployment {
		VerifiedTransferDelta funding;
		std::array<uint8_t, 32> program_id{};
	};
	struct VerifiedTokenIssuance {
		std::array<uint8_t, 16> network{};
		std::array<uint8_t, 32> anchor{};
		uint64_t expiry_height = 0;
		std::array<uint8_t, 32> program_id{};
		uint64_t sequence = 0;
		uint64_t issued_amount = 0;
		std::vector<std::array<uint8_t, 32>> commitments;
	};
	struct WalletScanResult {
		uint64_t balance = 0;
		size_t note_count = 0;
		std::array<uint8_t, 32> root{};
	};
	struct WalletAssetBalance {
		uint64_t balance = 0;
		size_t unspent_note_count = 0;
	};
	struct WalletTokenProgramStatus {
		std::array<uint8_t, 32> issuer{};
		uint64_t max_supply = 0;
		uint64_t issued_supply = 0;
		uint64_t next_sequence = 0;
		uint64_t activation_height = 0;
		uint64_t deactivation_height = 0;
		bool active = false;
		BinaryArray metadata;
	};
	struct SupplyAudit {
		uint64_t total_bridged = 0;
		uint64_t total_fees = 0;
		uint64_t circulating_supply = 0;
		uint64_t commitment_count = 0;
		uint64_t program_count = 0;
		uint64_t current_block_program_cost = 0;
		std::array<uint8_t, 32> commitment_root{};
	};
	enum class AdmissionPrecheck { INVALID, CONFLICT, ELIGIBLE };
	const char *backend_id() const override;
	static uint32_t abi_version();

	// O0: maps to the toy-circuit verifier. args.public_inputs must be the 32-byte public field
	// element; vk.data may be empty (the toy vk is regenerated from the circuit structure).
	bool verify(const VerifyingKey &vk, const ProofVerifyArgs &args) const override;

	// --- O0 pipeline-validation helpers (superseded by protocol circuits in O1/O4) ---

	// Orchard Poseidon (P128Pow5T3, arity 2): `in` is two 32-byte LE field elements (64 bytes).
	static bool poseidon_hash2(const uint8_t in[64], uint8_t out[32]);

	// Sinsemilla hash over the fixed test domain; input bytes expanded LSB-first to bits.
	static bool sinsemilla_hash(const BinaryArray &in, uint8_t out[32]);

	// Toy circuit prover (knowledge of a, b with a*b = public). Fills proof/vk/public_out.
	static bool toy_prove(
	    uint64_t a, uint64_t b, BinaryArray *proof, BinaryArray *vk, std::array<uint8_t, 32> *public_out);

	// Canonical Onyx authorized-envelope verification. Consensus callers use frozen depth/K
	// constants; malformed, unsupported, and invalid envelopes all fail closed.
	static bool verify_authorized_transfer(
	    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k);
	static bool verify_and_extract_transfer(const BinaryArray &encoded, uint32_t merkle_depth,
	    uint32_t native_circuit_k, uint32_t token_circuit_k, VerifiedTransferDelta *delta);
	static bool verify_apply_transfer(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
	    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t native_circuit_k,
	    uint32_t token_circuit_k,
	    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
	    BinaryArray *next_snapshot, uint64_t *fee);
	static bool verify_program_deployment(const BinaryArray &encoded, uint32_t merkle_depth,
	    uint32_t funding_circuit_k, uint32_t program_circuit_k, VerifiedProgramDeployment *deployment);
	static bool verify_apply_program_deployment(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
	    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t funding_circuit_k,
	    uint32_t program_circuit_k,
	    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
	    BinaryArray *next_snapshot, uint64_t *fee, std::array<uint8_t, 32> *program_id);
	static bool verify_token_issuance(const BinaryArray &encoded, uint32_t merkle_depth,
	    uint32_t circuit_k, VerifiedTokenIssuance *issuance);
	static bool verify_apply_token_issuance(const BinaryArray &snapshot, const BinaryArray &encoded,
	    uint32_t merkle_depth, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
	    uint64_t block_height, BinaryArray *next_snapshot, VerifiedTokenIssuance *issuance);
	static bool verify_apply_standard_program_transaction(const BinaryArray &snapshot,
	    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k,
	    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
	    BinaryArray *next_snapshot, VerifiedTransferDelta *delta);
	// State-independent authenticated extraction is only for pool cleanup after full verification.
	static bool extract_authenticated_standard_program_delta(
	    const BinaryArray &encoded, VerifiedTransferDelta *delta,
	    std::vector<std::array<uint8_t, 32>> *state_keys);
	static AdmissionPrecheck precheck_authenticated_standard_program_state(
	    const BinaryArray &snapshot, const BinaryArray &encoded, uint32_t merkle_depth);
	static bool verify_apply_bridge(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
	    const BinaryArray &encoded, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
	    uint64_t block_height, BinaryArray *next_snapshot, VerifiedBridgeDelta *delta);
	static bool verify_bridge(const BinaryArray &encoded, uint32_t circuit_k, VerifiedBridgeDelta *delta);
	static bool state_supply_audit(const BinaryArray &snapshot, SupplyAudit *audit);
	static bool state_standard_program_state(const BinaryArray &snapshot,
	    const std::array<uint8_t, 32> &program_id, const BinaryArray &application,
	    std::array<uint8_t, 32> *state, bool *found);
	static bool wallet_address(const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 16> &network, uint32_t address_index, std::array<uint8_t, 91> *address);
	static bool full_viewing_key(const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 16> &network, std::array<uint8_t, 177> *viewing_key);
	static bool wallet_scan(const BinaryArray &snapshot, const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 16> &network, uint8_t envelope_type, uint64_t block_height,
	    uint32_t circuit_k, uint32_t program_k, const BinaryArray &encoded,
	    BinaryArray *next_snapshot, WalletScanResult *result);
	static bool wallet_scan_viewing(const BinaryArray &snapshot, const BinaryArray &viewing_key,
	    uint8_t envelope_type, uint64_t block_height, uint32_t circuit_k, uint32_t program_k,
	    const BinaryArray &encoded, BinaryArray *next_snapshot,
	    WalletScanResult *result);
	static bool wallet_reserve_spends(const BinaryArray &snapshot, const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 16> &network, const BinaryArray &encoded, BinaryArray *next_snapshot);
	static bool wallet_reserve_deployment_spends(const BinaryArray &snapshot,
	    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 16> &network,
	    const BinaryArray &encoded, BinaryArray *next_snapshot);
	static bool wallet_summary(const BinaryArray &snapshot, WalletScanResult *result);
	static bool wallet_asset_balance(const BinaryArray &snapshot,
	    const std::array<uint8_t, 32> &program_id, const std::array<uint8_t, 32> &asset_id,
	    WalletAssetBalance *result);
	static bool wallet_token_program_status(const BinaryArray &snapshot,
	    const std::array<uint8_t, 32> &program_id, uint64_t query_height,
	    WalletTokenProgramStatus *result);
	static bool wallet_create_bridge(const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 91> &recipient, uint64_t expiry_height, uint64_t fee,
	    uint64_t legacy_amount, uint64_t legacy_stack_index,
	    const std::array<uint8_t, 32> &legacy_key_image, const BinaryArray &memo, uint32_t circuit_k,
	    BinaryArray *unsigned_bridge, std::array<uint8_t, 32> *ownership_sighash);
	static bool wallet_finalize_bridge(const BinaryArray &unsigned_bridge,
	    const std::array<uint8_t, 64> &ownership_signature, BinaryArray *finalized_bridge);
	static bool wallet_create_program_deployment(const BinaryArray &wallet_snapshot,
	    const std::array<uint8_t, 32> &seed, uint64_t max_supply, const BinaryArray &metadata,
	    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
	    uint64_t expiry_height, uint64_t fee, uint32_t funding_circuit_k, uint32_t program_circuit_k,
	    BinaryArray *deployment,
	    std::array<uint8_t, 32> *program_id);
	static bool wallet_create_standard_program_deployment(const BinaryArray &wallet_snapshot,
	    const std::array<uint8_t, 32> &seed, uint8_t kind, uint64_t inclusion_height,
	    uint64_t activation_height, uint64_t deactivation_height, uint64_t expiry_height,
	    uint64_t fee, uint32_t circuit_k, BinaryArray *deployment,
	    std::array<uint8_t, 32> *program_id);
	static bool wallet_create_standard_program_call(const BinaryArray &wallet_snapshot,
	    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 32> &program_id,
	    uint64_t inclusion_height, uint64_t valid_from_height, uint64_t expiry_height,
	    const BinaryArray &application, const std::array<uint8_t, 32> &prior_state,
	    const std::array<uint8_t, 32> &next_state, const BinaryArray &witness,
	    uint32_t circuit_k, BinaryArray *transaction);
	static bool wallet_create_token_issuance(const BinaryArray &wallet_snapshot,
	    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
	    const std::array<uint8_t, 32> &program_id, uint64_t issued_amount, uint64_t inclusion_height,
	    uint64_t expiry_height,
	    const BinaryArray &memo, uint32_t circuit_k, BinaryArray *issuance, uint64_t *sequence);
	static bool wallet_create_transfer(const BinaryArray &snapshot, const std::array<uint8_t, 32> &seed,
	    const std::array<uint8_t, 91> &recipient, uint64_t amount, uint64_t fee, uint64_t expiry_height,
	    const BinaryArray &memo, uint32_t circuit_k, BinaryArray *transaction);
	static bool wallet_create_mixed_token_transfer(const BinaryArray &snapshot,
	    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
	    const std::array<uint8_t, 32> &program_id, uint64_t token_amount, uint64_t fee,
	    uint64_t expiry_height, const BinaryArray &memo, uint32_t circuit_k, BinaryArray *transaction);
};

}  // namespace zk
}  // namespace cn
