// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Halo2ProofSystem.hpp"
#include <algorithm>
#include <utility>
#include "onyx_zk.h"  // vendored C ABI (vendor/onyx-zk/include), on the include path when ONYX_ZK=ON

namespace cn {
namespace zk {

namespace {
class OnyxBuffer {
  public:
	OnyxBuffer() = default;
	OnyxBuffer(const OnyxBuffer &) = delete;
	OnyxBuffer &operator=(const OnyxBuffer &) = delete;
	~OnyxBuffer() { onyx_free(data, size); }

	BinaryArray copy() const {
		if (size == 0)
			return {};
		return BinaryArray(data, data + size);
	}

	bool valid_nonempty(size_t maximum) const {
		return data != nullptr && size != 0 && size <= maximum;
	}

	bool valid_optional(size_t maximum) const {
		return size <= maximum && (size == 0 || data != nullptr);
	}

	uint8_t *data = nullptr;
	size_t size   = 0;
};
}  // namespace

const char *Halo2ProofSystem::backend_id() const { return onyx_backend_id(); }

uint32_t Halo2ProofSystem::abi_version() { return onyx_abi_version(); }

bool Halo2ProofSystem::verify(const VerifyingKey &vk, const ProofVerifyArgs &args) const {
	// O0: the only verifier available is the toy circuit, whose public statement is a single
	// 32-byte field element. Malformed shapes return false (the interface reserves exceptions for
	// genuinely malformed encodings, which the C ABI reports as a negative code we map to false).
	if (args.public_inputs.size() != 32)
		return false;
	const int rc = onyx_toy_verify(vk.data.empty() ? nullptr : vk.data.data(), vk.data.size(),
	    args.proof.empty() ? nullptr : args.proof.data(), args.proof.size(), args.public_inputs.data());
	return rc == 1;
}

bool Halo2ProofSystem::poseidon_hash2(const uint8_t in[64], uint8_t out[32]) {
	return onyx_poseidon_hash2(in, out) == 0;
}

bool Halo2ProofSystem::sinsemilla_hash(const BinaryArray &in, uint8_t out[32]) {
	return onyx_sinsemilla_hash(in.empty() ? nullptr : in.data(), in.size(), out) == 0;
}

bool Halo2ProofSystem::verify_authorized_transfer(
    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k) {
	if (encoded.empty())
		return false;
	return onyx_verify_authorized_transfer(
	           encoded.data(), encoded.size(), merkle_depth, circuit_k) == 1;
}

bool Halo2ProofSystem::verify_and_extract_transfer(const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t native_circuit_k, uint32_t token_circuit_k, VerifiedTransferDelta *delta) {
	if (delta != nullptr)
		*delta = VerifiedTransferDelta{};
	if (encoded.empty() || delta == nullptr)
		return false;
	std::array<uint8_t, 16 * 32> nullifiers{};
	std::array<uint8_t, 16 * 32> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	VerifiedTransferDelta result;
	const int rc = onyx_verify_and_extract_transfer(encoded.data(), encoded.size(), merkle_depth,
	    native_circuit_k, token_circuit_k,
	    result.network.data(), result.anchor.data(), &result.expiry_height, &result.fee,
	    nullifiers.data(), 16, &nullifier_count, commitments.data(), 16, &commitment_count);
	if (rc != 1 || nullifier_count > 16 || commitment_count > 16)
		return false;
	result.nullifiers.resize(nullifier_count);
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i < nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32, result.nullifiers[i].begin());
	for (size_t i = 0; i < commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*delta = std::move(result);
	return true;
}

bool Halo2ProofSystem::extract_authenticated_transfer_delta(
    const BinaryArray &encoded, VerifiedTransferDelta *delta) {
	if (delta != nullptr)
		*delta = VerifiedTransferDelta{};
	if (encoded.empty() || delta == nullptr)
		return false;
	std::array<uint8_t, 16 * 32> nullifiers{};
	std::array<uint8_t, 16 * 32> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	VerifiedTransferDelta result;
	const int rc = onyx_extract_authenticated_transfer_delta(encoded.data(), encoded.size(),
	    result.network.data(), result.anchor.data(), &result.expiry_height, &result.fee,
	    nullifiers.data(), 16, &nullifier_count, commitments.data(), 16, &commitment_count);
	if (rc != 1 || nullifier_count > 16 || commitment_count > 16)
		return false;
	result.nullifiers.resize(nullifier_count);
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i < nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.nullifiers[i].begin());
	for (size_t i = 0; i < commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*delta = std::move(result);
	return true;
}

Halo2ProofSystem::AdmissionPrecheck Halo2ProofSystem::precheck_authenticated_transfer_state(
    const BinaryArray &snapshot, const BinaryArray &encoded, uint32_t merkle_depth) {
	if (snapshot.empty() || encoded.empty())
		return AdmissionPrecheck::INVALID;
	const int rc = onyx_precheck_authenticated_transfer_state(
	    snapshot.data(), snapshot.size(), encoded.data(), encoded.size(), merkle_depth);
	if (rc == 1)
		return AdmissionPrecheck::ELIGIBLE;
	if (rc == 0)
		return AdmissionPrecheck::CONFLICT;
	return AdmissionPrecheck::INVALID;
}

bool Halo2ProofSystem::verify_apply_transfer(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t native_circuit_k,
    uint32_t token_circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, uint64_t *fee) {
	if (fee != nullptr)
		*fee = 0;
	if (next_snapshot == nullptr || fee == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	uint64_t next_fee = 0;
	const int rc      = onyx_verify_apply_transfer(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    anchor_window_blocks, encoded.data(), encoded.size(), merkle_depth, native_circuit_k,
	    token_circuit_k, expected_network.data(), block_height, &next.data, &next.size, &next_fee);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*fee = next_fee;
	return true;
}

bool Halo2ProofSystem::verify_program_deployment(const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t funding_circuit_k, uint32_t program_circuit_k, VerifiedProgramDeployment *deployment) {
	if (deployment != nullptr)
		*deployment = VerifiedProgramDeployment{};
	if (encoded.empty() || deployment == nullptr)
		return false;
	std::array<uint8_t, 16> network{};
	std::array<uint8_t, 32> anchor{};
	std::array<uint8_t, 32> program_id{};
	uint64_t expiry_height = 0;
	uint64_t fee           = 0;
	std::array<uint8_t, 32 * 16> nullifiers{};
	std::array<uint8_t, 32 * 16> commitments{};
	size_t nullifier_count  = 0;
	size_t commitment_count = 0;
	const int rc = onyx_verify_program_deployment(encoded.data(), encoded.size(), merkle_depth,
	    funding_circuit_k, program_circuit_k, network.data(), anchor.data(), &expiry_height, &fee,
	    program_id.data(), nullifiers.data(), 16,
	    &nullifier_count, commitments.data(), 16, &commitment_count);
	if (rc != 1 || nullifier_count > 16 || commitment_count > 16)
		return false;
	VerifiedProgramDeployment result;
	result.funding.network       = network;
	result.funding.anchor        = anchor;
	result.funding.expiry_height = expiry_height;
	result.funding.fee           = fee;
	result.program_id            = program_id;
	result.funding.nullifiers.resize(nullifier_count);
	result.funding.commitments.resize(commitment_count);
	for (size_t i = 0; i != nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.funding.nullifiers[i].begin());
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.funding.commitments[i].begin());
	*deployment = std::move(result);
	return true;
}

bool Halo2ProofSystem::extract_authenticated_program_deployment(const BinaryArray &encoded,
    uint32_t merkle_depth, uint32_t program_circuit_k, VerifiedProgramDeployment *deployment) {
	if (deployment != nullptr)
		*deployment = VerifiedProgramDeployment{};
	if (encoded.empty() || deployment == nullptr)
		return false;
	VerifiedProgramDeployment result;
	std::array<uint8_t, 32 * 16> nullifiers{};
	std::array<uint8_t, 32 * 16> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	const int rc = onyx_extract_authenticated_program_deployment(encoded.data(), encoded.size(),
	    merkle_depth, program_circuit_k, result.funding.network.data(), result.funding.anchor.data(),
	    &result.funding.expiry_height, &result.funding.fee, result.program_id.data(),
	    nullifiers.data(), 16, &nullifier_count, commitments.data(), 16, &commitment_count);
	if (rc != 1 || nullifier_count > 16 || commitment_count > 16)
		return false;
	result.funding.nullifiers.resize(nullifier_count);
	result.funding.commitments.resize(commitment_count);
	for (size_t i = 0; i != nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.funding.nullifiers[i].begin());
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.funding.commitments[i].begin());
	*deployment = std::move(result);
	return true;
}

bool Halo2ProofSystem::verify_apply_program_deployment(const BinaryArray &snapshot,
    uint64_t anchor_window_blocks, const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t funding_circuit_k, uint32_t program_circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, uint64_t *fee, std::array<uint8_t, 32> *program_id) {
	if (fee != nullptr)
		*fee = 0;
	if (program_id != nullptr)
		program_id->fill(0);
	if (next_snapshot == nullptr || fee == nullptr || program_id == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	uint64_t next_fee = 0;
	std::array<uint8_t, 32> next_program{};
	const int rc = onyx_verify_apply_program_deployment(snapshot.empty() ? nullptr : snapshot.data(),
	    snapshot.size(), anchor_window_blocks, encoded.data(), encoded.size(), merkle_depth,
	    funding_circuit_k, program_circuit_k, expected_network.data(), block_height, &next.data,
	    &next.size, &next_fee, next_program.data());
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*fee        = next_fee;
	*program_id = next_program;
	return true;
}

bool Halo2ProofSystem::verify_token_issuance(const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t circuit_k, VerifiedTokenIssuance *issuance) {
	if (issuance != nullptr)
		*issuance = VerifiedTokenIssuance{};
	if (encoded.empty() || issuance == nullptr)
		return false;
	VerifiedTokenIssuance result;
	std::array<uint8_t, 32 * 2> commitments{};
	size_t commitment_count = 0;
	const int rc = onyx_verify_and_extract_token_issuance(encoded.data(), encoded.size(), merkle_depth,
	    circuit_k, result.network.data(), result.anchor.data(), &result.expiry_height, result.program_id.data(),
	    &result.sequence, &result.issued_amount, commitments.data(), 2, &commitment_count);
	if (rc != 1 || commitment_count > 2)
		return false;
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*issuance = std::move(result);
	return true;
}

bool Halo2ProofSystem::validate_token_issuance_structure(const BinaryArray &encoded) {
	return !encoded.empty() && onyx_validate_token_issuance_structure(encoded.data(), encoded.size()) == 1;
}

Halo2ProofSystem::AdmissionPrecheck Halo2ProofSystem::precheck_authenticated_token_issuance(
    const BinaryArray &snapshot, const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    VerifiedTokenIssuance *issuance) {
	if (issuance != nullptr)
		*issuance = VerifiedTokenIssuance{};
	if (snapshot.empty() || encoded.empty() || issuance == nullptr)
		return AdmissionPrecheck::INVALID;
	VerifiedTokenIssuance result;
	std::array<uint8_t, 32 * 2> commitments{};
	size_t commitment_count = 0;
	const int rc = onyx_precheck_authenticated_token_issuance(snapshot.data(), snapshot.size(),
	    encoded.data(), encoded.size(), merkle_depth, circuit_k, expected_network.data(), block_height,
	    result.network.data(), result.anchor.data(), &result.expiry_height, result.program_id.data(),
	    &result.sequence, &result.issued_amount, commitments.data(), 2, &commitment_count);
	if ((rc != 0 && rc != 1) || commitment_count > 2)
		return AdmissionPrecheck::INVALID;
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*issuance = std::move(result);
	return rc == 1 ? AdmissionPrecheck::ELIGIBLE : AdmissionPrecheck::CONFLICT;
}

bool Halo2ProofSystem::verify_apply_token_issuance(const BinaryArray &snapshot, const BinaryArray &encoded,
    uint32_t merkle_depth, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
    uint64_t block_height, BinaryArray *next_snapshot, VerifiedTokenIssuance *issuance) {
	if (issuance != nullptr)
		*issuance = VerifiedTokenIssuance{};
	if (next_snapshot == nullptr || issuance == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (snapshot.empty() || encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	VerifiedTokenIssuance result;
	const int rc = onyx_verify_apply_token_issuance(snapshot.data(), snapshot.size(), encoded.data(),
	    encoded.size(), merkle_depth, circuit_k, expected_network.data(), block_height, &next.data, &next.size,
	    result.program_id.data(), &result.sequence, &result.issued_amount);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*issuance = result;
	return true;
}

bool Halo2ProofSystem::verify_apply_standard_program_transaction(const BinaryArray &snapshot,
    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, VerifiedTransferDelta *delta) {
	if (delta != nullptr)
		*delta = VerifiedTransferDelta{};
	if (next_snapshot == nullptr || delta == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (snapshot.empty() || encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	VerifiedTransferDelta result;
	std::array<uint8_t, 32 * 2> nullifiers{};
	std::array<uint8_t, 32 * 2> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	const int rc = onyx_verify_apply_standard_program_transaction(snapshot.data(), snapshot.size(),
	    encoded.data(), encoded.size(), merkle_depth, circuit_k, expected_network.data(), block_height,
	    &next.data, &next.size, result.network.data(), result.anchor.data(), &result.expiry_height,
	    nullifiers.data(), 2, &nullifier_count, commitments.data(), 2, &commitment_count);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES) ||
	    nullifier_count > 2 || commitment_count > 2) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	result.fee = 0;
	result.nullifiers.resize(nullifier_count);
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i != nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.nullifiers[i].begin());
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*next_snapshot = std::move(next_result);
	*delta         = std::move(result);
	return true;
}

bool Halo2ProofSystem::extract_authenticated_standard_program_delta(
    const BinaryArray &encoded, VerifiedTransferDelta *delta,
    std::vector<std::array<uint8_t, 32>> *state_keys) {
	if (delta != nullptr)
		*delta = VerifiedTransferDelta{};
	if (state_keys != nullptr)
		state_keys->clear();
	if (encoded.empty() || delta == nullptr || state_keys == nullptr)
		return false;
	VerifiedTransferDelta result;
	std::array<uint8_t, 32 * 2> nullifiers{};
	std::array<uint8_t, 32 * 2> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	std::array<uint8_t, 32 * 8> keys{};
	size_t key_count = 0;
	const int rc = onyx_extract_authenticated_standard_program_delta(encoded.data(), encoded.size(),
	    result.network.data(), result.anchor.data(), &result.expiry_height, nullifiers.data(), 2,
	    &nullifier_count, commitments.data(), 2, &commitment_count, keys.data(), 8, &key_count);
	if (rc != 1 || nullifier_count > 2 || commitment_count > 2 || key_count > 8)
		return false;
	result.fee = 0;
	result.nullifiers.resize(nullifier_count);
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i != nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.nullifiers[i].begin());
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	std::vector<std::array<uint8_t, 32>> key_result;
	key_result.resize(key_count);
	for (size_t i = 0; i != key_count; ++i)
		std::copy(keys.begin() + i * 32, keys.begin() + (i + 1) * 32, key_result[i].begin());
	*delta      = std::move(result);
	*state_keys = std::move(key_result);
	return true;
}

Halo2ProofSystem::AdmissionPrecheck Halo2ProofSystem::precheck_authenticated_standard_program_state(
    const BinaryArray &snapshot, const BinaryArray &encoded, uint32_t merkle_depth) {
	if (snapshot.empty() || encoded.empty())
		return AdmissionPrecheck::INVALID;
	const int rc = onyx_precheck_authenticated_standard_program_state(
	    snapshot.data(), snapshot.size(), encoded.data(), encoded.size(), merkle_depth);
	if (rc == 1)
		return AdmissionPrecheck::ELIGIBLE;
	if (rc == 0)
		return AdmissionPrecheck::CONFLICT;
	return AdmissionPrecheck::INVALID;
}

bool Halo2ProofSystem::verify_apply_bridge(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
    const BinaryArray &encoded, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
    uint64_t block_height, BinaryArray *next_snapshot, VerifiedBridgeDelta *delta) {
	if (delta != nullptr)
		*delta = VerifiedBridgeDelta{};
	if (next_snapshot == nullptr || delta == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	VerifiedBridgeDelta result;
	const int rc = onyx_verify_apply_bridge(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    anchor_window_blocks, encoded.data(), encoded.size(), circuit_k, expected_network.data(), block_height,
	    &next.data, &next.size, &result.legacy_amount, &result.legacy_stack_index,
	    result.legacy_key_image.data(), result.ownership_sighash.data(), result.ownership_signature.data(),
	    &result.fee);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*delta                  = result;
	return true;
}

bool Halo2ProofSystem::verify_bridge(
    const BinaryArray &encoded, uint32_t circuit_k, VerifiedBridgeDelta *delta) {
	if (delta != nullptr)
		*delta = VerifiedBridgeDelta{};
	if (delta == nullptr)
		return false;
	if (encoded.empty())
		return false;
	VerifiedBridgeDelta result;
	const int rc = onyx_verify_bridge(encoded.data(), encoded.size(), circuit_k, &result.legacy_amount,
	    &result.legacy_stack_index, result.legacy_key_image.data(), result.ownership_sighash.data(),
	    result.ownership_signature.data(), &result.fee);
	if (rc != 1)
		return false;
	*delta = result;
	return true;
}

bool Halo2ProofSystem::state_supply_audit(const BinaryArray &snapshot, SupplyAudit *audit) {
	if (audit != nullptr)
		*audit = SupplyAudit{};
	if (snapshot.empty() || audit == nullptr)
		return false;
	SupplyAudit result;
	if (onyx_state_supply_audit(snapshot.data(), snapshot.size(), &result.total_bridged,
	        &result.total_fees, &result.circulating_supply, &result.commitment_count,
	        &result.program_count, &result.current_block_program_cost, result.commitment_root.data()) != 1)
		return false;
	*audit = result;
	return true;
}

bool Halo2ProofSystem::state_standard_program_state(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &program_id, const BinaryArray &application,
    std::array<uint8_t, 32> *state, bool *found) {
	if (state != nullptr)
		state->fill(0);
	if (found != nullptr)
		*found = false;
	if (snapshot.empty() || application.empty() || state == nullptr || found == nullptr)
		return false;
	uint8_t present = 0;
	std::array<uint8_t, 32> value{};
	if (onyx_state_standard_program_state(snapshot.data(), snapshot.size(), program_id.data(),
	        application.data(), application.size(), value.data(), &present) != 1 || present > 1)
		return false;
	*state = value;
	*found = present != 0;
	return true;
}

bool Halo2ProofSystem::wallet_address(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 16> &network, uint32_t address_index, std::array<uint8_t, 91> *address) {
	if (address == nullptr)
		return false;
	address->fill(0);
	return onyx_wallet_address(seed.data(), network.data(), address_index, address->data()) == 0;
}

bool Halo2ProofSystem::full_viewing_key(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 16> &network, std::array<uint8_t, 177> *viewing_key) {
	if (viewing_key == nullptr)
		return false;
	viewing_key->fill(0);
	return onyx_full_viewing_key(seed.data(), network.data(), viewing_key->data()) == 0;
}

bool Halo2ProofSystem::wallet_scan(const BinaryArray &snapshot, const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 16> &network, uint8_t envelope_type, uint64_t block_height,
    uint32_t circuit_k, uint32_t program_k,
    const BinaryArray &encoded,
    BinaryArray *next_snapshot, WalletScanResult *result) {
	if (result != nullptr)
		*result = WalletScanResult{};
	if (next_snapshot == nullptr || result == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(), seed.data(),
	    network.data(), envelope_type, block_height, circuit_k, program_k,
	    encoded.data(), encoded.size(), &next.data, &next.size, &scanned.balance,
	    &scanned.note_count, scanned.root.data());
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*result = scanned;
	return true;
}

bool Halo2ProofSystem::wallet_scan_viewing(const BinaryArray &snapshot, const BinaryArray &viewing_key,
    uint8_t envelope_type, uint64_t block_height, uint32_t circuit_k, uint32_t program_k,
    const BinaryArray &encoded,
    BinaryArray *next_snapshot, WalletScanResult *result) {
	if (result != nullptr)
		*result = WalletScanResult{};
	if (next_snapshot == nullptr || result == nullptr) {
		if (next_snapshot != nullptr)
			next_snapshot->clear();
		return false;
	}
	if (viewing_key.size() != 177 || encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan_viewing(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    viewing_key.data(), viewing_key.size(), envelope_type, block_height, circuit_k, program_k,
	    encoded.data(), encoded.size(), &next.data,
	    &next.size, &scanned.balance, &scanned.note_count, scanned.root.data());
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	*result = scanned;
	return true;
}

bool Halo2ProofSystem::wallet_summary(const BinaryArray &snapshot, WalletScanResult *result) {
	if (result != nullptr)
		*result = WalletScanResult{};
	if (snapshot.empty() || result == nullptr)
		return false;
	WalletScanResult summary;
	if (onyx_wallet_summary(snapshot.data(), snapshot.size(), &summary.balance, &summary.note_count,
	        summary.root.data()) != 1)
		return false;
	*result = summary;
	return true;
}

bool Halo2ProofSystem::wallet_asset_balance(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &program_id, const std::array<uint8_t, 32> &asset_id,
    WalletAssetBalance *result) {
	if (result != nullptr)
		*result = WalletAssetBalance{};
	if (snapshot.empty() || result == nullptr)
		return false;
	WalletAssetBalance balance;
	if (onyx_wallet_asset_balance(snapshot.data(), snapshot.size(), program_id.data(), asset_id.data(),
	        &balance.balance, &balance.unspent_note_count) != 1)
		return false;
	*result = balance;
	return true;
}

bool Halo2ProofSystem::wallet_token_program_status(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &program_id, uint64_t query_height,
    WalletTokenProgramStatus *result) {
	if (result != nullptr)
		*result = WalletTokenProgramStatus{};
	if (snapshot.empty() || result == nullptr)
		return false;
	WalletTokenProgramStatus status;
	OnyxBuffer metadata;
	int active = 0;
	const int rc = onyx_wallet_token_program_status(snapshot.data(), snapshot.size(), program_id.data(),
	    query_height, status.issuer.data(), &status.max_supply, &status.issued_supply,
	    &status.next_sequence, &status.activation_height, &status.deactivation_height, &active,
	    &metadata.data, &metadata.size);
	if (rc != 1 || !metadata.valid_optional(ONYX_ZK_MAX_TOKEN_METADATA_BYTES) ||
	    (active != 0 && active != 1))
		return false;
	status.metadata = metadata.copy();
	status.active = active != 0;
	*result = std::move(status);
	return true;
}

bool Halo2ProofSystem::wallet_reserve_spends(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 16> &network,
    const BinaryArray &encoded, BinaryArray *next_snapshot) {
	if (next_snapshot == nullptr)
		return false;
	if (snapshot.empty() || encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	const int rc = onyx_wallet_reserve_spends(snapshot.data(), snapshot.size(), seed.data(), network.data(),
	    encoded.data(), encoded.size(), &next.data, &next.size);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	return true;
}

bool Halo2ProofSystem::wallet_reserve_deployment_spends(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 16> &network,
    const BinaryArray &encoded, BinaryArray *next_snapshot) {
	if (next_snapshot == nullptr)
		return false;
	if (snapshot.empty() || encoded.empty()) {
		next_snapshot->clear();
		return false;
	}
	OnyxBuffer next;
	const int rc = onyx_wallet_reserve_deployment_spends(snapshot.data(), snapshot.size(), seed.data(),
	    network.data(), encoded.data(), encoded.size(), &next.data, &next.size);
	if (rc != 1 || !next.valid_nonempty(ONYX_ZK_MAX_STATE_SNAPSHOT_BYTES)) {
		next_snapshot->clear();
		return false;
	}
	BinaryArray next_result = next.copy();
	*next_snapshot          = std::move(next_result);
	return true;
}

bool Halo2ProofSystem::wallet_create_bridge(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 91> &recipient, uint64_t expiry_height, uint64_t fee,
    uint64_t legacy_amount, uint64_t legacy_stack_index,
    const std::array<uint8_t, 32> &legacy_key_image, const BinaryArray &memo, uint32_t circuit_k,
    BinaryArray *unsigned_bridge, std::array<uint8_t, 32> *ownership_sighash) {
	if (unsigned_bridge == nullptr || ownership_sighash == nullptr) {
		if (unsigned_bridge != nullptr)
			unsigned_bridge->clear();
		if (ownership_sighash != nullptr)
			ownership_sighash->fill(0);
		return false;
	}
	OnyxBuffer encoded;
	std::array<uint8_t, 32> sighash{};
	const int rc = onyx_wallet_create_bridge(seed.data(), recipient.data(), expiry_height, fee, legacy_amount,
	    legacy_stack_index, legacy_key_image.data(), memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k,
	    &encoded.data, &encoded.size, sighash.data());
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_AUTHORIZED_TRANSACTION_BYTES)) {
		unsigned_bridge->clear();
		ownership_sighash->fill(0);
		return false;
	}
	BinaryArray bridge_result = encoded.copy();
	*unsigned_bridge          = std::move(bridge_result);
	*ownership_sighash        = sighash;
	return true;
}

bool Halo2ProofSystem::wallet_finalize_bridge(const BinaryArray &unsigned_bridge,
    const std::array<uint8_t, 64> &ownership_signature, BinaryArray *finalized_bridge) {
	if (finalized_bridge == nullptr)
		return false;
	if (unsigned_bridge.empty()) {
		finalized_bridge->clear();
		return false;
	}
	OnyxBuffer encoded;
	const int rc = onyx_wallet_finalize_bridge(unsigned_bridge.data(), unsigned_bridge.size(),
	    ownership_signature.data(), &encoded.data, &encoded.size);
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_AUTHORIZED_TRANSACTION_BYTES)) {
		finalized_bridge->clear();
		return false;
	}
	BinaryArray bridge_result = encoded.copy();
	*finalized_bridge         = std::move(bridge_result);
	return true;
}

bool Halo2ProofSystem::wallet_create_program_deployment(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, uint64_t max_supply, const BinaryArray &metadata,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t funding_circuit_k, uint32_t program_circuit_k,
    BinaryArray *deployment,
    std::array<uint8_t, 32> *program_id) {
	if (deployment == nullptr || program_id == nullptr) {
		if (deployment != nullptr)
			deployment->clear();
		if (program_id != nullptr)
			program_id->fill(0);
		return false;
	}
	if (wallet_snapshot.empty() || metadata.empty()) {
		deployment->clear();
		program_id->fill(0);
		return false;
	}
	OnyxBuffer encoded;
	std::array<uint8_t, 32> next_program{};
	const int rc = onyx_wallet_create_program_deployment(wallet_snapshot.data(), wallet_snapshot.size(),
	    seed.data(), max_supply, metadata.data(), metadata.size(), inclusion_height, activation_height,
	    deactivation_height, expiry_height, fee, funding_circuit_k, program_circuit_k, &encoded.data,
	    &encoded.size, next_program.data());
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_PROGRAM_DEPLOYMENT_BYTES)) {
		deployment->clear();
		program_id->fill(0);
		return false;
	}
	BinaryArray deployment_result = encoded.copy();
	*deployment                   = std::move(deployment_result);
	*program_id                   = next_program;
	return true;
}

bool Halo2ProofSystem::wallet_create_standard_program_deployment(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, uint8_t kind, uint64_t inclusion_height,
    uint64_t activation_height, uint64_t deactivation_height, uint64_t expiry_height,
    uint64_t fee, uint32_t circuit_k, BinaryArray *deployment,
    std::array<uint8_t, 32> *program_id) {
	if (deployment == nullptr || program_id == nullptr) {
		if (deployment != nullptr)
			deployment->clear();
		if (program_id != nullptr)
			program_id->fill(0);
		return false;
	}
	if (wallet_snapshot.empty() || kind < 1 || kind > 4) {
		deployment->clear();
		program_id->fill(0);
		return false;
	}
	OnyxBuffer encoded;
	std::array<uint8_t, 32> next_program{};
	const int rc = onyx_wallet_create_standard_program_deployment(wallet_snapshot.data(),
	    wallet_snapshot.size(), seed.data(), kind, inclusion_height, activation_height,
	    deactivation_height, expiry_height, fee, circuit_k, &encoded.data, &encoded.size, next_program.data());
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_PROGRAM_DEPLOYMENT_BYTES)) {
		deployment->clear();
		program_id->fill(0);
		return false;
	}
	BinaryArray deployment_result = encoded.copy();
	*deployment                   = std::move(deployment_result);
	*program_id                   = next_program;
	return true;
}

bool Halo2ProofSystem::wallet_create_standard_program_call(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 32> &program_id,
    uint64_t inclusion_height, uint64_t valid_from_height, uint64_t expiry_height,
    const BinaryArray &application, const std::array<uint8_t, 32> &prior_state,
    const std::array<uint8_t, 32> &next_state, const BinaryArray &witness,
    uint32_t circuit_k, BinaryArray *transaction) {
	if (transaction == nullptr)
		return false;
	if (wallet_snapshot.empty() || application.empty() || witness.empty() || witness.size() % 32 != 0) {
		transaction->clear();
		return false;
	}
	OnyxBuffer encoded;
	const int rc = onyx_wallet_create_standard_program_call(wallet_snapshot.data(),
	    wallet_snapshot.size(), seed.data(), program_id.data(), inclusion_height, valid_from_height,
	    expiry_height, application.data(), application.size(), prior_state.data(), next_state.data(),
	    witness.data(), witness.size() / 32, circuit_k, &encoded.data, &encoded.size);
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_CONTEXTUAL_TRANSACTION_BYTES)) {
		transaction->clear();
		return false;
	}
	BinaryArray transaction_result = encoded.copy();
	*transaction                   = std::move(transaction_result);
	return true;
}

bool Halo2ProofSystem::wallet_create_token_issuance(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    const std::array<uint8_t, 32> &program_id, uint64_t issued_amount, uint64_t inclusion_height,
    uint64_t expiry_height,
    const BinaryArray &memo, uint32_t circuit_k, BinaryArray *issuance, uint64_t *sequence) {
	if (sequence != nullptr)
		*sequence = 0;
	if (issuance == nullptr || sequence == nullptr) {
		if (issuance != nullptr)
			issuance->clear();
		return false;
	}
	if (wallet_snapshot.empty()) {
		issuance->clear();
		return false;
	}
	OnyxBuffer encoded;
	uint64_t next_sequence = 0;
	const int rc = onyx_wallet_create_token_issuance(wallet_snapshot.data(), wallet_snapshot.size(),
	    seed.data(), recipient.data(), program_id.data(), issued_amount, inclusion_height, expiry_height,
	    memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k,
	    &encoded.data, &encoded.size, &next_sequence);
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_TOKEN_ISSUANCE_BYTES)) {
		issuance->clear();
		return false;
	}
	BinaryArray issuance_result = encoded.copy();
	*issuance                   = std::move(issuance_result);
	*sequence                   = next_sequence;
	return true;
}

bool Halo2ProofSystem::wallet_create_transfer(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    uint64_t amount, uint64_t fee, uint64_t expiry_height, const BinaryArray &memo,
    uint32_t circuit_k, BinaryArray *transaction) {
	if (transaction == nullptr)
		return false;
	if (snapshot.empty()) {
		transaction->clear();
		return false;
	}
	OnyxBuffer encoded;
	const int rc = onyx_wallet_create_transfer(snapshot.data(), snapshot.size(), seed.data(), recipient.data(),
	    amount, fee, expiry_height, memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k,
	    &encoded.data, &encoded.size);
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_AUTHORIZED_TRANSACTION_BYTES)) {
		transaction->clear();
		return false;
	}
	BinaryArray transaction_result = encoded.copy();
	*transaction                   = std::move(transaction_result);
	return true;
}

bool Halo2ProofSystem::wallet_create_mixed_token_transfer(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    const std::array<uint8_t, 32> &program_id, uint64_t token_amount, uint64_t fee,
    uint64_t expiry_height, const BinaryArray &memo, uint32_t circuit_k, BinaryArray *transaction) {
	if (transaction == nullptr)
		return false;
	if (snapshot.empty()) {
		transaction->clear();
		return false;
	}
	OnyxBuffer encoded;
	const int rc = onyx_wallet_create_mixed_token_transfer(snapshot.data(), snapshot.size(), seed.data(),
	    recipient.data(), program_id.data(), token_amount, fee, expiry_height,
	    memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k, &encoded.data, &encoded.size);
	if (rc != 1 || !encoded.valid_nonempty(ONYX_ZK_MAX_AUTHORIZED_TRANSACTION_BYTES)) {
		transaction->clear();
		return false;
	}
	BinaryArray transaction_result = encoded.copy();
	*transaction                   = std::move(transaction_result);
	return true;
}

bool Halo2ProofSystem::toy_prove(
    uint64_t a, uint64_t b, BinaryArray *proof, BinaryArray *vk, std::array<uint8_t, 32> *public_out) {
	if (proof == nullptr || vk == nullptr || public_out == nullptr) {
		if (proof != nullptr)
			proof->clear();
		if (vk != nullptr)
			vk->clear();
		if (public_out != nullptr)
			public_out->fill(0);
		return false;
	}
	proof->clear();
	vk->clear();
	public_out->fill(0);
	OnyxBuffer proof_buffer;
	OnyxBuffer vk_buffer;
	std::array<uint8_t, 32> public_buf{};
	if (onyx_toy_prove(a, b, &proof_buffer.data, &proof_buffer.size,
	        &vk_buffer.data, &vk_buffer.size, public_buf.data()) != 0)
		return false;
	if (!proof_buffer.valid_nonempty(ONYX_ZK_MAX_PROOF_BYTES) ||
	    !vk_buffer.valid_optional(ONYX_ZK_MAX_VK_BYTES))
		return false;
	BinaryArray proof_result = proof_buffer.copy();
	BinaryArray vk_result    = vk_buffer.copy();
	*proof      = std::move(proof_result);
	*vk         = std::move(vk_result);
	*public_out = public_buf;
	return true;
}

}  // namespace zk
}  // namespace cn
