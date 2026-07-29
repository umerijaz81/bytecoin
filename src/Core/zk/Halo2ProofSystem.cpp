// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Halo2ProofSystem.hpp"
#include <algorithm>
#include <utility>
#include "onyx_zk.h"  // vendored C ABI (vendor/onyx-zk/include), on the include path when ONYX_ZK=ON

namespace cn {
namespace zk {

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
    uint32_t circuit_k, VerifiedTransferDelta *delta) {
	if (encoded.empty() || delta == nullptr)
		return false;
	std::array<uint8_t, 16 * 32> nullifiers{};
	std::array<uint8_t, 16 * 32> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	VerifiedTransferDelta result;
	const int rc = onyx_verify_and_extract_transfer(encoded.data(), encoded.size(), merkle_depth, circuit_k,
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

bool Halo2ProofSystem::verify_apply_transfer(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, uint64_t *fee) {
	if (encoded.empty() || next_snapshot == nullptr || fee == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len   = 0;
	uint64_t next_fee = 0;
	const int rc      = onyx_verify_apply_transfer(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    anchor_window_blocks, encoded.data(), encoded.size(), merkle_depth, circuit_k, expected_network.data(),
	    block_height, &next_ptr, &next_len, &next_fee);
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*fee = next_fee;
	return true;
}

bool Halo2ProofSystem::verify_program_deployment(const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t circuit_k, VerifiedProgramDeployment *deployment) {
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
	const int rc = onyx_verify_program_deployment(encoded.data(), encoded.size(), merkle_depth, circuit_k,
	    network.data(), anchor.data(), &expiry_height, &fee, program_id.data(), nullifiers.data(), 16,
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

bool Halo2ProofSystem::verify_apply_program_deployment(const BinaryArray &snapshot,
    uint64_t anchor_window_blocks, const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, uint64_t *fee, std::array<uint8_t, 32> *program_id) {
	if (encoded.empty() || next_snapshot == nullptr || fee == nullptr || program_id == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len   = 0;
	uint64_t next_fee = 0;
	std::array<uint8_t, 32> next_program{};
	const int rc = onyx_verify_apply_program_deployment(snapshot.empty() ? nullptr : snapshot.data(),
	    snapshot.size(), anchor_window_blocks, encoded.data(), encoded.size(), merkle_depth, circuit_k,
	    expected_network.data(), block_height, &next_ptr, &next_len, &next_fee, next_program.data());
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*fee        = next_fee;
	*program_id = next_program;
	return true;
}

bool Halo2ProofSystem::verify_token_issuance(const BinaryArray &encoded, uint32_t merkle_depth,
    uint32_t circuit_k, VerifiedTokenIssuance *issuance) {
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

bool Halo2ProofSystem::verify_apply_token_issuance(const BinaryArray &snapshot, const BinaryArray &encoded,
    uint32_t merkle_depth, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
    uint64_t block_height, BinaryArray *next_snapshot, VerifiedTokenIssuance *issuance) {
	if (snapshot.empty() || encoded.empty() || next_snapshot == nullptr || issuance == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len   = 0;
	VerifiedTokenIssuance result;
	const int rc = onyx_verify_apply_token_issuance(snapshot.data(), snapshot.size(), encoded.data(),
	    encoded.size(), merkle_depth, circuit_k, expected_network.data(), block_height, &next_ptr, &next_len,
	    result.program_id.data(), &result.sequence, &result.issued_amount);
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*issuance = result;
	return true;
}

bool Halo2ProofSystem::verify_apply_standard_program_transaction(const BinaryArray &snapshot,
    const BinaryArray &encoded, uint32_t merkle_depth, uint32_t circuit_k,
    const std::array<uint8_t, 16> &expected_network, uint64_t block_height,
    BinaryArray *next_snapshot, VerifiedTransferDelta *delta) {
	if (snapshot.empty() || encoded.empty() || next_snapshot == nullptr || delta == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	VerifiedTransferDelta result;
	std::array<uint8_t, 32 * 2> nullifiers{};
	std::array<uint8_t, 32 * 2> commitments{};
	size_t nullifier_count = 0;
	size_t commitment_count = 0;
	const int rc = onyx_verify_apply_standard_program_transaction(snapshot.data(), snapshot.size(),
	    encoded.data(), encoded.size(), merkle_depth, circuit_k, expected_network.data(), block_height,
	    &next_ptr, &next_len, result.network.data(), result.anchor.data(), &result.expiry_height,
	    nullifiers.data(), 2, &nullifier_count, commitments.data(), 2, &commitment_count);
	if (rc != 1 || next_ptr == nullptr || next_len == 0 || nullifier_count > 2 || commitment_count > 2) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	result.fee = 0;
	result.nullifiers.resize(nullifier_count);
	result.commitments.resize(commitment_count);
	for (size_t i = 0; i != nullifier_count; ++i)
		std::copy(nullifiers.begin() + i * 32, nullifiers.begin() + (i + 1) * 32,
		    result.nullifiers[i].begin());
	for (size_t i = 0; i != commitment_count; ++i)
		std::copy(commitments.begin() + i * 32, commitments.begin() + (i + 1) * 32,
		    result.commitments[i].begin());
	*delta = std::move(result);
	return true;
}

bool Halo2ProofSystem::extract_authenticated_standard_program_delta(
    const BinaryArray &encoded, VerifiedTransferDelta *delta,
    std::vector<std::array<uint8_t, 32>> *state_keys) {
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
	*delta = std::move(result);
	state_keys->resize(key_count);
	for (size_t i = 0; i != key_count; ++i)
		std::copy(keys.begin() + i * 32, keys.begin() + (i + 1) * 32, (*state_keys)[i].begin());
	return true;
}

bool Halo2ProofSystem::verify_apply_bridge(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
    const BinaryArray &encoded, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
    uint64_t block_height, BinaryArray *next_snapshot, VerifiedBridgeDelta *delta) {
	if (next_snapshot == nullptr || delta == nullptr)
		return false;
	next_snapshot->clear();
	*delta = VerifiedBridgeDelta{};
	if (encoded.empty())
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len   = 0;
	VerifiedBridgeDelta result;
	const int rc = onyx_verify_apply_bridge(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    anchor_window_blocks, encoded.data(), encoded.size(), circuit_k, expected_network.data(), block_height,
	    &next_ptr, &next_len, &result.legacy_amount, &result.legacy_stack_index,
	    result.legacy_key_image.data(), result.ownership_sighash.data(), result.ownership_signature.data(),
	    &result.fee);
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*delta = result;
	return true;
}

bool Halo2ProofSystem::verify_bridge(
    const BinaryArray &encoded, uint32_t circuit_k, VerifiedBridgeDelta *delta) {
	if (delta == nullptr)
		return false;
	*delta = VerifiedBridgeDelta{};
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
	return address != nullptr &&
	       onyx_wallet_address(seed.data(), network.data(), address_index, address->data()) == 0;
}

bool Halo2ProofSystem::full_viewing_key(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 16> &network, std::array<uint8_t, 177> *viewing_key) {
	return viewing_key != nullptr &&
	       onyx_full_viewing_key(seed.data(), network.data(), viewing_key->data()) == 0;
}

bool Halo2ProofSystem::wallet_scan(const BinaryArray &snapshot, const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 16> &network, uint8_t envelope_type, uint64_t block_height,
    uint32_t circuit_k,
    const BinaryArray &encoded,
    BinaryArray *next_snapshot, WalletScanResult *result) {
	if (encoded.empty() || next_snapshot == nullptr || result == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(), seed.data(),
	    network.data(), envelope_type, block_height, circuit_k,
	    encoded.data(), encoded.size(), &next_ptr, &next_len, &scanned.balance,
	    &scanned.note_count, scanned.root.data());
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*result = scanned;
	return true;
}

bool Halo2ProofSystem::wallet_scan_viewing(const BinaryArray &snapshot, const BinaryArray &viewing_key,
    uint8_t envelope_type, uint64_t block_height, uint32_t circuit_k, const BinaryArray &encoded,
    BinaryArray *next_snapshot, WalletScanResult *result) {
	if (viewing_key.size() != 177 || encoded.empty() || next_snapshot == nullptr || result == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan_viewing(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    viewing_key.data(), viewing_key.size(), envelope_type, block_height, circuit_k,
	    encoded.data(), encoded.size(), &next_ptr,
	    &next_len, &scanned.balance, &scanned.note_count, scanned.root.data());
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	*result = scanned;
	return true;
}

bool Halo2ProofSystem::wallet_summary(const BinaryArray &snapshot, WalletScanResult *result) {
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
	if (snapshot.empty() || result == nullptr)
		return false;
	WalletTokenProgramStatus status;
	uint8_t *metadata_ptr = nullptr;
	size_t metadata_len = 0;
	int active = 0;
	const int rc = onyx_wallet_token_program_status(snapshot.data(), snapshot.size(), program_id.data(),
	    query_height, status.issuer.data(), &status.max_supply, &status.issued_supply,
	    &status.next_sequence, &status.activation_height, &status.deactivation_height, &active,
	    &metadata_ptr, &metadata_len);
	if (rc != 1 || (metadata_len != 0 && metadata_ptr == nullptr)) {
		if (metadata_ptr != nullptr)
			onyx_free(metadata_ptr, metadata_len);
		return false;
	}
	try {
		if (metadata_len != 0)
			status.metadata.assign(metadata_ptr, metadata_ptr + metadata_len);
	} catch (...) {
		if (metadata_ptr != nullptr)
			onyx_free(metadata_ptr, metadata_len);
		throw;
	}
	if (metadata_ptr != nullptr)
		onyx_free(metadata_ptr, metadata_len);
	status.active = active != 0;
	*result = std::move(status);
	return true;
}

bool Halo2ProofSystem::wallet_reserve_spends(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 16> &network,
    const BinaryArray &encoded, BinaryArray *next_snapshot) {
	if (snapshot.empty() || encoded.empty() || next_snapshot == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	const int rc = onyx_wallet_reserve_spends(snapshot.data(), snapshot.size(), seed.data(), network.data(),
	    encoded.data(), encoded.size(), &next_ptr, &next_len);
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	return true;
}

bool Halo2ProofSystem::wallet_reserve_deployment_spends(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 16> &network,
    const BinaryArray &encoded, BinaryArray *next_snapshot) {
	if (snapshot.empty() || encoded.empty() || next_snapshot == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	const int rc = onyx_wallet_reserve_deployment_spends(snapshot.data(), snapshot.size(), seed.data(),
	    network.data(), encoded.data(), encoded.size(), &next_ptr, &next_len);
	if (rc != 1 || next_ptr == nullptr || next_len == 0) {
		if (next_ptr != nullptr)
			onyx_free(next_ptr, next_len);
		return false;
	}
	try {
		next_snapshot->assign(next_ptr, next_ptr + next_len);
	} catch (...) {
		onyx_free(next_ptr, next_len);
		throw;
	}
	onyx_free(next_ptr, next_len);
	return true;
}

bool Halo2ProofSystem::wallet_create_bridge(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 91> &recipient, uint64_t expiry_height, uint64_t fee,
    uint64_t legacy_amount, uint64_t legacy_stack_index,
    const std::array<uint8_t, 32> &legacy_key_image, const BinaryArray &memo, uint32_t circuit_k,
    BinaryArray *unsigned_bridge, std::array<uint8_t, 32> *ownership_sighash) {
	if (unsigned_bridge == nullptr || ownership_sighash == nullptr)
		return false;
	unsigned_bridge->clear();
	ownership_sighash->fill(0);
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_bridge(seed.data(), recipient.data(), expiry_height, fee, legacy_amount,
	    legacy_stack_index, legacy_key_image.data(), memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k,
	    &ptr, &len, ownership_sighash->data());
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		unsigned_bridge->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::wallet_finalize_bridge(const BinaryArray &unsigned_bridge,
    const std::array<uint8_t, 64> &ownership_signature, BinaryArray *finalized_bridge) {
	if (finalized_bridge == nullptr)
		return false;
	finalized_bridge->clear();
	if (unsigned_bridge.empty())
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_finalize_bridge(unsigned_bridge.data(), unsigned_bridge.size(),
	    ownership_signature.data(), &ptr, &len);
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		finalized_bridge->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::wallet_create_program_deployment(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, uint64_t max_supply, const BinaryArray &metadata,
    uint64_t inclusion_height, uint64_t activation_height, uint64_t deactivation_height,
    uint64_t expiry_height, uint64_t fee, uint32_t circuit_k, BinaryArray *deployment,
    std::array<uint8_t, 32> *program_id) {
	if (wallet_snapshot.empty() || metadata.empty() || deployment == nullptr || program_id == nullptr)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_program_deployment(wallet_snapshot.data(), wallet_snapshot.size(),
	    seed.data(), max_supply, metadata.data(), metadata.size(), inclusion_height, activation_height,
	    deactivation_height, expiry_height, fee, circuit_k, &ptr, &len, program_id->data());
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		deployment->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::wallet_create_standard_program_deployment(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, uint8_t kind, uint64_t inclusion_height,
    uint64_t activation_height, uint64_t deactivation_height, uint64_t expiry_height,
    uint64_t fee, uint32_t circuit_k, BinaryArray *deployment,
    std::array<uint8_t, 32> *program_id) {
	if (deployment == nullptr || program_id == nullptr)
		return false;
	deployment->clear();
	program_id->fill(0);
	if (wallet_snapshot.empty() || kind < 1 || kind > 4)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_standard_program_deployment(wallet_snapshot.data(),
	    wallet_snapshot.size(), seed.data(), kind, inclusion_height, activation_height,
	    deactivation_height, expiry_height, fee, circuit_k, &ptr, &len, program_id->data());
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		deployment->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
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
	transaction->clear();
	if (wallet_snapshot.empty() || application.empty() || witness.empty() || witness.size() % 32 != 0)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_standard_program_call(wallet_snapshot.data(),
	    wallet_snapshot.size(), seed.data(), program_id.data(), inclusion_height, valid_from_height,
	    expiry_height, application.data(), application.size(), prior_state.data(), next_state.data(),
	    witness.data(), witness.size() / 32, circuit_k, &ptr, &len);
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		transaction->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::wallet_create_token_issuance(const BinaryArray &wallet_snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    const std::array<uint8_t, 32> &program_id, uint64_t issued_amount, uint64_t inclusion_height,
    uint64_t expiry_height,
    const BinaryArray &memo, uint32_t circuit_k, BinaryArray *issuance, uint64_t *sequence) {
	if (wallet_snapshot.empty() || issuance == nullptr || sequence == nullptr)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	uint64_t next_sequence = 0;
	const int rc = onyx_wallet_create_token_issuance(wallet_snapshot.data(), wallet_snapshot.size(),
	    seed.data(), recipient.data(), program_id.data(), issued_amount, inclusion_height, expiry_height,
	    memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k, &ptr, &len, &next_sequence);
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		issuance->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	*sequence = next_sequence;
	return true;
}

bool Halo2ProofSystem::wallet_create_transfer(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    uint64_t amount, uint64_t fee, uint64_t expiry_height, const BinaryArray &memo,
    uint32_t circuit_k, BinaryArray *transaction) {
	if (snapshot.empty() || transaction == nullptr)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_transfer(snapshot.data(), snapshot.size(), seed.data(), recipient.data(),
	    amount, fee, expiry_height, memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k, &ptr, &len);
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		transaction->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::wallet_create_mixed_token_transfer(const BinaryArray &snapshot,
    const std::array<uint8_t, 32> &seed, const std::array<uint8_t, 91> &recipient,
    const std::array<uint8_t, 32> &program_id, uint64_t token_amount, uint64_t fee,
    uint64_t expiry_height, const BinaryArray &memo, uint32_t circuit_k, BinaryArray *transaction) {
	if (snapshot.empty() || transaction == nullptr)
		return false;
	uint8_t *ptr = nullptr;
	size_t len = 0;
	const int rc = onyx_wallet_create_mixed_token_transfer(snapshot.data(), snapshot.size(), seed.data(),
	    recipient.data(), program_id.data(), token_amount, fee, expiry_height,
	    memo.empty() ? nullptr : memo.data(), memo.size(), circuit_k, &ptr, &len);
	if (rc != 1 || ptr == nullptr || len == 0) {
		if (ptr != nullptr)
			onyx_free(ptr, len);
		return false;
	}
	try {
		transaction->assign(ptr, ptr + len);
	} catch (...) {
		onyx_free(ptr, len);
		throw;
	}
	onyx_free(ptr, len);
	return true;
}

bool Halo2ProofSystem::toy_prove(
    uint64_t a, uint64_t b, BinaryArray *proof, BinaryArray *vk, std::array<uint8_t, 32> *public_out) {
	uint8_t *proof_ptr = nullptr;
	uint8_t *vk_ptr    = nullptr;
	size_t proof_len   = 0;
	size_t vk_len      = 0;
	uint8_t public_buf[32];
	if (onyx_toy_prove(a, b, &proof_ptr, &proof_len, &vk_ptr, &vk_len, public_buf) != 0)
		return false;
	proof->assign(proof_ptr, proof_ptr + proof_len);
	vk->assign(vk_ptr, vk_ptr + vk_len);
	std::copy(public_buf, public_buf + 32, public_out->begin());
	onyx_free(proof_ptr, proof_len);
	onyx_free(vk_ptr, vk_len);
	return true;
}

}  // namespace zk
}  // namespace cn
