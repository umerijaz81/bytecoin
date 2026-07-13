// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Halo2ProofSystem.hpp"
#include <algorithm>
#include <utility>
#include "onyx_zk.h"  // vendored C ABI (vendor/onyx-zk/include), on the include path when ONYX_ZK=ON

namespace cn {
namespace zk {

const char *Halo2ProofSystem::backend_id() const { return onyx_backend_id(); }

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

bool Halo2ProofSystem::verify_apply_bridge(const BinaryArray &snapshot, uint64_t anchor_window_blocks,
    const BinaryArray &encoded, uint32_t circuit_k, const std::array<uint8_t, 16> &expected_network,
    uint64_t block_height, BinaryArray *next_snapshot, VerifiedBridgeDelta *delta) {
	if (encoded.empty() || next_snapshot == nullptr || delta == nullptr)
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
	if (encoded.empty() || delta == nullptr)
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
    const std::array<uint8_t, 16> &network, uint8_t envelope_type, const BinaryArray &encoded,
    BinaryArray *next_snapshot, WalletScanResult *result) {
	if (encoded.empty() || next_snapshot == nullptr || result == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(), seed.data(),
	    network.data(), envelope_type, encoded.data(), encoded.size(), &next_ptr, &next_len, &scanned.balance,
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
    uint8_t envelope_type, const BinaryArray &encoded, BinaryArray *next_snapshot, WalletScanResult *result) {
	if (viewing_key.size() != 177 || encoded.empty() || next_snapshot == nullptr || result == nullptr)
		return false;
	uint8_t *next_ptr = nullptr;
	size_t next_len = 0;
	WalletScanResult scanned;
	const int rc = onyx_wallet_scan_viewing(snapshot.empty() ? nullptr : snapshot.data(), snapshot.size(),
	    viewing_key.data(), viewing_key.size(), envelope_type, encoded.data(), encoded.size(), &next_ptr,
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

bool Halo2ProofSystem::wallet_create_bridge(const std::array<uint8_t, 32> &seed,
    const std::array<uint8_t, 91> &recipient, uint64_t expiry_height, uint64_t fee,
    uint64_t legacy_amount, uint64_t legacy_stack_index,
    const std::array<uint8_t, 32> &legacy_key_image, const BinaryArray &memo, uint32_t circuit_k,
    BinaryArray *unsigned_bridge, std::array<uint8_t, 32> *ownership_sighash) {
	if (unsigned_bridge == nullptr || ownership_sighash == nullptr)
		return false;
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
	if (unsigned_bridge.empty() || finalized_bridge == nullptr)
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
