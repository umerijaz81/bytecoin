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
