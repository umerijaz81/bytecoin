// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Halo2ProofSystem.hpp"
#include <algorithm>
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
