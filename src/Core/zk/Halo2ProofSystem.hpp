// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.
//
// Onyx (V6) — C++ adapter over the vendored Halo2/PLONKish (Pasta) backend (vendor/onyx-zk).
// Compiled only when the build is configured with -DONYX_ZK=ON. See ONYX_ARCHITECTURE.md / O0 plan.

#pragma once

#include <array>
#include <cstdint>
#include "IProofSystem.hpp"

namespace cn {
namespace zk {

// IProofSystem backed by the vendored Halo2 C ABI (include/onyx_zk.h).
//
// O0 scope: backend identity, the Orchard Poseidon/Sinsemilla primitives, and the toy prove/verify
// pipeline used to validate the FFI end-to-end. The protocol's real program-verifying-key dispatch
// lands in O4; until then verify() targets the toy circuit.
class Halo2ProofSystem : public IProofSystem {
public:
	const char *backend_id() const override;

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
};

}  // namespace zk
}  // namespace cn
