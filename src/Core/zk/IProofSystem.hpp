// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.
//
// DESIGN STUB (Onyx / V6) — see ONYX_ARCHITECTURE.md.
//
// This header fixes the seam between the consensus state machine and the zero-knowledge proof
// backend. It is intentionally NOT added to CMakeLists yet (header-only design anchor, cannot break
// the build). Phase O0 vendors a peer-reviewed Halo2/PLONKish backend implementing IProofSystem;
// a STARK/post-quantum backend can later be added behind the same interface without touching the
// state machine (the concrete continuation of audit finding Q-1: quantum-agility).
//
// NOTHING here is consensus-critical crypto written by hand. Implementations are vendored and
// audited before any mainnet activation height is set.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include "common/BinaryArray.hpp"

namespace cn {
namespace zk {

using common::BinaryArray;

// Identifies a registered program circuit (a key into the on-chain verifying-key registry).
struct ProgramId {
	uint8_t bytes[32]{};
};

// A verifying key for one program function, as published in the program registry.
struct VerifyingKey {
	BinaryArray data;  // backend-specific encoding (e.g. serialized Halo2 VK over Pasta)
};

// One unit of work for the batch verifier: a proof, the public inputs it is checked against
// (anchor root, value-balance commitments, nullifiers, output commitments, program id...), and the
// verifying key to use. Mirrors how RingCheckArgs feed the existing Multicore batch path, so the
// proof batch re-targets that infrastructure rather than introducing a new threading model.
struct ProofVerifyArgs {
	ProgramId program;
	BinaryArray proof;
	BinaryArray public_inputs;  // canonical serialization of the bundle's public statement
};

// Abstract proof backend. A single instance is shared by block validation and the mempool; verify()
// must be thread-safe for the batched/parallel path.
class IProofSystem {
public:
	virtual ~IProofSystem() = default;

	// Human-readable backend identity, e.g. "halo2-ipa-pasta" or "stark-poseidon". Recorded so the
	// node can refuse proofs from an unexpected/unsupported backend version.
	virtual const char *backend_id() const = 0;

	// Verify a single statement. Returns true iff the proof is valid for (verifying key, public
	// inputs). Must not throw on a merely-invalid proof — return false — reserving exceptions for
	// malformed encodings.
	virtual bool verify(const VerifyingKey &vk, const ProofVerifyArgs &args) const = 0;

	// Verify a batch; an implementation may amortize work across proofs. Returns one bool per item,
	// in order. Default implementation defers to verify().
	virtual std::vector<bool> verify_batch(
	    const std::vector<const VerifyingKey *> &vks, const std::vector<ProofVerifyArgs> &items) const {
		std::vector<bool> out;
		out.reserve(items.size());
		for (size_t i = 0; i < items.size(); ++i)
			out.push_back(verify(*vks.at(i), items.at(i)));
		return out;
	}
};

// Phase O0 provides a factory returning the vendored backend selected at build/config time.
// std::unique_ptr<IProofSystem> make_proof_system(const std::string &backend_id);

}  // namespace zk
}  // namespace cn
