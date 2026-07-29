// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.
//
// Active Onyx O0 proof-backend seam. This header and Halo2ProofSystem are part of the ONYX_ZK CMake
// source set. The generic interface is exercised by backend ABI tests; consensus envelope validation
// uses Halo2ProofSystem's typed, fail-closed transition methods so callers cannot confuse public
// statement shapes. A future backend requires a versioned consensus change and matching typed
// adapters; selecting one is never an automatic runtime downgrade.
//
// No consensus-critical cryptography is implemented here. Backends remain vendored, pinned, tested,
// and independently audited before any activation height can be set.

#pragma once

#include <cstddef>
#include <cstdint>
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
	BinaryArray data;  // Backend-specific encoding, such as a serialized Halo2/Pasta verifying key.
};

// One unit of generic backend work. Consensus callers use typed envelope methods instead.
struct ProofVerifyArgs {
	ProgramId program;
	BinaryArray proof;
	BinaryArray public_inputs;
};

class IProofSystem {
public:
	virtual ~IProofSystem() = default;

	// Human-readable, version-bound backend identity.
	virtual const char *backend_id() const = 0;

	// Returns true only when the proof is valid for the supplied key and canonical public statement.
	virtual bool verify(const VerifyingKey &vk, const ProofVerifyArgs &args) const = 0;

	// Returns one result per item. Shape mismatch fails the complete batch closed, and null key slots
	// fail their corresponding items without dereferencing them.
	virtual std::vector<bool> verify_batch(
	    const std::vector<const VerifyingKey *> &vks, const std::vector<ProofVerifyArgs> &items) const {
		if (vks.size() != items.size())
			return std::vector<bool>(items.size(), false);
		std::vector<bool> out;
		out.reserve(items.size());
		for (size_t i = 0; i < items.size(); ++i)
			out.push_back(vks[i] != nullptr && verify(*vks[i], items[i]));
		return out;
	}
};

}  // namespace zk
}  // namespace cn
