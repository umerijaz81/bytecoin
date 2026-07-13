// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "types.hpp"
#include "common/Nocopy.hpp"

struct randomx_cache;
struct randomx_vm;

namespace crypto {

class RandomXContext : private common::Nocopy {
public:
	RandomXContext() = default;
	~RandomXContext();
	Hash hash(const Hash &seed, const void *data, size_t size);

private:
	randomx_cache *m_cache = nullptr;
	randomx_vm *m_vm       = nullptr;
	Hash m_seed{};
	bool m_initialized = false;
};

}  // namespace crypto
