// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "RandomX.hpp"
#include <stdexcept>
#include "randomx.h"

namespace crypto {

RandomXContext::~RandomXContext() {
	if (m_vm != nullptr)
		randomx_destroy_vm(m_vm);
	if (m_cache != nullptr)
		randomx_release_cache(m_cache);
}

Hash RandomXContext::hash(const Hash &seed, const void *data, size_t size) {
	if (m_cache == nullptr) {
		const randomx_flags available = randomx_get_flags();
		const randomx_flags cache_flags = static_cast<randomx_flags>(available &
		    static_cast<randomx_flags>(RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2));
		m_cache = randomx_alloc_cache(cache_flags);
		if (m_cache == nullptr)
			throw std::runtime_error("RandomX cache allocation failed");
	}
	if (!m_initialized || seed != m_seed) {
		randomx_init_cache(m_cache, seed.data, sizeof(seed.data));
		m_seed        = seed;
		m_initialized = true;
		if (m_vm != nullptr)
			randomx_vm_set_cache(m_vm, m_cache);
	}
	if (m_vm == nullptr) {
		const randomx_flags available = randomx_get_flags();
		randomx_flags flags = static_cast<randomx_flags>(available &
		    static_cast<randomx_flags>(RANDOMX_FLAG_HARD_AES | RANDOMX_FLAG_JIT));
		flags |= RANDOMX_FLAG_V2;
		if (flags & RANDOMX_FLAG_JIT)
			flags |= RANDOMX_FLAG_SECURE;
		m_vm = randomx_create_vm(flags, m_cache, nullptr);
		if (m_vm == nullptr && flags != RANDOMX_FLAG_V2)
			m_vm = randomx_create_vm(RANDOMX_FLAG_V2, m_cache, nullptr);
		if (m_vm == nullptr)
			throw std::runtime_error("RandomX virtual machine allocation failed");
	}
	Hash result;
	randomx_calculate_hash(m_vm, data, size, result.data);
	return result;
}

}  // namespace crypto
