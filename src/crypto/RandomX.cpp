// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "RandomX.hpp"
#include <algorithm>
#include <stdexcept>
#include <thread>
#include <vector>
#include "randomx.h"

namespace crypto {

RandomXDataset::RandomXDataset(const Hash &seed, size_t initialization_threads, bool large_pages)
    : m_seed(seed) {
	if (initialization_threads == 0)
		throw std::invalid_argument("RandomX dataset initialization requires at least one thread");
	randomx_flags flags = randomx_get_flags();
	flags |= static_cast<randomx_flags>(RANDOMX_FLAG_V2 | RANDOMX_FLAG_FULL_MEM);
	if (flags & RANDOMX_FLAG_JIT)
		flags |= RANDOMX_FLAG_SECURE;
	if (large_pages)
		flags |= RANDOMX_FLAG_LARGE_PAGES;
	m_flags = static_cast<int>(flags);

	randomx_cache *cache = randomx_alloc_cache(flags);
	if (cache == nullptr)
		throw std::runtime_error(large_pages ? "RandomX large-page cache allocation failed" :
		                                       "RandomX full-memory cache allocation failed");
	randomx_init_cache(cache, seed.data, sizeof(seed.data));
	m_dataset = randomx_alloc_dataset(flags);
	if (m_dataset == nullptr) {
		randomx_release_cache(cache);
		throw std::runtime_error(large_pages ? "RandomX large-page dataset allocation failed" :
		                                       "RandomX dataset allocation failed");
	}

	const uint32_t items = randomx_dataset_item_count();
	const size_t thread_count = std::min<size_t>(initialization_threads, items);
	std::vector<std::thread> workers;
	try {
		workers.reserve(thread_count);
		uint32_t start = 0;
		for (size_t i = 0; i != thread_count; ++i) {
			const uint32_t count = items / static_cast<uint32_t>(thread_count) +
			                       (i + 1 == thread_count ? items % static_cast<uint32_t>(thread_count) : 0);
			workers.emplace_back(randomx_init_dataset, m_dataset, cache, start, count);
			start += count;
		}
		for (auto &worker : workers)
			worker.join();
	} catch (...) {
		for (auto &worker : workers)
			if (worker.joinable())
				worker.join();
		randomx_release_dataset(m_dataset);
		m_dataset = nullptr;
		randomx_release_cache(cache);
		throw;
	}
	randomx_release_cache(cache);
}

RandomXDataset::~RandomXDataset() {
	if (m_dataset != nullptr)
		randomx_release_dataset(m_dataset);
}

randomx_vm *RandomXDataset::create_vm() const {
	const randomx_flags flags = static_cast<randomx_flags>(m_flags);
	randomx_vm *vm = randomx_create_vm(flags, nullptr, m_dataset);
	if (vm == nullptr) {
		randomx_flags fallback = static_cast<randomx_flags>(RANDOMX_FLAG_V2 | RANDOMX_FLAG_FULL_MEM);
		if (flags & RANDOMX_FLAG_LARGE_PAGES)
			fallback |= RANDOMX_FLAG_LARGE_PAGES;
		vm = randomx_create_vm(fallback, nullptr, m_dataset);
	}
	if (vm == nullptr)
		throw std::runtime_error("RandomX full-memory virtual machine allocation failed");
	return vm;
}

RandomXContext::RandomXContext(std::shared_ptr<const RandomXDataset> dataset) : m_dataset(std::move(dataset)) {
	if (!m_dataset)
		throw std::invalid_argument("RandomX dataset context requires a dataset");
}

RandomXContext::~RandomXContext() {
	if (m_vm != nullptr)
		randomx_destroy_vm(m_vm);
	if (m_cache != nullptr)
		randomx_release_cache(m_cache);
}

Hash RandomXContext::hash(const Hash &seed, const void *data, size_t size) {
	if (m_dataset) {
		if (seed != m_dataset->seed())
			throw std::invalid_argument("RandomX full-memory dataset seed mismatch");
		if (m_vm == nullptr)
			m_vm = m_dataset->create_vm();
		Hash result;
		randomx_calculate_hash(m_vm, data, size, result.data);
		return result;
	}
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
