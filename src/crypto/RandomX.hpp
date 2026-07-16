// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <memory>
#include "types.hpp"
#include "common/Nocopy.hpp"

struct randomx_cache;
struct randomx_dataset;
struct randomx_vm;

namespace crypto {

class RandomXDataset : private common::Nocopy {
public:
	RandomXDataset(const Hash &seed, size_t initialization_threads, bool large_pages);
	~RandomXDataset();
	const Hash &seed() const { return m_seed; }

private:
	friend class RandomXContext;
	randomx_vm *create_vm() const;
	randomx_dataset *m_dataset = nullptr;
	Hash m_seed{};
	int m_flags = 0;
};

class RandomXContext : private common::Nocopy {
public:
	RandomXContext() = default;
	explicit RandomXContext(std::shared_ptr<const RandomXDataset> dataset);
	~RandomXContext();
	Hash hash(const Hash &seed, const void *data, size_t size);

private:
	randomx_cache *m_cache = nullptr;
	randomx_vm *m_vm       = nullptr;
	Hash m_seed{};
	bool m_initialized = false;
	std::shared_ptr<const RandomXDataset> m_dataset;
};

}  // namespace crypto
