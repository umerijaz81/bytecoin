// Copyright (c) 2012-2018, The Bytecoin developers
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace cn {

// A non-blocking process-local admission bound for expensive mempool proof verification. It is not
// consensus state: callers applying blocks or restoring transactions after a reorg bypass it.
class OnyxVerifierAdmission {
public:
	class Permit {
	public:
		~Permit() { m_owner.release(m_source); }

		Permit(const Permit &) = delete;
		Permit &operator=(const Permit &) = delete;

	private:
		friend class OnyxVerifierAdmission;
		Permit(OnyxVerifierAdmission &owner, std::string source)
		    : m_owner(owner), m_source(std::move(source)) {}

		OnyxVerifierAdmission &m_owner;
		std::string m_source;
	};

	OnyxVerifierAdmission(size_t global_limit, size_t per_source_limit)
	    : m_global_limit(global_limit), m_per_source_limit(per_source_limit) {}

	std::unique_ptr<Permit> try_acquire(const std::string &source) {
		if (source.empty() || m_global_limit == 0 || m_per_source_limit == 0)
			return nullptr;
		std::lock_guard<std::mutex> lock(m_mutex);
		const auto found = m_active_by_source.find(source);
		const size_t source_active = found == m_active_by_source.end() ? 0 : found->second;
		if (m_active >= m_global_limit || source_active >= m_per_source_limit)
			return nullptr;
		++m_active;
		++m_active_by_source[source];
		return std::unique_ptr<Permit>(new Permit(*this, source));
	}

	size_t active() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_active;
	}

private:
	void release(const std::string &source) {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto found = m_active_by_source.find(source);
		if (found == m_active_by_source.end() || found->second == 0 || m_active == 0)
			return;
		--m_active;
		if (--found->second == 0)
			m_active_by_source.erase(found);
	}

	const size_t m_global_limit;
	const size_t m_per_source_limit;
	mutable std::mutex m_mutex;
	size_t m_active = 0;
	std::unordered_map<std::string, size_t> m_active_by_source;
};

}  // namespace cn
