// Copyright (c) 2012-2018, The Bytecoin developers
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace cn {

// A non-blocking process-local admission bound for expensive mempool proof verification. It is not
// consensus state: callers applying blocks or restoring transactions after a reorg bypass it.
class OnyxVerifierAdmission {
public:
	struct Stats {
		size_t active = 0;
		size_t peak_active = 0;
		uint64_t acquired = 0;
		uint64_t rejected_global = 0;
		uint64_t rejected_source = 0;
	};

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
		if (m_active >= m_global_limit) {
			++m_rejected_global;
			return nullptr;
		}
		if (source_active >= m_per_source_limit) {
			++m_rejected_source;
			return nullptr;
		}
		++m_active;
		++m_active_by_source[source];
		++m_acquired;
		m_peak_active = std::max(m_peak_active, m_active);
		return std::unique_ptr<Permit>(new Permit(*this, source));
	}

	Stats stats() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return Stats{m_active, m_peak_active, m_acquired, m_rejected_global, m_rejected_source};
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
	size_t m_peak_active = 0;
	uint64_t m_acquired = 0;
	uint64_t m_rejected_global = 0;
	uint64_t m_rejected_source = 0;
	std::unordered_map<std::string, size_t> m_active_by_source;
};

// A bounded non-consensus cooldown for proof-verifier overload. Expired entries are removed lazily;
// when full, the entry expiring soonest is evicted so attacker-selected transaction ids cannot grow
// memory without bound.
template<typename Key> class BoundedRetryCooldown {
public:
	using Clock = std::chrono::steady_clock;
	using TimePoint = Clock::time_point;

	BoundedRetryCooldown(size_t max_entries, Clock::duration cooldown)
	    : m_max_entries(max_entries), m_cooldown(cooldown) {}

	void defer(const Key &key, TimePoint now = Clock::now()) {
		std::lock_guard<std::mutex> lock(m_mutex);
		prune(now);
		if (m_max_entries == 0 || m_cooldown <= Clock::duration::zero())
			return;
		auto found = m_entries.find(key);
		if (found != m_entries.end()) {
			found->second = now + m_cooldown;
			return;
		}
		if (m_entries.size() >= m_max_entries) {
			auto earliest = std::min_element(m_entries.begin(), m_entries.end(),
			    [](const auto &left, const auto &right) { return left.second < right.second; });
			m_entries.erase(earliest);
		}
		m_entries.emplace(key, now + m_cooldown);
	}

	bool is_deferred(const Key &key, TimePoint now = Clock::now()) {
		std::lock_guard<std::mutex> lock(m_mutex);
		auto found = m_entries.find(key);
		if (found == m_entries.end())
			return false;
		if (found->second <= now) {
			m_entries.erase(found);
			return false;
		}
		return true;
	}

	size_t size(TimePoint now = Clock::now()) const {
		std::lock_guard<std::mutex> lock(m_mutex);
		prune(now);
		return m_entries.size();
	}

private:
	void prune(TimePoint now) const {
		for (auto it = m_entries.begin(); it != m_entries.end();) {
			if (it->second <= now)
				it = m_entries.erase(it);
			else
				++it;
		}
	}

	const size_t m_max_entries;
	const Clock::duration m_cooldown;
	mutable std::mutex m_mutex;
	mutable std::map<Key, TimePoint> m_entries;
};

inline size_t bounded_transaction_download_admission(size_t candidates, size_t peer_active,
    size_t global_active, size_t peer_limit, size_t global_limit) {
	const size_t peer_available = peer_active >= peer_limit ? 0 : peer_limit - peer_active;
	const size_t global_available = global_active >= global_limit ? 0 : global_limit - global_active;
	return std::min(candidates, std::min(peer_available, global_available));
}

}  // namespace cn
