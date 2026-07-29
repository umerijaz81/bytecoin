// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <cstddef>

namespace cn { namespace p2p {

struct AnonymityReferralPolicy {
	static constexpr size_t MAX_REFERRALS_PER_SOURCE = 16;
	static constexpr size_t MAX_CONSECUTIVE_FAILURES = 8;

	static bool can_accept(size_t current_count) { return current_count < MAX_REFERRALS_PER_SOURCE; }
	static bool should_ban(size_t consecutive_failures) {
		return consecutive_failures >= MAX_CONSECUTIVE_FAILURES;
	}
};

}}  // namespace cn::p2p
