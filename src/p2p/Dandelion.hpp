// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>

namespace cn { namespace p2p {

struct DandelionPolicy {
	static bool should_fluff(
	    bool enabled, uint8_t hop, uint8_t max_hops, uint8_t probability_percent, uint32_t draw) {
		return !enabled || hop >= max_hops || draw % 100 < std::min<uint8_t>(probability_percent, 100);
	}

	static uint64_t embargo_seconds(uint64_t first, uint64_t second, uint64_t draw) {
		const uint64_t minimum = std::min(first, second);
		const uint64_t maximum = std::max(first, second);
		if (minimum == 0 && maximum == std::numeric_limits<uint64_t>::max())
			return draw;
		const uint64_t range = maximum - minimum + 1;
		return minimum + draw % range;
	}
};

}}  // namespace cn::p2p
