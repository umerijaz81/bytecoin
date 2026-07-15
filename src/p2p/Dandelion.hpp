// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace cn { namespace p2p {

struct DandelionPolicy {
	enum : int { MIN_PEER_SCORE = -8, MAX_PEER_SCORE = 8 };

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

	static int update_peer_score(int score, int delta) {
		return std::max<int>(MIN_PEER_SCORE, std::min<int>(MAX_PEER_SCORE, score + delta));
	}

	static bool accept_fluff_reflection(bool from_selected_stem_peer) {
		return !from_selected_stem_peer;
	}

	static int decay_peer_score(int score) {
		if (score > 0)
			return score - 1;
		if (score < 0)
			return score + 1;
		return 0;
	}

	static uint32_t peer_weight(int score) {
		const int bounded = std::max<int>(MIN_PEER_SCORE, std::min<int>(MAX_PEER_SCORE, score));
		return static_cast<uint32_t>(bounded - MIN_PEER_SCORE + 1);  // 1..17, never exclusion.
	}

	static size_t select_weighted_peer(const std::vector<int> &scores, uint64_t draw) {
		if (scores.empty())
			return 0;
		uint64_t total = 0;
		for (int score : scores)
			total += peer_weight(score);
		uint64_t selected = draw % total;
		for (size_t index = 0; index != scores.size(); ++index) {
			const uint32_t weight = peer_weight(scores[index]);
			if (selected < weight)
				return index;
			selected -= weight;
		}
		return scores.size() - 1;
	}
};

}}  // namespace cn::p2p
