// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <limits>
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"

namespace cn {

struct OnyxConstructionWindow {
	Height inclusion_height = 0;
	Height expiry_height    = 0;
};

inline bool resolve_onyx_construction_window(
    Height tip_height, Height requested_expiry, OnyxConstructionWindow *window) {
	if (window == nullptr || tip_height == std::numeric_limits<Height>::max())
		return false;
	const Height inclusion = tip_height + 1;
	Height expiry          = requested_expiry;
	if (expiry == 0) {
		constexpr Height default_distance = 19;  // Preserve the historical tip + 20 default.
		if (inclusion > std::numeric_limits<Height>::max() - default_distance)
			return false;
		expiry = inclusion + default_distance;
	}
	if (expiry < inclusion || expiry - inclusion > parameters::ONYX_MAX_EXPIRY_DISTANCE)
		return false;
	window->inclusion_height = inclusion;
	window->expiry_height    = expiry;
	return true;
}

}  // namespace cn
