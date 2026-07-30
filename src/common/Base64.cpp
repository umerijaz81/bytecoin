// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "Base64.hpp"

#include <limits>
#include <utility>
#include <vector>

namespace common { namespace base64 {

static const char to_base64[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string encode(const BinaryArray &data) {
	std::string ret;
	const uint8_t *const buf = data.data();
	const size_t buf_len     = data.size();
	// Calculate how many bytes that needs to be added to get a multiple of 3
	size_t missing  = 0;
	size_t ret_size = buf_len;
	while ((ret_size % 3) != 0) {
		++ret_size;
		++missing;
	}

	// Expand the return string size to a multiple of 4
	ret_size = 4 * ret_size / 3;

	ret.reserve(ret_size);

	for (size_t i = 0; i < ret_size / 4; ++i) {
		// Read a group of three bytes (avoid buffer overrun by replacing with 0)
		const size_t index = i * 3;
		const uint8_t b3_0 = (index + 0 < buf_len) ? buf[index + 0] : uint8_t(0);
		const uint8_t b3_1 = (index + 1 < buf_len) ? buf[index + 1] : uint8_t(0);
		const uint8_t b3_2 = (index + 2 < buf_len) ? buf[index + 2] : uint8_t(0);

		// Transform into four base 64 characters
		const uint8_t b4_0 = ((b3_0 & 0xfc) >> 2);
		const uint8_t b4_1 = ((b3_0 & 0x03) << 4) + ((b3_1 & 0xf0) >> 4);
		const uint8_t b4_2 = ((b3_1 & 0x0f) << 2) + ((b3_2 & 0xc0) >> 6);
		const uint8_t b4_3 = ((b3_2 & 0x3f) << 0);

		// Add the base 64 characters to the return value
		ret.push_back(to_base64[b4_0]);
		ret.push_back(to_base64[b4_1]);
		ret.push_back(to_base64[b4_2]);
		ret.push_back(to_base64[b4_3]);
	}

	// Replace data that is invalid (always as many as there are missing bytes)
	for (size_t i = 0; i != missing; ++i)
		ret[ret_size - i - 1] = '=';
	return ret;
}

static bool decode_character(char character, uint8_t *value) {
	if (character >= 'A' && character <= 'Z')
		*value = static_cast<uint8_t>(character - 'A');
	else if (character >= 'a' && character <= 'z')
		*value = static_cast<uint8_t>(character - 'a' + 26);
	else if (character >= '0' && character <= '9')
		*value = static_cast<uint8_t>(character - '0' + 52);
	else if (character == '+')
		*value = 62;
	else if (character == '/')
		*value = 63;
	else
		return false;
	return true;
}

bool decode(const std::string &in, BinaryArray *ret) {
	if (ret == nullptr)
		return false;
	ret->clear();
	if (in.empty())
		return true;
	if (in.size() % 4 != 0 || in.size() / 4 > std::numeric_limits<size_t>::max() / 3)
		return false;
	BinaryArray decoded;
	decoded.reserve(3 * (in.size() / 4));
	for (size_t i = 0; i != in.size(); i += 4) {
		const bool final_group = i + 4 == in.size();
		const bool pad2 = in[i + 2] == '=';
		const bool pad3 = in[i + 3] == '=';
		if (!final_group && (pad2 || pad3))
			return false;
		if (pad2 && !pad3)
			return false;
		uint8_t b0 = 0;
		uint8_t b1 = 0;
		uint8_t b2 = 0;
		uint8_t b3 = 0;
		if (!decode_character(in[i], &b0) || !decode_character(in[i + 1], &b1) ||
		    (!pad2 && !decode_character(in[i + 2], &b2)) ||
		    (!pad3 && !decode_character(in[i + 3], &b3)))
			return false;
		if ((pad2 && (b1 & 0x0f) != 0) || (!pad2 && pad3 && (b2 & 0x03) != 0))
			return false;  // Reject noncanonical unused trailing bits.
		decoded.push_back(static_cast<uint8_t>((b0 << 2) | (b1 >> 4)));
		if (!pad2)
			decoded.push_back(static_cast<uint8_t>((b1 << 4) | (b2 >> 2)));
		if (!pad3)
			decoded.push_back(static_cast<uint8_t>((b2 << 6) | b3));
	}
	*ret = std::move(decoded);
	return true;
}
}}  // namespace common::base64
