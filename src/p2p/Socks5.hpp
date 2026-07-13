// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stdexcept>
#include "common/BinaryArray.hpp"
#include "common/Ipv4Address.hpp"

namespace cn { namespace p2p {

struct Socks5 {
	static common::BinaryArray greeting() { return {5, 1, 0}; }

	static common::BinaryArray connect_ipv4(const common::NetworkAddress &target) {
		if (target.ip.size() != 4 || target.port == 0)
			throw std::runtime_error("SOCKS5 target must be an IPv4 address with a nonzero port");
		common::BinaryArray result{5, 1, 0, 1};
		result.insert(result.end(), target.ip.begin(), target.ip.end());
		result.push_back(static_cast<uint8_t>(target.port >> 8));
		result.push_back(static_cast<uint8_t>(target.port));
		return result;
	}

	static void validate_method(const common::BinaryArray &reply) {
		if (reply.size() != 2 || reply[0] != 5 || reply[1] != 0)
			throw std::runtime_error("SOCKS5 proxy rejected no-authentication method");
	}

	static size_t connect_reply_size(const common::BinaryArray &reply) {
		if (reply.size() < 4)
			return 4;
		if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0)
			throw std::runtime_error("SOCKS5 proxy rejected connection");
		if (reply[3] == 1)
			return 10;
		if (reply[3] == 4)
			return 22;
		if (reply[3] == 3)
			return reply.size() < 5 ? 5 : static_cast<size_t>(7) + reply[4];
		throw std::runtime_error("SOCKS5 proxy returned an unknown address type");
	}

	static void validate_connect_reply(const common::BinaryArray &reply) {
		const size_t expected = connect_reply_size(reply);
		if (reply.size() != expected)
			throw std::runtime_error("SOCKS5 proxy returned a truncated connection reply");
	}
};

}}  // namespace cn::p2p
