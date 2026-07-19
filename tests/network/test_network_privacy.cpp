// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "common/StringTools.hpp"
#include "p2p/Dandelion.hpp"
#include "p2p/Socks5.hpp"

namespace {

void require(bool value, const char *message) {
	if (!value)
		throw std::runtime_error(message);
}

template<class Function>
void require_rejected(Function function, const char *message) {
	try {
		function();
	} catch (const std::runtime_error &) {
		return;
	}
	throw std::runtime_error(message);
}

void test_dandelion_policy() {
	require(common::constant_time_equal("user:secret", "user:secret"), "constant-time equality rejected equal input");
	require(!common::constant_time_equal("user:secret", "user:secreu"), "constant-time equality accepted mismatch");
	require(!common::constant_time_equal("user:secret", "user:secret-long"), "constant-time equality accepted length mismatch");
	using cn::p2p::DandelionPolicy;
	require(DandelionPolicy::should_fluff(false, 0, 20, 10, 99), "disabled relay did not fluff");
	require(DandelionPolicy::should_fluff(true, 20, 20, 0, 99), "hop limit did not fluff");
	require(DandelionPolicy::should_fluff(true, 1, 20, 10, 9), "probability lower bound changed");
	require(!DandelionPolicy::should_fluff(true, 1, 20, 10, 10), "probability upper bound changed");
	require(DandelionPolicy::embargo_seconds(30, 10, 0) == 10, "embargo lower bound changed");
	require(DandelionPolicy::embargo_seconds(30, 10, 20) == 30, "embargo upper bound changed");

	require(DandelionPolicy::update_peer_score(8, 1) == 8, "positive score escaped bound");
	require(DandelionPolicy::update_peer_score(-8, -2) == -8, "negative score escaped bound");
	require(DandelionPolicy::decay_peer_score(3) == 2, "positive score did not decay");
	require(DandelionPolicy::decay_peer_score(-3) == -2, "negative score did not decay");
	require(!DandelionPolicy::accept_fluff_reflection(true),
	    "selected peer could cancel its own embargo");
	require(DandelionPolicy::accept_fluff_reflection(false),
	    "third-party fluff did not cancel the embargo");
	require(DandelionPolicy::peer_weight(-100) == 1, "degraded peer was excluded");
	require(DandelionPolicy::peer_weight(100) == 17, "peer weight escaped bound");

	// Deterministic adversarial topology: a failing peer remains selectable but receives 17x less
	// traffic than a peer whose stems repeatedly reappear as fluff. Neutral peers remain in between.
	const std::vector<int> scores{-8, 0, 8};
	std::array<size_t, 3> selected{{0, 0, 0}};
	for (uint64_t draw = 0; draw != 2700; ++draw)
		++selected.at(DandelionPolicy::select_weighted_peer(scores, draw));
	require(selected[0] == 100 && selected[1] == 900 && selected[2] == 1700,
	    "weighted topology distribution changed");
	require(DandelionPolicy::select_weighted_peer(std::vector<int>{}, 42) == 0,
	    "empty topology sentinel changed");
}

void test_dandelion_adversarial_campaign() {
	using cn::p2p::DandelionPolicy;
	const size_t peer_count = 64;
	const size_t adversarial_count = 16;
	std::vector<int> scores(peer_count, 0);
	std::vector<size_t> selections(peer_count, 0);
	uint64_t state = 0xbb67ae8584caa73bULL;
	size_t reflected = 0;
	size_t recovered = 0;
	for (size_t transaction = 0; transaction != 20000; ++transaction) {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		const size_t selected = DandelionPolicy::select_weighted_peer(scores, state);
		require(selected < peer_count, "campaign selected a nonexistent stem peer");
		++selections[selected];
		if (selected < adversarial_count) {
			// A selected observer reflects its own fluff immediately. That reflection must not cancel
			// pending state; disconnect/embargo recovery then diffuses the transaction and penalizes it.
			require(!DandelionPolicy::accept_fluff_reflection(true),
			    "adversarial self-reflection cancelled pending stem state");
			scores[selected] = DandelionPolicy::update_peer_score(scores[selected], -2);
			++recovered;
		} else {
			require(DandelionPolicy::accept_fluff_reflection(false),
			    "independent fluff did not complete an honest stem");
			scores[selected] = DandelionPolicy::update_peer_score(scores[selected], 1);
			++reflected;
		}
		if (transaction % 64 == 63)
			for (int &score : scores)
				score = DandelionPolicy::decay_peer_score(score);
		// Model a connection identity disappearing. New connections start neutral and cannot inherit
		// permanent reputation from the old socket identity.
		if (transaction % 257 == 256)
			scores[(state >> 32) % peer_count] = 0;
		for (int score : scores)
			require(score >= DandelionPolicy::MIN_PEER_SCORE &&
			            score <= DandelionPolicy::MAX_PEER_SCORE,
			    "campaign peer score escaped its bounds");
	}
	require(reflected + recovered == 20000, "campaign lost a pending transaction");
	size_t adversarial_selections = 0;
	size_t honest_selections = 0;
	for (size_t peer = 0; peer != peer_count; ++peer) {
		require(selections[peer] != 0, "weighted campaign permanently excluded a live peer");
		if (peer < adversarial_count)
			adversarial_selections += selections[peer];
		else
			honest_selections += selections[peer];
	}
	// Compare per-peer rates: repeatedly failing peers remain reachable but should carry less than
	// half the average honest peer's stem load. Score decay and connection replacement deliberately
	// restore neutral eligibility, so this is a delivery preference rather than permanent exclusion.
	require(honest_selections * adversarial_count > adversarial_selections *
	            (peer_count - adversarial_count) * 2,
	    "delivery scoring did not sufficiently reduce repeated adversarial selection");
}

void test_socks5_policy() {
	using cn::p2p::Socks5;
	require(Socks5::greeting() == common::BinaryArray({5, 1, 0}), "SOCKS5 greeting changed");
	common::NetworkAddress target;
	target.ip = {127, 0, 0, 1};
	target.port = 8080;
	require(Socks5::connect_ipv4(target) == common::BinaryArray({5, 1, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}),
	    "SOCKS5 IPv4 request changed");
	const std::string onion_host = std::string(56, 'a') + ".onion";
	const std::string i2p_host = std::string(52, '2') + ".b32.i2p";
	require(Socks5::is_anonymity_domain(onion_host) && Socks5::is_anonymity_domain(i2p_host),
	    "canonical anonymity domain was rejected");
	const common::BinaryArray onion_request = Socks5::connect_anonymity_domain(onion_host, 18080);
	require(onion_request.size() == 7 + onion_host.size() && onion_request[0] == 5 &&
	        onion_request[3] == 3 && onion_request[4] == onion_host.size() &&
	        onion_request[onion_request.size() - 2] == 0x46 && onion_request.back() == 0xa0,
	    "SOCKS5 anonymity-domain request changed");
	common::NetworkAddress onion_target;
	onion_target.host = onion_host;
	onion_target.port = 18080;
	require(Socks5::is_anonymity_target(onion_target), "canonical anonymity target was rejected");
	require(Socks5::connect_target(onion_target) == onion_request,
	    "generic SOCKS5 target did not preserve anonymity-domain framing");
	require_rejected([&onion_target] {
		auto ambiguous = onion_target;
		ambiguous.ip = {127, 0, 0, 1};
		Socks5::connect_target(ambiguous);
	}, "ambiguous numeric/anonymity target was accepted");
	require_rejected([] { Socks5::connect_anonymity_domain("example.com", 80); },
	    "clearnet domain was accepted by anonymity-only framing");
	require_rejected([] { Socks5::connect_anonymity_domain(std::string(56, 'A') + ".onion", 80); },
	    "non-canonical uppercase onion address was accepted");
	require_rejected([&onion_host] { Socks5::connect_anonymity_domain(onion_host, 0); },
	    "zero-port anonymity target was accepted");

	const common::BinaryArray ipv4_reply{5, 0, 0, 1, 127, 0, 0, 1, 0, 1};
	const common::BinaryArray domain_reply{5, 0, 0, 3, 3, 'o', 'k', '!', 0, 1};
	common::BinaryArray ipv6_reply{5, 0, 0, 4};
	ipv6_reply.resize(22, 0);
	require(Socks5::connect_reply_size(ipv4_reply) == 10, "SOCKS5 IPv4 reply size changed");
	require(Socks5::connect_reply_size(domain_reply) == 10, "SOCKS5 domain reply size changed");
	require(Socks5::connect_reply_size(ipv6_reply) == 22, "SOCKS5 IPv6 reply size changed");
	Socks5::validate_method(common::BinaryArray{5, 0});
	Socks5::validate_connect_reply(ipv4_reply);
	Socks5::validate_connect_reply(domain_reply);
	Socks5::validate_connect_reply(ipv6_reply);

	require_rejected([] { Socks5::validate_method(common::BinaryArray{5, 0xff}); },
	    "SOCKS5 authentication rejection was accepted");
	require_rejected([] { Socks5::connect_reply_size(common::BinaryArray{5, 5, 0, 1}); },
	    "SOCKS5 destination rejection was accepted");
	require_rejected([] { Socks5::validate_connect_reply(common::BinaryArray{5, 0, 0, 3, 4, 'x'}); },
	    "truncated SOCKS5 domain reply was accepted");
	require_rejected([] { Socks5::connect_reply_size(common::BinaryArray{5, 0, 0, 2}); },
	    "unknown SOCKS5 address type was accepted");
	require_rejected([&target] {
		auto invalid = target;
		invalid.port = 0;
		Socks5::connect_ipv4(invalid);
	}, "zero-port SOCKS5 target was accepted");
	require_rejected([&target] {
		auto invalid = target;
		invalid.ip.resize(16);
		Socks5::connect_ipv4(invalid);
	}, "non-IPv4 SOCKS5 target was accepted");
}

}  // namespace

int main() {
	try {
		test_dandelion_policy();
		test_dandelion_adversarial_campaign();
		test_socks5_policy();
		std::cout << "network privacy policy tests passed" << std::endl;
		return 0;
	} catch (const std::exception &error) {
		std::cerr << error.what() << std::endl;
		return 1;
	}
}
