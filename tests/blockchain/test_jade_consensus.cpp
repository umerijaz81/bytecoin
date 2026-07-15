// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_jade_consensus.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include "Core/BlockChainState.hpp"
#include "Core/Config.hpp"
#include "Core/Currency.hpp"
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "common/Invariant.hpp"
#include "crypto/crypto.hpp"
#include "p2p/P2pProtocolDefinitions.hpp"
#include "p2p/Dandelion.hpp"
#include "p2p/Socks5.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "rpc_api.hpp"

using namespace cn;

// Minimal semantically-valid (under check_keys=false) 1-in/1-out transaction with the given
// transaction version and ring size (number of output indexes on the single input).
static Transaction build_tx(uint8_t version, size_t ring_size) {
	Transaction tx;
	tx.version = version;
	if (version == parameters::TRANSACTION_VERSION_JADE)
		tx.signature_scheme = static_cast<uint8_t>(TransactionSignatureScheme::AMETHYST_LINKABLE_RING);

	InputKey in;
	in.amount    = 1000;
	in.key_image = crypto::rand<KeyImage>();
	in.output_indexes.assign(ring_size, 1);  // relative offsets {0,1,1,...} -> absolute {0,1,2,...}
	if (ring_size > 0)
		in.output_indexes[0] = 0;
	tx.inputs.push_back(in);

	OutputKey out;
	out.amount     = 1000;  // must be non-zero; <= input so sum(out) <= sum(in)
	out.public_key = crypto::rand<PublicKey>();
	tx.outputs.push_back(out);

	return tx;
}

static bool semantic_rejects(const Currency &currency, uint8_t block_major_version, const Transaction &tx,
    std::string *what) {
	try {
		validate_tx_semantic(currency, block_major_version, /*coinbase=*/false, tx,
		    /*check_keys=*/false, /*key_image_subgroup_check=*/false);
		return false;
	} catch (const std::exception &e) {
		*what = e.what();
		return true;
	}
}

void test_jade_consensus(common::CommandLine &cmd) {
	Config config(cmd);
	Currency currency(config);
	const uint8_t jade = currency.jade_block_version;
	std::string what;

	// 1. Zero-mixin / undersized ring MUST be rejected under Jade (the loophole is closed).
	{
		const Transaction tx = build_tx(currency.jade_transaction_version, 1);
		const bool rejected  = semantic_rejects(currency, jade, tx, &what);
		invariant(rejected, "Jade consensus accepted a ring-size-1 transaction (loophole open!)");
		std::cout << "  [jade] ring size 1 rejected: " << what << std::endl;
	}

	// 2. A full ring (minimum_anonymity + 1 = 16) MUST be accepted.
	{
		const size_t good   = currency.minimum_anonymity(jade) + 1;
		const Transaction tx = build_tx(currency.jade_transaction_version, good);
		const bool rejected  = semantic_rejects(currency, jade, tx, &what);
		invariant(!rejected, "Jade consensus rejected a valid full ring: " + what);
		std::cout << "  [jade] ring size " << good << " accepted" << std::endl;
	}

	// 3. Pre-fork (Amethyst/V4) semantic validation MUST be unchanged: ring size 1 still passes
	//    the (stateless) semantic check, exactly as before this work.
	{
		const Transaction tx = build_tx(currency.amethyst_transaction_version, 1);
		const bool rejected  = semantic_rejects(currency, currency.amethyst_block_version, tx, &what);
		invariant(!rejected, "Amethyst semantic validation changed unexpectedly: " + what);
		std::cout << "  [amethyst] ring size 1 still semantically valid (unchanged)" << std::endl;
	}

	// 4. Jade blocks must not admit legacy non-coinbase transaction formats. Otherwise old
	// validation paths could bypass future Jade-only consensus rules.
	{
		const size_t good = currency.minimum_anonymity(jade) + 1;
		const Transaction tx = build_tx(currency.amethyst_transaction_version, good);
		const bool rejected = semantic_rejects(currency, jade, tx, &what);
		invariant(rejected, "Jade consensus accepted an Amethyst transaction");
		std::cout << "  [jade] legacy non-coinbase transaction rejected: " << what << std::endl;
	}

	// 5. Future/unknown transaction versions fail closed under Jade.
	{
		const size_t good = currency.minimum_anonymity(jade) + 1;
		const Transaction tx = build_tx(static_cast<uint8_t>(currency.jade_transaction_version + 1), good);
		const bool rejected = semantic_rejects(currency, jade, tx, &what);
		invariant(rejected, "Jade consensus accepted an unknown transaction version");
		std::cout << "  [jade] unknown transaction version rejected: " << what << std::endl;
	}

	// 6. Jade carries an explicit, prefix-bound authorization scheme. Inactive registered schemes
	//    and unregistered wire identifiers both fail closed, while Amethyst bytes remain unchanged.
	{
		const size_t good = currency.minimum_anonymity(jade) + 1;
		Transaction jade_tx = build_tx(currency.jade_transaction_version, good);
		const common::BinaryArray jade_prefix = seria::to_binary(static_cast<const TransactionPrefix &>(jade_tx));
		invariant(jade_prefix.size() > 1 && jade_prefix[1] ==
		        static_cast<uint8_t>(TransactionSignatureScheme::AMETHYST_LINKABLE_RING),
		    "Jade signature scheme is not encoded immediately after the transaction version");

		Transaction inactive = jade_tx;
		inactive.signature_scheme = static_cast<uint8_t>(TransactionSignatureScheme::RESERVED_HYBRID_PQ);
		invariant(get_transaction_prefix_hash(inactive) != get_transaction_prefix_hash(jade_tx),
		    "Jade signature scheme is not bound into the signed prefix");
		const bool inactive_rejected = semantic_rejects(currency, jade, inactive, &what);
		invariant(inactive_rejected, "Jade accepted an inactive registered signature scheme");
		bool inactive_wire_rejected = false;
		try {
			(void)seria::to_binary(inactive);
		} catch (const std::exception &) {
			inactive_wire_rejected = true;
		}
		invariant(inactive_wire_rejected, "Jade serialized signatures for an inactive registered scheme");

		Transaction unknown = jade_tx;
		unknown.signature_scheme = 0xff;
		bool unknown_rejected = false;
		try {
			(void)seria::to_binary(static_cast<const TransactionPrefix &>(unknown));
		} catch (const std::exception &) {
			unknown_rejected = true;
		}
		invariant(unknown_rejected, "Jade serialized an unregistered signature scheme");

		Transaction amethyst = build_tx(currency.amethyst_transaction_version, good);
		const common::BinaryArray amethyst_before = seria::to_binary(static_cast<const TransactionPrefix &>(amethyst));
		amethyst.signature_scheme = 0xff;  // Not a V4 wire field.
		const common::BinaryArray amethyst_after = seria::to_binary(static_cast<const TransactionPrefix &>(amethyst));
		invariant(amethyst_before == amethyst_after, "Jade scheme registry changed pre-Jade transaction bytes");
		TransactionPrefix empty_amethyst;
		empty_amethyst.version = parameters::TRANSACTION_VERSION_AMETHYST;
		invariant(seria::to_binary(empty_amethyst) == common::BinaryArray({0x04, 0x00, 0x00, 0x00, 0x00}),
		    "Amethyst V4 prefix compatibility vector changed");
		std::cout << "  [jade] explicit signature scheme is prefix-bound and fail-closed" << std::endl;
	}

	// 7. Onyx transaction V6 is a bounded opaque envelope and round-trips without invoking legacy
	// input/output/signature serialization. Block major version 6 remains skipped/reserved.
	{
		Transaction tx;
		tx.version = currency.onyx_transaction_version;
		tx.onyx_envelope = common::BinaryArray{0x06, 0x01, 0x02, 0x03};
		const common::BinaryArray encoded = seria::to_binary(tx);
		Transaction decoded;
		seria::from_binary(decoded, encoded);
		invariant(decoded.version == tx.version && decoded.onyx_type == parameters::ONYX_TYPE_TRANSFER &&
		              decoded.onyx_envelope == tx.onyx_envelope,
		    "Onyx opaque envelope did not round-trip");
		invariant(get_transaction_hash(tx) == crypto::cn_fast_hash(encoded.data(), encoded.size()) &&
		              get_transaction_hash(decoded) == get_transaction_hash(tx),
		    "Onyx transaction hash is not the hash of its canonical envelope encoding");
		tx.onyx_type = parameters::ONYX_TYPE_BRIDGE;
		const common::BinaryArray bridge_encoded = seria::to_binary(tx);
		seria::from_binary(decoded, bridge_encoded);
		invariant(decoded.onyx_type == parameters::ONYX_TYPE_BRIDGE && decoded.onyx_envelope == tx.onyx_envelope,
		    "Onyx bridge envelope did not round-trip");
		tx.onyx_type = parameters::ONYX_TYPE_PROGRAM_DEPLOYMENT;
		const common::BinaryArray deployment_encoded = seria::to_binary(tx);
		seria::from_binary(decoded, deployment_encoded);
		invariant(decoded.onyx_type == parameters::ONYX_TYPE_PROGRAM_DEPLOYMENT &&
		              decoded.onyx_envelope == tx.onyx_envelope,
		    "Onyx program deployment envelope did not round-trip");
		tx.onyx_type = parameters::ONYX_TYPE_TOKEN_ISSUANCE;
		const common::BinaryArray issuance_encoded = seria::to_binary(tx);
		seria::from_binary(decoded, issuance_encoded);
		invariant(decoded.onyx_type == parameters::ONYX_TYPE_TOKEN_ISSUANCE &&
		              decoded.onyx_envelope == tx.onyx_envelope,
		    "Onyx token issuance envelope did not round-trip");
		invariant(currency.get_block_major_version_for_height(parameters::UPGRADE_HEIGHT_ONYX - 1) ==
		        currency.jade_block_version,
		    "pre-Onyx block version changed");
		invariant(currency.get_block_major_version_for_height(parameters::UPGRADE_HEIGHT_ONYX) ==
		        currency.onyx_block_version,
		    "Onyx activation did not skip reserved block version 6");
		bool oversized_rejected = false;
		try {
			tx.onyx_envelope.assign(parameters::ONYX_MAX_ENVELOPE_SIZE + 1, 0);
			(void)seria::to_binary(tx);
		} catch (const std::exception &) {
			oversized_rejected = true;
		}
		invariant(oversized_rejected, "oversized Onyx envelope was serialized");
		tx.onyx_type = parameters::ONYX_TYPE_TRANSFER;
		tx.onyx_envelope = common::BinaryArray{0x06, 0x01};
		const bool inactive_rejected = semantic_rejects(currency, currency.onyx_block_version, tx, &what);
		invariant(inactive_rejected, "inactive Onyx state transition was accepted");
		std::cout << "  [onyx] bounded opaque envelope round-trip and reserved-version skip ok" << std::endl;
	}

	// 7. Onyx-aware wallets explicitly request all post-activation commitment history. Keep the
	// versioned binary method and the serialized flag covered together so either side cannot drift.
	{
		api::cnd::SyncBlocks::Request request;
		request.need_redundant_data = false;
		request.need_onyx_history = true;
		const common::BinaryArray encoded = seria::to_binary_kv(request);
		api::cnd::SyncBlocks::Request decoded;
		seria::from_binary_kv(decoded, encoded);
		invariant(api::cnd::SyncBlocks::bin_method() == "sync_blocks_v3.4.4",
		    "Onyx sync request method version changed unexpectedly");
		invariant(!decoded.need_redundant_data && decoded.need_onyx_history,
		    "Onyx sync history flag did not round-trip");
		std::cout << "  [onyx] global commitment-history sync request round-trip ok" << std::endl;
	}

	// 8. Dandelion++ is negotiated as P2P v5 and its one-descriptor stem message is canonical.
	{
		invariant(P2PProtocolVersion::DANDELION == 5, "Dandelion P2P version changed unexpectedly");
		p2p::StemTransaction::Notify stem;
		stem.transaction_desc.hash = crypto::rand<Hash>();
		stem.transaction_desc.fee = 1234;
		stem.transaction_desc.size = 567;
		stem.transaction_desc.newest_referenced_block = crypto::rand<Hash>();
		stem.hop = 7;
		const common::BinaryArray encoded = seria::to_binary_kv(stem);
		p2p::StemTransaction::Notify decoded;
		seria::from_binary_kv(decoded, encoded);
		invariant(decoded.transaction_desc.hash == stem.transaction_desc.hash &&
		              decoded.transaction_desc.fee == stem.transaction_desc.fee &&
		              decoded.transaction_desc.size == stem.transaction_desc.size &&
		              decoded.transaction_desc.newest_referenced_block ==
		                  stem.transaction_desc.newest_referenced_block &&
		              decoded.hop == stem.hop,
		    "Dandelion stem descriptor did not round-trip");
		invariant(p2p::StemTransaction::Notify::MAX_HOPS == 20,
		    "Dandelion maximum stem path changed unexpectedly");
		invariant(p2p::DandelionPolicy::should_fluff(false, 0, 20, 10, 99),
		    "disabled Dandelion did not force fluff");
		invariant(p2p::DandelionPolicy::should_fluff(true, 20, 20, 0, 99),
		    "Dandelion hop cap did not force fluff");
		invariant(p2p::DandelionPolicy::should_fluff(true, 1, 20, 10, 9) &&
		              !p2p::DandelionPolicy::should_fluff(true, 1, 20, 10, 10),
		    "Dandelion diffusion probability boundary is wrong");
		invariant(p2p::DandelionPolicy::embargo_seconds(30, 10, 0) == 10 &&
		              p2p::DandelionPolicy::embargo_seconds(30, 10, 20) == 30,
		    "Dandelion embargo bounds are not inclusive or normalized");
		invariant(p2p::DandelionPolicy::update_peer_score(8, 1) == 8 &&
		              p2p::DandelionPolicy::update_peer_score(-8, -2) == -8 &&
		              p2p::DandelionPolicy::decay_peer_score(3) == 2 &&
		              p2p::DandelionPolicy::decay_peer_score(-3) == -2 &&
		              !p2p::DandelionPolicy::accept_fluff_reflection(true) &&
		              p2p::DandelionPolicy::accept_fluff_reflection(false),
		    "Dandelion peer score bounds or decay changed");
		const std::vector<int> topology_scores{-8, 0, 8};
		std::array<size_t, 3> selections{{0, 0, 0}};
		for (uint64_t draw = 0; draw != 2700; ++draw)
			++selections.at(p2p::DandelionPolicy::select_weighted_peer(topology_scores, draw));
		invariant(selections[0] == 100 && selections[1] == 900 && selections[2] == 1700,
		    "Dandelion weighted peer selection is not deterministic or bounded");
		std::cout << "  [jade] Dandelion v5 stem descriptor round-trip ok" << std::endl;
	}

	// 9. SOCKS5 framing sends numeric peer addresses through the proxy and rejects unsafe replies.
	{
		NetworkAddress target;
		target.ip = common::BinaryArray{1, 2, 3, 4};
		target.port = 8080;
		invariant(p2p::Socks5::greeting() == common::BinaryArray({5, 1, 0}),
		    "SOCKS5 no-auth greeting changed unexpectedly");
		invariant(p2p::Socks5::connect_ipv4(target) ==
		              common::BinaryArray({5, 1, 0, 1, 1, 2, 3, 4, 0x1f, 0x90}),
		    "SOCKS5 numeric target request is not canonical");
		p2p::Socks5::validate_method(common::BinaryArray{5, 0});
		const common::BinaryArray ipv4_reply{5, 0, 0, 1, 127, 0, 0, 1, 0x23, 0x28};
		invariant(p2p::Socks5::connect_reply_size(ipv4_reply) == ipv4_reply.size(),
		    "SOCKS5 IPv4 reply length is wrong");
		p2p::Socks5::validate_connect_reply(ipv4_reply);
		bool rejected = false;
		try {
			p2p::Socks5::validate_method(common::BinaryArray{5, 0xff});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		invariant(rejected, "SOCKS5 authentication rejection was accepted");
		rejected = false;
		try {
			p2p::Socks5::connect_reply_size(common::BinaryArray{5, 5, 0, 1});
		} catch (const std::runtime_error &) {
			rejected = true;
		}
		invariant(rejected, "SOCKS5 destination rejection was accepted");
		std::cout << "  [jade] SOCKS5 numeric-target framing and rejection checks ok" << std::endl;
	}

	// 10. RandomX seed epochs are deterministic and always lag the block being validated.
	{
		invariant(currency.uses_randomx(currency.jade_block_version, currency.randomx_switch_height),
		    "RandomX is not active at its versioned switch height");
		invariant(!currency.uses_randomx(currency.amethyst_block_version, currency.randomx_switch_height),
		    "RandomX activated for a legacy block version");
		invariant(currency.randomx_seed_height(63) == 0 && currency.randomx_seed_height(64) == 0 &&
		              currency.randomx_seed_height(2111) == 0 && currency.randomx_seed_height(2112) == 2048,
		    "RandomX 2048-block seed epoch or 64-block lag changed");
		const Height activation_seed = currency.randomx_seed_height(currency.randomx_switch_height);
		invariant(activation_seed < currency.randomx_switch_height,
		    "RandomX activation seed is not an ancestor");
		std::cout << "  [jade] RandomX activation and delayed seed-height rules ok" << std::endl;
	}

	std::cout << "  test_jade_consensus: OK" << std::endl;
}
