// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_jade_consensus.hpp"
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

	// 6. Onyx transaction V6 is a bounded opaque envelope and round-trips without invoking legacy
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
		std::cout << "  [jade] Dandelion v5 stem descriptor round-trip ok" << std::endl;
	}

	std::cout << "  test_jade_consensus: OK" << std::endl;
}
