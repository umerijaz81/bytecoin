// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_jade_consensus.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include "Core/Archive.hpp"
#include "Core/BlockChainState.hpp"
#include "Core/Config.hpp"
#include "Core/Currency.hpp"
#include "Core/OnyxWalletPolicy.hpp"
#include "Core/WalletSync.hpp"
#include "CryptoNote.hpp"
#include "CryptoNoteConfig.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "common/Invariant.hpp"
#include "common/CommandLine.hpp"
#include "crypto/crypto.hpp"
#include "p2p/P2pProtocolDefinitions.hpp"
#include "p2p/Dandelion.hpp"
#include "p2p/Socks5.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryCommon.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "rpc_api.hpp"

using namespace cn;

static void append_le(common::BinaryArray &out, uint64_t value, size_t size) {
	for (size_t i = 0; i != size; ++i)
		out.push_back(static_cast<uint8_t>(value >> (i * 8)));
}

static common::BinaryArray kv_header() {
	common::BinaryArray out;
	append_le(out, PORTABLE_STORAGE_SIGNATUREA, 4);
	append_le(out, PORTABLE_STORAGE_SIGNATUREB, 4);
	out.push_back(PORTABLE_STORAGE_FORMAT_VER);
	return out;
}

static bool rejects_malformed_kv(const common::BinaryArray &wire) {
	try {
		common::MemoryInputStream stream(wire.data(), wire.size());
		seria::KVBinaryInputStream input(stream);
		(void)input;
		return false;
	} catch (const std::exception &) {
		return true;
	}
}

template<typename T>
static bool rejects_truncated_binary(T &value, const common::BinaryArray &wire) {
	try {
		seria::from_binary(value, wire);
		return false;
	} catch (const std::exception &) {
		return true;
	}
}

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
	invariant(currency.get_next_block_major_version(parameters::UPGRADE_HEIGHT_V5 - 2) ==
	              currency.amethyst_block_version,
	    "wallet/mempool next-block version switched to Jade too early");
	invariant(currency.get_next_block_major_version(parameters::UPGRADE_HEIGHT_V5 - 1) ==
	              currency.jade_block_version,
	    "wallet/mempool next-block version did not switch at the Jade boundary");
	invariant(currency.get_next_block_major_version(parameters::UPGRADE_HEIGHT_ONYX - 2) ==
	              currency.jade_block_version,
	    "wallet next-block construction enabled Onyx too early");
	invariant(currency.get_next_block_major_version(parameters::UPGRADE_HEIGHT_ONYX - 1) ==
	              currency.onyx_block_version,
	    "wallet/mempool next-block construction did not switch at the Onyx boundary");
	bool maximum_height_rejected = false;
	try {
		(void)currency.get_next_block_major_version(std::numeric_limits<Height>::max());
	} catch (const std::exception &) {
		maximum_height_rejected = true;
	}
	invariant(maximum_height_rejected, "next-block version wrapped at maximum height");
	{
		constexpr size_t inputs = 3;
		constexpr size_t outputs = 5;
		constexpr size_t anonymity = 15;
		const size_t amethyst_size = get_maximum_tx_size_amethyst(inputs, outputs, anonymity);
		const size_t jade_size = get_maximum_tx_size_jade(inputs, outputs, anonymity);
		invariant(jade_size == amethyst_size + 1,
		    "Jade size estimator does not model its one-byte signature-scheme field");
		TransactionPrefix amethyst_prefix;
		amethyst_prefix.version = currency.amethyst_transaction_version;
		TransactionPrefix jade_prefix = amethyst_prefix;
		jade_prefix.version = currency.jade_transaction_version;
		jade_prefix.signature_scheme =
		    static_cast<uint8_t>(TransactionSignatureScheme::AMETHYST_LINKABLE_RING);
		invariant(seria::to_binary(jade_prefix).size() == seria::to_binary(amethyst_prefix).size() + 1,
		    "Jade transaction-prefix wire delta is not one byte");
		invariant(get_maximum_tx_input_count_jade(jade_size, outputs, anonymity) ==
		              get_maximum_tx_input_count_amethyst(amethyst_size, outputs, anonymity),
		    "Jade maximum-input estimator is not the inverse of its wire-size delta");
		Amount rounded = 0;
		invariant(round_amount_up(1001, 1000, &rounded) && rounded == 2000,
		    "wallet fee rounding changed its ceiling behavior");
		invariant(round_amount_up(std::numeric_limits<Amount>::max() - 999, 1000, &rounded),
		    "wallet rejected the largest representable rounded fee");
		invariant(!round_amount_up(std::numeric_limits<Amount>::max(), 1000, &rounded),
		    "wallet fee rounding wrapped at the amount limit");
		Amount required = std::numeric_limits<Amount>::max();
		invariant(!add_amount(required, 1), "wallet amount-plus-fee arithmetic wrapped");
		invariant(absolute_index_distance(0, std::numeric_limits<size_t>::max()) ==
		              std::numeric_limits<size_t>::max() &&
		              absolute_index_distance(std::numeric_limits<size_t>::max(), 0) ==
		                  std::numeric_limits<size_t>::max() &&
		              absolute_index_distance(std::numeric_limits<size_t>::max() - 1,
		                  std::numeric_limits<size_t>::max()) == 1,
		    "wallet decoy stack-index distance narrowed or overflowed");
		invariant(has_requested_anonymity(16, 16) && has_requested_anonymity(17, 16) &&
		              !has_requested_anonymity(15, 16),
		    "wallet anonymity policy does not fail closed below the requested ring privacy");
	}
	{
		OnyxConstructionWindow window;
		const Height tip = parameters::UPGRADE_HEIGHT_ONYX - 1;
		invariant(!resolve_onyx_construction_window(tip, tip, &window),
		    "wallet accepted an Onyx transaction expiring before next-block inclusion");
		invariant(resolve_onyx_construction_window(tip, tip + 1, &window) &&
		              window.inclusion_height == tip + 1 && window.expiry_height == tip + 1,
		    "wallet rejected the inclusive Onyx expiry lower bound");
		invariant(resolve_onyx_construction_window(
		              tip, tip + 1 + parameters::ONYX_MAX_EXPIRY_DISTANCE, &window),
		    "wallet rejected the inclusive Onyx expiry upper bound");
		invariant(!resolve_onyx_construction_window(
		              tip, tip + 2 + parameters::ONYX_MAX_EXPIRY_DISTANCE, &window),
		    "wallet accepted an Onyx expiry beyond the consensus window");
		invariant(resolve_onyx_construction_window(tip, 0, &window) &&
		              window.expiry_height == tip + 20,
		    "wallet changed the default Onyx expiry distance");
		invariant(!resolve_onyx_construction_window(
		              std::numeric_limits<Height>::max(), 0, &window),
		    "wallet wrapped the next Onyx inclusion height");
	}

	// Portable-storage is reachable through both RPC and Levin/P2P. Reject ambiguous encodings and
	// attacker-selected allocation/work factors before materializing the intermediate JSON tree.
	{
		common::BinaryArray duplicate = kv_header();
		duplicate.push_back(2 << 2);  // root object count
		for (uint8_t value = 1; value != 3; ++value) {
			duplicate.push_back(1);
			duplicate.push_back('a');
			duplicate.push_back(BIN_KV_SERIALIZE_TYPE_UINT8);
			duplicate.push_back(value);
		}
		invariant(rejects_malformed_kv(duplicate), "duplicate KV object key was accepted");

		common::BinaryArray noncanonical = kv_header();
		append_le(noncanonical, (uint64_t{0} << 2) | PORTABLE_RAW_SIZE_MARK_WORD, 2);
		invariant(rejects_malformed_kv(noncanonical), "non-canonical KV size varint was accepted");

		common::BinaryArray oversized_object = kv_header();
		append_le(oversized_object,
		    (uint64_t{KV_BINARY_MAX_CONTAINER_ENTRIES + 1} << 2) | PORTABLE_RAW_SIZE_MARK_DWORD, 4);
		invariant(rejects_malformed_kv(oversized_object), "oversized KV object count was accepted");

		common::BinaryArray oversized_string = kv_header();
		oversized_string.push_back(1 << 2);
		oversized_string.push_back(1);
		oversized_string.push_back('s');
		oversized_string.push_back(BIN_KV_SERIALIZE_TYPE_STRING);
		append_le(oversized_string,
		    (uint64_t{KV_BINARY_MAX_STRING_SIZE + 1} << 2) | PORTABLE_RAW_SIZE_MARK_DWORD, 4);
		invariant(rejects_malformed_kv(oversized_string), "oversized KV string was accepted");

		common::BinaryArray invalid_bool = kv_header();
		invalid_bool.push_back(1 << 2);
		invalid_bool.push_back(1);
		invalid_bool.push_back('b');
		invalid_bool.push_back(BIN_KV_SERIALIZE_TYPE_BOOL);
		invalid_bool.push_back(2);
		invariant(rejects_malformed_kv(invalid_bool), "non-canonical KV boolean was accepted");

		common::BinaryArray invalid_empty_array = kv_header();
		invalid_empty_array.push_back(1 << 2);
		invalid_empty_array.push_back(1);
		invalid_empty_array.push_back('a');
		invalid_empty_array.push_back(BIN_KV_SERIALIZE_FLAG_ARRAY | 0x7f);
		invalid_empty_array.push_back(0);
		invariant(rejects_malformed_kv(invalid_empty_array), "invalid empty KV array type was accepted");
		std::cout << "  [jade] bounded canonical KV-binary parser checks ok" << std::endl;
	}

	// Compact binary vectors, maps and strings must not trust a declared count larger than the
	// entire remaining buffer. This rejects work/allocation amplification before mutating containers.
	{
		common::VectorStream encoded;
		encoded.write_varint(1024 * 1024);
		const common::BinaryArray declared_large = encoded.buffer();

		std::vector<uint64_t> values{7};
		invariant(rejects_truncated_binary(values, declared_large),
		    "truncated compact-binary array count was accepted");
		invariant(values == std::vector<uint64_t>{7},
		    "rejected compact-binary array mutated its destination");

		std::string text = "unchanged";
		invariant(rejects_truncated_binary(text, declared_large),
		    "truncated compact-binary string size was accepted");
		invariant(text == "unchanged", "rejected compact-binary string mutated its destination");
		std::cout << "  [jade] remaining-input compact-binary bounds ok" << std::endl;
	}

	// Privacy-sensitive attribution is opt-in at both the top-level config and the lower-level
	// archive constructor. The deprecated ambiguous flag must not silently restore collection.
	invariant(config.archive_omit_source_addresses && !config.log_peer_addresses &&
	              Archive::DEFAULT_OMIT_SOURCE_ADDRESSES,
	    "peer attribution or address logging was enabled by default");
	{
		const char *explicit_args[] = {
		    "tests", "--archive-store-source-ips", "--log-peer-addresses"};
		common::CommandLine explicit_cmd(3, explicit_args);
		Config explicit_config(explicit_cmd);
		invariant(!explicit_config.archive_omit_source_addresses && explicit_config.log_peer_addresses,
		    "explicit peer-attribution diagnostics were not honored");
		const char *legacy_args[] = {"tests", "--archive-keep-source-addresses"};
		common::CommandLine legacy_cmd(2, legacy_args);
		bool legacy_rejected = false;
		try {
			Config legacy_config(legacy_cmd);
			(void)legacy_config;
		} catch (const Config::ConfigError &) {
			legacy_rejected = true;
		}
		invariant(legacy_rejected, "deprecated archive attribution flag bypassed explicit opt-in");
	}

	// Pool policy is intentionally non-consensus, but its exact boundary must remain deterministic
	// across nodes and reject before expensive standard-program proof verification.
	invariant(BlockChainState::can_accept_zero_fee_standard_call(
	              BlockChainState::MAX_POOL_ZERO_FEE_STANDARD_CALLS - 1),
	    "zero-fee standard-call pool rejected below its cap");
	invariant(!BlockChainState::can_accept_zero_fee_standard_call(
	              BlockChainState::MAX_POOL_ZERO_FEE_STANDARD_CALLS),
	    "zero-fee standard-call pool accepted at its cap");

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
		request.sparse_chain.push_back(Hash{});
		request.need_redundant_data = false;
		request.need_onyx_history = true;
		const common::BinaryArray encoded = seria::to_binary_kv(request);
		api::cnd::SyncBlocks::Request decoded;
		seria::from_binary_kv(decoded, encoded);
		invariant(api::cnd::SyncBlocks::bin_method() == "sync_blocks_v3.4.4",
		    "Onyx sync request method version changed unexpectedly");
		invariant(!decoded.need_redundant_data && decoded.need_onyx_history &&
		              decoded.first_block_timestamp == 0 && decoded.sparse_chain.size() == 1 &&
		              decoded.sparse_chain.front() == Hash{},
		    "privacy-preserving Onyx sync request did not round-trip");
		std::cout << "  [onyx] global commitment-history sync request round-trip ok" << std::endl;
	}

	// 8. Privacy-mode mempool sync sends no wallet-local hash fingerprint and reconciles its old
	// cache against the node's full authoritative response.
	{
		api::cnd::SyncMemPool::Request request;
		const common::BinaryArray encoded = seria::to_binary_kv(request);
		api::cnd::SyncMemPool::Request decoded;
		seria::from_binary_kv(decoded, encoded);
		invariant(decoded.known_hashes.empty(),
		    "privacy mempool request disclosed known transaction hashes");
		Hash first{};
		Hash retained{};
		Hash added{};
		first.data[0] = 1;
		retained.data[0] = 2;
		added.data[0] = 3;
		api::Transaction retained_transaction;
		retained_transaction.hash = retained;
		api::Transaction added_transaction;
		added_transaction.hash = added;
		const std::vector<Hash> removed = WalletSync::calculate_privacy_pool_removals(
		    {first, retained}, {retained_transaction, added_transaction});
		invariant(removed == std::vector<Hash>{first},
		    "privacy mempool reconciliation did not remove exactly the absent transaction");
		std::cout << "  [privacy] mempool fingerprint omission and reconciliation ok" << std::endl;
	}

	// 9. Dandelion++ is negotiated as P2P v5 and its one-descriptor stem message is canonical.
	{
		invariant(P2PProtocolVersion::DANDELION == 5, "Dandelion P2P version changed unexpectedly");
		invariant(P2PProtocolVersion::ANONYMITY_ADDRESSES == 6,
		    "anonymity-address P2P version changed unexpectedly");
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
		const std::string onion_host = std::string(56, 'a') + ".onion";
		invariant(p2p::Socks5::is_anonymity_domain(onion_host) &&
		              p2p::Socks5::connect_anonymity_domain(onion_host, 18080).at(3) == 3,
		    "SOCKS5 onion framing is not canonical");
		p2p::Handshake::Response identity_response;
		identity_response.node_data.version = P2PProtocolVersion::ANONYMITY_ADDRESSES;
		identity_response.node_data.anonymity_host = onion_host;
		identity_response.node_data.anonymity_port = 18080;
		AnonymityNetworkAddress shared_identity;
		shared_identity.host = onion_host;
		shared_identity.port = 18081;
		identity_response.anonymity_peerlist.push_back(shared_identity);
		const BinaryArray identity_wire = seria::to_binary_kv(identity_response);
		p2p::Handshake::Response decoded_identity;
		seria::from_binary_kv(decoded_identity, identity_wire);
		invariant(decoded_identity.node_data.version == P2PProtocolVersion::ANONYMITY_ADDRESSES &&
		              decoded_identity.node_data.anonymity_host == onion_host &&
		              decoded_identity.node_data.anonymity_port == 18080 &&
		              decoded_identity.anonymity_peerlist.size() == 1 &&
		              decoded_identity.anonymity_peerlist.front().host == onion_host &&
		              decoded_identity.anonymity_peerlist.front().port == 18081,
		    "versioned anonymity identity did not round-trip");
		p2p::Handshake::Response legacy_identity_response;
		legacy_identity_response.node_data.version = P2PProtocolVersion::DANDELION;
		const BinaryArray legacy_identity_wire = seria::to_binary_kv(legacy_identity_response);
		const std::string anonymity_key = "anonymity_peerlist";
		invariant(std::search(legacy_identity_wire.begin(), legacy_identity_wire.end(), anonymity_key.begin(),
		              anonymity_key.end()) == legacy_identity_wire.end(),
		    "empty v5 handshake unexpectedly emitted the v6 anonymity peer list");
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
		BlockHeader jade_header;
		jade_header.major_version = currency.jade_block_version;
		BlockHeader onyx_header;
		onyx_header.major_version = currency.onyx_block_version;
		invariant(jade_header.is_merge_mined() && onyx_header.is_merge_mined(),
		    "Jade or Onyx did not retain the canonical root-block wire format");
		BlockHeader reserved_header;
		reserved_header.major_version = 6;
		invariant(!reserved_header.is_merge_mined(), "reserved V6 block format was accepted as merge-mined");
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
