// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "test_blockchain.hpp"

#include <array>
#include <fstream>
#include <vector>
#include "Core/BlockChainState.hpp"
#include "Core/Config.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/Currency.hpp"
#include "Core/Difficulty.hpp"
#include "Core/TransactionExtra.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "logging/ConsoleLogger.hpp"
#include "platform/PathTools.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "seria/KVBinaryInputStream.hpp"
#include "seria/KVBinaryOutputStream.hpp"
#include "version.hpp"

using namespace cn;

struct MinedBlockDesc {
	BlockTemplate block_template;
	BinaryArray binary_block_template;
	Hash hash;
	Height height = 0;
};

class TestMiner {
public:
	BlockChainState &block_chain;
	const Currency &currency;
	AccountAddress address;
	crypto::CryptoNightContext cryptoContext;
	crypto::RandomXContext randomxContext;
	std::vector<KeyPair> checkpoint_keypairs;

	TestMiner(BlockChainState &block_chain, const Currency &currency) : block_chain(block_chain), currency(currency) {
		invariant(currency.parse_account_address_string("21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqU"
		                                                "cLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC",
		              &address),
		    "");
		std::vector<std::string> skeys{"dacb828348483011f63ebb538401b3f3d52e8ce1916278f9b189f820d1ec730e",
		    "3ab19160e48f77b41a9b7f87322542b1e977577f30886db3dce3076806709d0d",
		    "16d4d146d8ba2bbff13a4bb174b4c5d73d3ca22817a6585956a697337be26a09"};
		for (auto &&sk : skeys) {
			checkpoint_keypairs.push_back(KeyPair{});
			invariant(common::pod_from_hex(sk, &checkpoint_keypairs.back().secret_key), "");
			invariant(crypto::secret_key_to_public_key(
			              checkpoint_keypairs.back().secret_key, &checkpoint_keypairs.back().public_key),
			    "");
		}
	}
	MinedBlockDesc mine_block(Hash bid) {
		api::BlockHeader parent;
		invariant(block_chain.get_header(bid, &parent), "");

		BlockTemplate block;
		Difficulty difficulty      = 0;
		Height height              = 0;
		size_t reserve_back_offset = 0;
		block_chain.create_mining_block_template(
		    bid, address, BinaryArray{}, Hash{}, &block, &difficulty, &height, &reserve_back_offset);
		set_root_extra_to_solo_mining_tag(block);
		block.root_block.timestamp = parent.timestamp + currency.difficulty_target;
		block.timestamp            = block.root_block.timestamp;
		//		block.root_block.nonce.resize(4);
		uint32_t nonce = crypto::rand<uint32_t>();
		//		block.nonce.resize(4);
		auto body_proxy = get_body_proxy_from_template(block);
		Hash pow_seed{};
		const Height candidate_height = parent.height + 1;
		if (currency.uses_randomx(block.major_version, candidate_height))
			pow_seed = block_chain.get_ancestor_hash(parent, currency.randomx_seed_height(candidate_height));
		while (true) {
			common::uint_le_to_bytes(block.root_block.nonce, 4, nonce);
			//			block.nonce    = block.root_block.nonce;
			BinaryArray ba = currency.get_block_pow_hashing_data(block, body_proxy);
			Hash hash = currency.uses_randomx(block.major_version, candidate_height) ?
			                randomxContext.hash(pow_seed, ba.data(), ba.size()) :
			                cryptoContext.cn_slow_hash(ba.data(), ba.size());
			if (check_hash(hash, difficulty))
				break;
			nonce += 1;
		}
		RawBlock rb;
		MinedBlockDesc desc{block, seria::to_binary(block), get_block_hash(block, body_proxy), candidate_height};
		return desc;
	}
	void add_mined_block(const MinedBlockDesc &desc, bool log = true) {
		RawBlock rb;
		api::BlockHeader info;
		block_chain.add_mined_block(desc.binary_block_template, &rb, &info);
		if (log)
			std::cout << "---- After add_mined_block tip=" << block_chain.get_tip_height() << " : "
			          << block_chain.get_tip_bid() << std::endl;
	}
	MinedBlockDesc test_grow_chain(Hash bid, Height length) {
		MinedBlockDesc desc;
		for (Height i = 0; i != length; ++i) {
			desc = mine_block(bid);
			add_mined_block(desc, false);
			bid = desc.hash;
		}
		std::cout << "---- After test_grow_chain tip=" << block_chain.get_tip_height() << " : "
		          << block_chain.get_tip_bid() << std::endl;
		return desc;
	}
	void add_checkpoint(size_t key_id, uint64_t counter, Hash hash, Height height) {
		SignedCheckpoint small_checkpoint;
		small_checkpoint.height    = height;
		small_checkpoint.hash      = hash;
		small_checkpoint.key_id    = key_id;
		small_checkpoint.counter   = counter;
		small_checkpoint.signature = crypto::generate_signature(small_checkpoint.get_message_hash(),
		    checkpoint_keypairs.at(key_id).public_key,
		    checkpoint_keypairs.at(key_id).secret_key);
		invariant(block_chain.add_checkpoint(small_checkpoint, ""), "");
		std::cout << "---- After add_checkpoint tip=" << block_chain.get_tip_height() << " : "
		          << block_chain.get_tip_bid() << std::endl;
	}
};

void test_blockchain(common::CommandLine &cmd) {
	logging::ConsoleLogger logger;
	Config config(cmd);
	config.data_folder = "../tests/scratchpad";
	config.net         = "test";
	BlockChain::DB::delete_db(config.data_folder + "/blockchain");

	std::cout << "Point 1" << std::endl;
	Currency currency(config);

	std::cout << "Point 2" << std::endl;
	BlockChainState block_chain(logger, config, currency, false);

	std::cout << "Point 3" << std::endl;
	TestMiner test_miner(block_chain, currency);

	std::cout << "Point 4" << std::endl;
	auto middle_desc = test_miner.test_grow_chain(block_chain.get_tip().hash, 25);

	std::cout << "Point 5" << std::endl;
	auto small_desc = test_miner.test_grow_chain(middle_desc.hash, 25);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	auto big_desc = test_miner.test_grow_chain(middle_desc.hash, 50);

	invariant(block_chain.get_tip_bid() == big_desc.hash, "");

	auto small_plus_1_desc = test_miner.mine_block(small_desc.hash);
	auto big_plus_1_desc   = test_miner.mine_block(big_desc.hash);

	test_miner.add_checkpoint(0, 1, small_desc.hash, small_desc.height);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	test_miner.add_checkpoint(0, 2, big_plus_1_desc.hash, big_plus_1_desc.height);

	invariant(block_chain.get_tip_bid() == small_desc.hash, "");

	test_miner.add_mined_block(big_plus_1_desc);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_checkpoint(1, 1, small_desc.hash, small_desc.height);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_checkpoint(2, 1, small_plus_1_desc.hash, small_plus_1_desc.height);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	test_miner.add_mined_block(small_plus_1_desc);

	invariant(block_chain.get_tip_bid() == small_plus_1_desc.hash, "");

	test_miner.add_checkpoint(1, std::numeric_limits<uint64_t>::max(), Hash{}, 0);

	invariant(block_chain.get_tip_bid() == big_plus_1_desc.hash, "");

	// Exercise the real RandomX validator across an epoch-boundary reorganization. Both branches
	// fork before height 8, so their height-8 seed blocks differ. A height-10 side-chain block is
	// valid only if validation resolves the delayed seed from that block's own parent branch.
	{
		Config randomx_config(cmd);
		randomx_config.data_folder = "../tests/scratchpad-randomx";
		randomx_config.net         = "test";
		invariant(platform::create_folders_if_necessary(randomx_config.data_folder),
		    "Could not create RandomX test data folder");
		BlockChain::DB::delete_db(randomx_config.data_folder + "/blockchain");
		Currency randomx_currency(randomx_config);
		randomx_currency.upgrade_heights.at(3) = 2;
		randomx_currency.randomx_switch_height = 2;
		randomx_currency.randomx_seed_epoch    = 8;
		randomx_currency.randomx_seed_lag      = 2;
		BlockChainState randomx_chain(logger, randomx_config, randomx_currency, false);
		TestMiner randomx_miner(randomx_chain, randomx_currency);

		const auto fork = randomx_miner.test_grow_chain(randomx_chain.get_tip_bid(), 7);
		const auto main_seed = randomx_miner.test_grow_chain(fork.hash, 1);
		const auto main_tip = randomx_miner.test_grow_chain(main_seed.hash, 3);
		invariant(main_tip.height == 11 && randomx_chain.get_tip_bid() == main_tip.hash,
		    "RandomX main branch did not reach the expected epoch boundary");

		const auto side_seed = randomx_miner.test_grow_chain(fork.hash, 1);
		invariant(side_seed.hash != main_seed.hash, "RandomX fork did not create distinct seed blocks");
		const auto side_tip = randomx_miner.test_grow_chain(side_seed.hash, 4);
		invariant(side_tip.height == 12 && randomx_chain.get_tip_bid() == side_tip.hash,
		    "RandomX side branch did not validate and reorganize across its seed epoch");
		invariant(randomx_chain.get_ancestor_hash(randomx_chain.get_tip(), 8) == side_seed.hash,
		    "RandomX reorganized tip did not retain the side-branch seed");

		// Continue both retained branches through a second seed epoch and force two more tip changes.
		// This catches implementations that cache the current tip's seed and accidentally reuse it when
		// validating a longer branch whose height-16 ancestor differs.
		const auto main_second_seed = randomx_miner.test_grow_chain(main_tip.hash, 5);
		invariant(main_second_seed.height == 16, "RandomX main branch missed its second seed height");
		const auto main_second_tip = randomx_miner.test_grow_chain(main_second_seed.hash, 1);
		invariant(main_second_tip.height == 17 && randomx_chain.get_tip_bid() == main_second_tip.hash,
		    "RandomX main branch did not reorganize through the second epoch");
		invariant(randomx_chain.get_ancestor_hash(randomx_chain.get_tip(), 16) == main_second_seed.hash,
		    "RandomX main branch retained the wrong second-epoch seed");

		const auto side_second_seed = randomx_miner.test_grow_chain(side_tip.hash, 4);
		invariant(side_second_seed.height == 16 && side_second_seed.hash != main_second_seed.hash,
		    "RandomX branches did not produce distinct second-epoch seeds");
		const auto side_second_tip = randomx_miner.test_grow_chain(side_second_seed.hash, 2);
		invariant(side_second_tip.height == 18 && randomx_chain.get_tip_bid() == side_second_tip.hash,
		    "RandomX side branch did not reorg back through the second epoch");
		invariant(randomx_chain.get_ancestor_hash(randomx_chain.get_tip(), 16) == side_second_seed.hash,
		    "RandomX side branch retained the wrong second-epoch seed");
		std::cout << "---- RandomX repeated branch-derived epoch reorganizations: OK" << std::endl;
	}

	// Run a longer deterministic pseudo-random campaign with a smaller test-only epoch. Each round
	// extends the inactive branch by a varying amount until it becomes strictly longer, forcing the
	// validator to abandon its current cached seed and resolve the candidate's own retained ancestry.
	// Reopen the database afterwards and force one more reorganization onto the previously inactive
	// branch, covering persisted side-chain ancestry as well as the in-memory path.
	{
		Config randomx_config(cmd);
		randomx_config.data_folder = "../tests/scratchpad-randomx-randomized";
		randomx_config.net         = "test";
		invariant(platform::create_folders_if_necessary(randomx_config.data_folder),
		    "Could not create randomized RandomX test data folder");
		BlockChain::DB::delete_db(randomx_config.data_folder + "/blockchain");
		Currency randomx_currency(randomx_config);
		randomx_currency.upgrade_heights.at(3) = 2;
		randomx_currency.randomx_switch_height = 2;
		randomx_currency.randomx_seed_epoch    = 4;
		randomx_currency.randomx_seed_lag      = 1;

		std::array<std::vector<Hash>, 2> histories;
		std::array<Hash, 2> tips{};
		std::array<Height, 2> heights{{0, 0}};
		size_t active = 0;
		{
			BlockChainState randomx_chain(logger, randomx_config, randomx_currency, false);
			TestMiner randomx_miner(randomx_chain, randomx_currency);
			const Hash genesis = randomx_chain.get_tip_bid();
			std::vector<Hash> common_history{genesis};
			Hash common_tip = genesis;
			for (Height height = 1; height <= 3; ++height) {
				const auto block = randomx_miner.mine_block(common_tip);
				randomx_miner.add_mined_block(block, false);
				common_tip = block.hash;
				common_history.push_back(block.hash);
			}
			histories[0] = histories[1] = common_history;
			tips[0] = tips[1] = common_tip;
			heights[0] = heights[1] = 3;

			uint64_t state = 0x6a09e667f3bcc909ULL;
			for (size_t round = 0; round != 14; ++round) {
				const size_t target = round % 2;
				const size_t other = 1 - target;
				invariant(heights[target] <= heights[other],
				    "RandomX campaign did not select the inactive branch");
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				const Height growth = heights[other] - heights[target] + 1 + state % 3;
				for (Height count = 0; count != growth; ++count) {
					const auto block = randomx_miner.mine_block(tips[target]);
					randomx_miner.add_mined_block(block, false);
					tips[target] = block.hash;
					heights[target] = block.height;
					histories[target].push_back(block.hash);
				}
				active = target;
				invariant(randomx_chain.get_tip_bid() == tips[active],
				    "RandomX randomized branch did not become active");
				const Height seed_height = randomx_currency.randomx_seed_height(heights[active]);
				invariant(seed_height < histories[active].size() &&
				              randomx_chain.get_ancestor_hash(randomx_chain.get_tip(), seed_height) ==
				                  histories[active].at(seed_height),
				    "RandomX randomized reorganization selected the wrong branch seed");
				if (seed_height > 3 && seed_height < histories[other].size())
					invariant(histories[active].at(seed_height) != histories[other].at(seed_height),
					    "RandomX randomized branches unexpectedly shared a post-fork seed");
			}
			randomx_chain.db_commit();
		}

		const size_t inactive = 1 - active;
		{
			BlockChainState reopened_chain(logger, randomx_config, randomx_currency, false);
			invariant(reopened_chain.get_tip_bid() == tips[active],
			    "RandomX active tip changed after database reopen");
			api::BlockHeader retained_header;
			invariant(reopened_chain.get_header(tips[inactive], &retained_header) &&
			              retained_header.height == heights[inactive],
			    "RandomX inactive branch was not retained across database reopen");
			TestMiner reopened_miner(reopened_chain, randomx_currency);
			const Height growth = heights[active] - heights[inactive] + 2;
			for (Height count = 0; count != growth; ++count) {
				const auto block = reopened_miner.mine_block(tips[inactive]);
				reopened_miner.add_mined_block(block, false);
				tips[inactive] = block.hash;
				heights[inactive] = block.height;
				histories[inactive].push_back(block.hash);
			}
			invariant(reopened_chain.get_tip_bid() == tips[inactive],
			    "RandomX persisted inactive branch did not reorganize after database reopen");
			const Height seed_height = randomx_currency.randomx_seed_height(heights[inactive]);
			invariant(reopened_chain.get_ancestor_hash(reopened_chain.get_tip(), seed_height) ==
			              histories[inactive].at(seed_height),
			    "RandomX database-reopen reorganization selected the wrong persisted seed");
		}
		std::cout << "---- RandomX randomized multi-epoch reorg and reopen campaign: OK" << std::endl;
	}
}

// Sometimes in the future we will test consistency with simple model
class TestBlockChain {
	const Currency &m_currency;
	Hash m_tip_bid;
	Height m_tip_height = Height(-1);
	struct TestBlock {
		api::BlockHeader header;

		std::bitset<64> checkpoint_key_ids;
		BlockChain::CheckpointDifficulty checkpoint_difficulty;  // (key_count-1)->max_height

		TestBlock *parent = nullptr;
		std::vector<TestBlock *> children;
	};
	std::map<Hash, TestBlock> blocks;
	std::map<size_t, SignedCheckpoint> checkpoints;
	std::map<size_t, SignedCheckpoint> stable_checkpoints;

	bool add_block(const api::BlockHeader &info) {
		auto bit = blocks.find(info.hash);
		if (bit != blocks.end())
			return true;
		auto pit = blocks.find(info.previous_block_hash);
		if (pit == blocks.end())
			return false;
		auto &block  = blocks[info.hash];
		block.header = info;
		block.parent = &pit->second;
		pit->second.children.push_back(&block);
		return true;
	}

public:
	explicit TestBlockChain(const Currency &currency) : m_currency(currency) {
		auto &block             = blocks[m_currency.genesis_block_hash];
		block.header.hash       = m_currency.genesis_block_hash;
		block.header.height     = 0;
		block.header.difficulty = 1;
		block.header.timestamp  = m_currency.genesis_block_template.timestamp;
	}
	Hash get_tip_bid() const { return m_tip_bid; }
	Height get_tip_height() const { return m_tip_height; }
	bool add_checkpoint(const SignedCheckpoint &checkpoint) { return false; }
	bool add_block(const PreparedBlock &pb, api::BlockHeader *info) { return false; }
	bool add_mined_block(const BinaryArray &raw_block_template, RawBlock *raw_block, api::BlockHeader *info) {
		return false;
	}
};
