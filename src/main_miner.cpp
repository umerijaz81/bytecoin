// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <thread>
#include "Core/Config.hpp"
#include "Core/CryptoNoteTools.hpp"
#include "Core/Currency.hpp"
#include "Core/Difficulty.hpp"
#include "Core/TransactionExtra.hpp"
#include "CryptoNoteConfig.hpp"
#include "common/CommandLine.hpp"
#include "common/ConsoleTools.hpp"
#include "common/Varint.hpp"
#include "crypto/crypto.hpp"
#include "crypto/RandomX.hpp"
#include "http/Agent.hpp"
#include "http/JsonRpc.hpp"
#include "platform/Network.hpp"
#include "rpc_api.hpp"
#include "seria/BinaryInputStream.hpp"
#include "seria/BinaryOutputStream.hpp"
#include "version.hpp"

static const char USAGE[] =
    R"(minerd. Bytecoin proof-of-work miner

Usage:
  minerd [options]

Options:
  -h --help                      Show this screen.
  -v --version                   Show version.
  --wallet-address=<address>     Address to receive mined coins (required).
  --bytecoind-address=<ip:port>  Single option for both daemon address and port.
  --limit=<N>                    Mine and submit specified number of blocks, then exit, 0 means no limit [Default: 0].
  --threads=<N>                  RandomX hashing threads [Default: detected CPU count].
  --randomx-init-threads=<N>     Full-memory dataset initialization threads [Default: hashing threads].
  --randomx-large-pages          Require large pages for the RandomX dataset (fail if unavailable).
  --randomx-light                Use one-thread 256 MiB verification mode instead of the 2080 MiB dataset.
  --boast=<text>                 Text to insert into coinbase transaction's extra nonce.
  --miner-secret=<hash_hex>      Turn on deterministic mining.
  --cm                           EXPERIMENTAL. Use CM with random virtual coins.
)";

using namespace cn;

struct MiningConfig {
	explicit MiningConfig(common::CommandLine &cmd)
	    : bytecoind_ip("127.0.0.1"), bytecoind_port(parameters::RPC_DEFAULT_PORT) {
		if (const char *pa = cmd.get("--address", "Use --wallet-address instead"))
			mining_address = pa;
		if (const char *pa = cmd.get("--wallet-address"))
			mining_address = pa;
		if (const char *pa = cmd.get("--" CRYPTONOTE_NAME "d-address")) {
			ewrap(common::parse_ip_address_and_port(pa, &bytecoind_ip, &bytecoind_port),
			    std::runtime_error("Command line option --" CRYPTONOTE_NAME "d-address has wrong format"));
		} else
			throw std::runtime_error("--" CRYPTONOTE_NAME "d-address=ip:port argument is mandatory");
		if (const char *pa = cmd.get("--limit"))
			blocks_limit = common::integer_cast<size_t>(pa);
		threads = std::max<size_t>(1, std::thread::hardware_concurrency());
		if (const char *pa = cmd.get("--threads"))
			threads = common::integer_cast<size_t>(pa);
		if (threads == 0 || threads > 256)
			throw std::runtime_error("--threads must be between 1 and 256");
		randomx_init_threads = threads;
		if (const char *pa = cmd.get("--randomx-init-threads"))
			randomx_init_threads = common::integer_cast<size_t>(pa);
		if (randomx_init_threads == 0 || randomx_init_threads > 256)
			throw std::runtime_error("--randomx-init-threads must be between 1 and 256");
		randomx_large_pages = cmd.get_bool("--randomx-large-pages");
		randomx_light       = cmd.get_bool("--randomx-light");
		if (randomx_light && threads != 1)
			throw std::runtime_error("--randomx-light requires --threads=1 to avoid duplicate 256 MiB caches");
		if (const char *pa = cmd.get("--boast"))
			boast = pa;
		if (const char *pa = cmd.get("--miner-secret")) {
			if (!common::pod_from_hex(pa, &miner_secret))
				throw std::runtime_error("Miner Secret must be hash in hex");
			if (miner_secret == Hash{})
				throw std::runtime_error("Miner Secret must not be all zeroes");
		}
		cm = cmd.get_bool("--cm");
		mm = cmd.get_bool("--mm");
	}

	std::string mining_address;
	std::string bytecoind_ip;
	std::string boast;
	uint16_t bytecoind_port = 0;
	size_t blocks_limit     = 0;
	// Mine specified number of blocks, then exit, 0 == indefinetely
	Hash miner_secret;
	bool cm = false;
	bool mm = false;
	size_t threads = 1;
	size_t randomx_init_threads = 1;
	bool randomx_large_pages = false;
	bool randomx_light = false;
};

class RandomXHashPool : private common::Nocopy {
public:
	RandomXHashPool(std::shared_ptr<const crypto::RandomXDataset> dataset, size_t thread_count)
	    : m_dataset(std::move(dataset)), m_inputs(thread_count), m_results(thread_count) {
		if (!m_dataset || thread_count == 0)
			throw std::invalid_argument("RandomX hash pool requires a dataset and worker threads");
		m_contexts.reserve(thread_count);
		m_workers.reserve(thread_count);
		for (size_t i = 0; i != thread_count; ++i)
			m_contexts.emplace_back(new crypto::RandomXContext(m_dataset));
		try {
			for (size_t i = 0; i != thread_count; ++i)
				m_workers.emplace_back(&RandomXHashPool::worker_run, this, i);
		} catch (...) {
			stop_workers();
			throw;
		}
	}

	~RandomXHashPool() { stop_workers(); }

	std::vector<Hash> hash(std::vector<BinaryArray> inputs) {
		if (inputs.size() != m_workers.size())
			throw std::invalid_argument("RandomX hash pool input count does not match worker count");
		std::unique_lock<std::mutex> lock(m_mutex);
		m_inputs = std::move(inputs);
		m_completed = 0;
		m_error = nullptr;
		++m_generation;
		m_start.notify_all();
		m_done.wait(lock, [&] { return m_completed == m_workers.size(); });
		if (m_error)
			std::rethrow_exception(m_error);
		return m_results;
	}

private:
	void stop_workers() {
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_stopping = true;
			++m_generation;
		}
		m_start.notify_all();
		for (auto &worker : m_workers)
			if (worker.joinable())
				worker.join();
		m_workers.clear();
	}

	void worker_run(size_t index) {
		size_t observed_generation = 0;
		for (;;) {
			std::unique_lock<std::mutex> lock(m_mutex);
			m_start.wait(lock, [&] { return m_stopping || m_generation != observed_generation; });
			if (m_stopping)
				return;
			observed_generation = m_generation;
			const BinaryArray &input = m_inputs[index];
			lock.unlock();
			try {
				m_results[index] =
				    m_contexts[index]->hash(m_dataset->seed(), input.data(), input.size());
			} catch (...) {
				lock.lock();
				if (!m_error)
					m_error = std::current_exception();
				lock.unlock();
			}
			lock.lock();
			++m_completed;
			if (m_completed == m_workers.size())
				m_done.notify_one();
		}
	}

	std::shared_ptr<const crypto::RandomXDataset> m_dataset;
	std::vector<std::unique_ptr<crypto::RandomXContext>> m_contexts;
	std::vector<std::thread> m_workers;
	std::vector<BinaryArray> m_inputs;
	std::vector<Hash> m_results;
	std::mutex m_mutex;
	std::condition_variable m_start;
	std::condition_variable m_done;
	size_t m_generation = 0;
	size_t m_completed = 0;
	bool m_stopping = false;
	std::exception_ptr m_error;
};

class HTTPMiner {
public:
	const MiningConfig &mining_config;
	const Currency &currency;

	http::Agent getwork_agent;
	std::unique_ptr<http::Request> getwork_request;
	http::Agent submit_agent;
	std::unique_ptr<http::Request> submit_request;
	platform::Timer getwork_retry;
	platform::Timer submit_retry;

	crypto::CryptoNightContext crypto_context;
	crypto::RandomXContext randomx_context;
	std::shared_ptr<const crypto::RandomXDataset> randomx_dataset_handle;
	std::unique_ptr<RandomXHashPool> randomx_hash_pool;
	BlockTemplate block{};
	api::cnd::GetBlockTemplate::Response block_response;
	api::cnd::GetCurrencyId::Response currencyid_response;
	bool need_currency_id = true;
	uint64_t nonce        = 0;  // we use lower 4 bytes as a nonce.
	Difficulty difficulty = 0;  // used as a flag to mine/not mine

	struct FoundBlock {
		BlockTemplate block;
		common::BinaryArray cm_nonce;  // cm, if not empty
		std::vector<crypto::CMBranchElement> cm_merkle_branch;
	};
	std::deque<FoundBlock> found_blocks;
	size_t blocks_submitted = 0;
	// In MM boast is included into reserved space in block
	// In CM boast is included into cm_nonce

	HTTPMiner(const MiningConfig &mining_config, const Currency &currency)
	    : mining_config(mining_config)
	    , currency(currency)
	    , getwork_agent(mining_config.bytecoind_ip, mining_config.bytecoind_port)
	    , submit_agent(mining_config.bytecoind_ip, mining_config.bytecoind_port)
	    , getwork_retry(std::bind(&HTTPMiner::send_getwork, this))
	    , submit_retry(std::bind(&HTTPMiner::send_submit, this)) {
		send_getwork();
	}
	bool on_idle() {
		if (difficulty == 0)
			return false;
		if (block_response.pow_algorithm == "randomx-v2" && !mining_config.cm &&
		    !mining_config.randomx_light)
			return on_randomx_idle();
		nonce++;
		BinaryArray pow_hashing_data;
		BinaryArray cm_nonce;
		std::vector<crypto::CMBranchElement> cm_merkle_branch;
		Hash cm_merkle_root;
		if (mining_config.cm) {
			cm_nonce.resize(cm_nonce.size() + 7);
			common::uint_le_to_bytes(cm_nonce.data() + 3, 7, nonce);
			cm_nonce.push_back(0);  // So that next symbol is UTF-8 rune start
			common::append(cm_nonce,
			    BinaryArray{mining_config.boast.data(), mining_config.boast.data() + mining_config.boast.size()});
			if (crypto::rand<uint32_t>() % 2) {
				cm_merkle_branch.push_back(
				    crypto::CMBranchElement{static_cast<uint8_t>(crypto::rand<uint32_t>() % 4), crypto::rand<Hash>()});
				const size_t count = crypto::rand<uint32_t>() % 4;
				for (size_t i = 0; i != count; ++i) {
					const size_t depth = cm_merkle_branch.back().depth + 1 + crypto::rand<uint32_t>() % 4;
					cm_merkle_branch.push_back(
					    crypto::CMBranchElement{static_cast<uint8_t>(depth), crypto::rand<Hash>()});
				}
			}
			cm_merkle_root =
			    crypto::tree_hash_from_cm_branch(cm_merkle_branch, block_response.cm_prehash, block_response.cm_path);
			common::append(pow_hashing_data, cm_nonce);
			common::append(pow_hashing_data, std::begin(cm_merkle_root.data), std::end(cm_merkle_root.data));
		} else {
			common::uint_le_to_bytes(block.root_block.nonce, 4, nonce);
			auto body_proxy  = get_body_proxy_from_template(block);
			pow_hashing_data = get_block_pow_hashing_data(block, body_proxy, currencyid_response.currency_id_blob);
		}
		Hash hash;
		if (block_response.pow_algorithm == "randomx-v2")
			hash = randomx_context.hash(
			    block_response.pow_seed_hash, pow_hashing_data.data(), pow_hashing_data.size());
		else
			hash = crypto_context.cn_slow_hash(pow_hashing_data.data(), pow_hashing_data.size());
		if (check_hash(hash, difficulty)) {
			common::console::set_text_color(common::console::BrightGreen);
			std::cout << "Miner found block !!!, will send ASAP" << std::endl;
			if (mining_config.cm) {
				std::cout << "    cm_nonce=" << common::to_hex(cm_nonce) << std::endl;
				std::cout << "    cm_merkle_root=" << cm_merkle_root << std::endl;
				for (const auto &cb : cm_merkle_branch)
					std::cout << "    cm_merkle_branch d=" << cb.depth << " h=" << cb.hash << std::endl;
			}
			common::console::set_text_color(common::console::Default);
			found_blocks.push_back(FoundBlock{block, cm_nonce, cm_merkle_branch});
			difficulty = 0;
			send_submit();
			return false;
		}
		return true;
	}
	bool on_randomx_idle() {
		if (!randomx_dataset_handle || randomx_dataset_handle->seed() != block_response.pow_seed_hash) {
			randomx_hash_pool.reset();
			randomx_dataset_handle = std::make_shared<crypto::RandomXDataset>(block_response.pow_seed_hash,
			    mining_config.randomx_init_threads, mining_config.randomx_large_pages);
			randomx_hash_pool =
			    std::make_unique<RandomXHashPool>(randomx_dataset_handle, mining_config.threads);
			std::cout << "RandomX full-memory dataset ready with " << mining_config.threads
			          << " hashing thread(s)" << std::endl;
		}
		std::vector<BinaryArray> inputs;
		std::vector<uint32_t> nonces;
		inputs.reserve(mining_config.threads);
		nonces.reserve(mining_config.threads);
		for (size_t i = 0; i != mining_config.threads; ++i) {
			++nonce;
			const uint32_t candidate_nonce = static_cast<uint32_t>(nonce);
			common::uint_le_to_bytes(block.root_block.nonce, 4, candidate_nonce);
			nonces.push_back(candidate_nonce);
			const auto body_proxy = get_body_proxy_from_template(block);
			inputs.push_back(
			    get_block_pow_hashing_data(block, body_proxy, currencyid_response.currency_id_blob));
		}
		const std::vector<Hash> hashes = randomx_hash_pool->hash(std::move(inputs));
		for (size_t i = 0; i != hashes.size(); ++i) {
			if (!check_hash(hashes[i], difficulty))
				continue;
			common::uint_le_to_bytes(block.root_block.nonce, 4, nonces[i]);
			common::console::set_text_color(common::console::BrightGreen);
			std::cout << "Miner found RandomX block !!!, will send ASAP" << std::endl;
			common::console::set_text_color(common::console::Default);
			found_blocks.push_back(FoundBlock{block, BinaryArray{}, {}});
			difficulty = 0;
			send_submit();
			return false;
		}
		return true;
	}
	void send_submit() {
		if (found_blocks.empty() || submit_request)
			return;
		api::cnd::SubmitBlock::Request req;
		req.blocktemplate_blob       = seria::to_binary(found_blocks.front().block);
		req.cm_nonce                 = found_blocks.front().cm_nonce;
		req.cm_merkle_branch         = found_blocks.front().cm_merkle_branch;
		http::RequestBody req_header = json_rpc::create_request(api::cnd::url(), api::cnd::SubmitBlock::method(), req);
		submit_request               = std::make_unique<http::Request>(submit_agent, std::move(req_header),
            [&](http::ResponseBody &&response) {
                submit_request.reset();
                api::cnd::SubmitBlock::Response resp;
                json_rpc::Error err_resp;
                if (!json_rpc::parse_response(response.body, resp, err_resp)) {
                    common::console::set_text_color(common::console::BrightRed);
                    std::cout << "Json Error submitting block code=" << err_resp.code << " msg=" << err_resp.message
                              << std::endl;
                    need_currency_id = true;  // In case it changed due to consensus update
                    common::console::set_text_color(common::console::Default);
                    if (!found_blocks.empty())  // Should not be empty, but...
                        found_blocks.pop_front();
                    send_submit();
                } else {
                    common::console::set_text_color(common::console::BrightGreen);
                    std::cout << "Block submitted " << resp.block_header.hash << " orphan_status=" << resp.orphan_status
                              << std::endl;
                    common::console::set_text_color(common::console::Default);
                    if (!found_blocks.empty()) {  // Should not be empty, but...
                        found_blocks.pop_front();
                        blocks_submitted += 1;
                    }
                    if (mining_config.blocks_limit != 0 && blocks_submitted >= mining_config.blocks_limit) {
                        platform::EventLoop::cancel_current();
                    } else {
                        send_submit();
                    }
                }
            },
            [&](std::string err) { submit_retry.once(5); });
	}
	void send_getcurrency_id() {
		api::cnd::GetCurrencyId::Request req{};
		http::RequestBody req_header =
		    json_rpc::create_request(api::cnd::url(), api::cnd::GetCurrencyId::method(), req);
		std::cout << "Miner send " << api::cnd::GetCurrencyId::method() << std::endl;
		getwork_request = std::make_unique<http::Request>(getwork_agent, std::move(req_header),
		    [&](http::ResponseBody &&response) {
			    getwork_request.reset();
			    api::cnd::GetCurrencyId::Response resp;
			    json_rpc::Error err_resp;
			    if (json_rpc::parse_response(response.body, resp, err_resp)) {
				    currencyid_response = resp;
				    need_currency_id    = false;
				    std::cout << "Miner received currrency id=" << resp.currency_id_blob << std::endl;
				    getwork_retry.once(0.1f);
			    } else {
				    getwork_retry.once(10);
				    std::cout << "Json Error getting currency id (will retry in 10 sec) code=" << err_resp.code
				              << " msg=" << err_resp.message << std::endl;
			    }
		    },
		    [&](std::string err) {
			    getwork_retry.once(5);
			    std::cout << "Network Error getting currency id (will retry in 5 sec) err=" << err << std::endl;
		    });
	}
	void install_block_template(api::cnd::GetBlockTemplate::Response resp) {
		if (resp.pow_algorithm != "cryptonight" && resp.pow_algorithm != "randomx-v2")
			throw std::runtime_error("unsupported proof-of-work algorithm '" + resp.pow_algorithm + "'");
		if (resp.difficulty == 0)
			throw std::runtime_error("zero mining difficulty");
		if (resp.height == 0 || resp.height > parameters::MAX_BLOCK_NUMBER)
			throw std::runtime_error("candidate height is out of bounds");
		if (resp.top_block_hash == Hash{})
			throw std::runtime_error("top block hash is zero");
		if (resp.blocktemplate_blob.empty() ||
		    resp.blocktemplate_blob.size() > parameters::BLOCK_CAPACITY_VOTE_MAX + parameters::MAX_HEADER_SIZE)
			throw std::runtime_error("block template size is out of bounds");
		if (resp.pow_algorithm == "randomx-v2" && resp.pow_seed_hash == Hash{})
			throw std::runtime_error("RandomX seed hash is zero");
		if (resp.pow_algorithm == "cryptonight" && resp.pow_seed_hash != Hash{})
			throw std::runtime_error("CryptoNight template carries an unexpected RandomX seed");
		if (!mining_config.cm && !mining_config.boast.empty()) {
			if (resp.reserved_offset > resp.blocktemplate_blob.size() ||
			    mining_config.boast.size() > resp.blocktemplate_blob.size() - resp.reserved_offset)
				throw std::runtime_error("reserved nonce range is outside the block template");
			for (size_t i = 0; i != mining_config.boast.size(); ++i)
				resp.blocktemplate_blob[resp.reserved_offset + i] = mining_config.boast[i];
		}

		BlockTemplate candidate;
		seria::from_binary(candidate, resp.blocktemplate_blob);
		if (candidate.previous_block_hash != resp.top_block_hash)
			throw std::runtime_error("template parent does not match top_block_hash");
		if (candidate.base_transaction.inputs.size() != 1)
			throw std::runtime_error("template coinbase input count is not one");
		const auto *coinbase = boost::get<InputCoinbase>(&candidate.base_transaction.inputs.front());
		if (coinbase == nullptr || coinbase->height != resp.height)
			throw std::runtime_error("template coinbase height does not match response height");
		const bool expected_randomx = currency.uses_randomx(candidate.major_version, resp.height);
		if ((resp.pow_algorithm == "randomx-v2") != expected_randomx)
			throw std::runtime_error("proof-of-work algorithm does not match template version and height");

		block_response = std::move(resp);
		if (block_response.pow_algorithm != "randomx-v2") {
			randomx_hash_pool.reset();
			randomx_dataset_handle.reset();
		}
		block = std::move(candidate);
		set_root_extra_to_solo_mining_tag(block);
		difficulty = block_response.difficulty;
		nonce      = crypto::rand<uint32_t>();
		if (mining_config.miner_secret != Hash{}) {
			block.timestamp = block.root_block.timestamp =
			    1550000000 + block_response.height * parameters::DIFFICULTY_TARGET;
			nonce = 0;
		}
		std::cout << "Miner received getblocktemplate difficulty=" << difficulty
		          << " algorithm=" << block_response.pow_algorithm
		          << " top_block_hash=" << block_response.top_block_hash
		          << " #tx=" << block.transaction_hashes.size() << std::endl;
		for (const auto &ha : block.transaction_hashes)
			std::cout << "tx=" << ha << std::endl;
		getwork_retry.once(0.1f);
	}
	void send_getwork() {
		if (need_currency_id) {
			return send_getcurrency_id();
		}
		api::cnd::GetBlockTemplate::Request req{};
		req.wallet_address = mining_config.mining_address;
		req.miner_secret   = mining_config.miner_secret;
		if (!mining_config.cm)
			req.reserve_size = mining_config.boast.size();
		req.top_block_hash           = block_response.top_block_hash;
		req.transaction_pool_version = block_response.transaction_pool_version;
		http::RequestBody req_header =
		    json_rpc::create_request(api::cnd::url(), api::cnd::GetBlockTemplate::method(), req);
		std::cout << "Miner send " << api::cnd::GetBlockTemplate::method()
		          << " top_block_hash=" << block_response.top_block_hash << std::endl;
		getwork_request = std::make_unique<http::Request>(getwork_agent, std::move(req_header),
		    [&](http::ResponseBody &&response) {
			    getwork_request.reset();
			    api::cnd::GetBlockTemplate::Response resp;
			    json_rpc::Error err_resp;
			    if (json_rpc::parse_response(response.body, resp, err_resp)) {
				    try {
					    install_block_template(std::move(resp));
				    } catch (const std::exception &ex) {
					    difficulty = 0;
					    std::cout << "Rejected block template: " << common::what(ex)
					              << " (will retry in 1 sec)" << std::endl;
					    getwork_retry.once(1);
				    }
			    } else {
				    getwork_retry.once(10);
				    std::cout << "Json Error getting blocktemplate (will retry in 10 sec) code=" << err_resp.code
				              << " msg=" << err_resp.message << std::endl;
			    }
		    },
		    [&](std::string err) {
			    getwork_retry.once(5);
			    std::cout << "Network Error getting blocktemplate (will retry in 5 sec) err=" << err << std::endl;
		    });
	}
	static int main(int argc, const char *argv[]) try {
		common::console::UnicodeConsoleSetup console_setup;
		common::console::set_text_color(common::console::BrightRed);
		std::cout << "This miner is VERY INEFFICIENT and should be only used by team only for testnet" << std::endl;
		common::console::set_text_color(common::console::Default);

		common::CommandLine cmd(argc, argv);
		if (cmd.show_help(Config::prepare_usage(USAGE).c_str(), cn::app_version()))
			return 0;
		MiningConfig mining_config(cmd);
		Config config(cmd);
		Currency currency(config);
		if (cmd.show_errors())
			return 1;
		if (mining_config.mining_address.empty()) {
			std::cout << "--wallet-address=<addr> option is mandatory" << std::endl;
			return 1;
		}

		boost::asio::io_context io;
		platform::EventLoop run_loop(io);

		HTTPMiner miner(mining_config, currency);
		while (!io.stopped()) {
			io.poll();
			if (!miner.on_idle())
				io.run_one();
		}
		return 0;
	} catch (const std::exception &ex) {
		std::cout << common::what(ex) << std::endl;
		return 1;
	}
};

int main(int argc, const char *argv[]) { return HTTPMiner::main(argc, argv); }
