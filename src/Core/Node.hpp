// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <chrono>
#include <functional>
#include <iostream>
#include "BlockChainState.hpp"
#include "http/BinaryRpc.hpp"
#include "http/JsonRpc.hpp"
#include "p2p/P2P.hpp"
#include "p2p/P2PProtocolBasic.hpp"
#include "rpc_api.hpp"

namespace http {
class Server;
class Client;
}  // namespace http
namespace platform {
class PreventSleep;
}
namespace cn {

class Node {
public:
	typedef std::function<bool(Node *, http::Client *, http::RequestBody &&, json_rpc::Request &&, std::string &)>
	    JSONRPCHandlerFunction;
	typedef std::function<bool(Node *, http::Client *, common::IInputStream &, json_rpc::Request &&, std::string &)>
	    BINARYRPCHandlerFunction;

	explicit Node(logging::ILogger &, const Config &, BlockChainState &);
	~Node();
	bool on_idle();

	// binary method
	bool on_sync_blocks(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::SyncBlocks::Request &&,
	    api::cnd::SyncBlocks::Response &);
	bool on_sync_blocks_bin(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::SyncBlocks::Request &&, api::cnd::SyncBlocks::ResponseCompact &);
	bool on_sync_mempool(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::SyncMemPool::Request &&,
	    api::cnd::SyncMemPool::Response &);

	bool on_get_raw_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetRawTransaction::Request &&, api::cnd::GetRawTransaction::Response &);
	bool on_get_raw_block(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::GetRawBlock::Request &&,
	    api::cnd::GetRawBlock::Response &);
	bool on_get_block_header(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetBlockHeader::Request &&, api::cnd::GetBlockHeader::Response &);

	api::cnd::GetStatus::Response create_status_response() const;
	api::cnd::GetStatistics::Response create_statistics_response(const api::cnd::GetStatistics::Request &) const;
	// json_rpc_node
	bool on_get_status(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::GetStatus::Request &&,
	    api::cnd::GetStatus::Response &);
	bool on_get_onyx_supply_audit(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetOnyxSupplyAudit::Request &&, api::cnd::GetOnyxSupplyAudit::Response &);
	bool on_get_onyx_standard_program_state(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetOnyxStandardProgramState::Request &&, api::cnd::GetOnyxStandardProgramState::Response &);
	bool on_get_statistics(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetStatistics::Request &&, api::cnd::GetStatistics::Response &);
	bool on_get_archive(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::GetArchive::Request &&,
	    api::cnd::GetArchive::Response &);
	bool on_get_random_outputs(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetRandomOutputs::Request &&, api::cnd::GetRandomOutputs::Response &);
	bool on_send_transaction(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::SendTransaction::Request &&, api::cnd::SendTransaction::Response &);
	bool on_check_sendproof(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::CheckSendproof::Request &&, api::cnd::CheckSendproof::Response &);
	bool on_getblocktemplate(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetBlockTemplate::Request &&r, api::cnd::GetBlockTemplate::Response &);
	void getblocktemplate(const api::cnd::GetBlockTemplate::Request &, api::cnd::GetBlockTemplate::Response &);
	bool on_get_currency_id(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetCurrencyId::Request &&, api::cnd::GetCurrencyId::Response &);
	void submit_block(const BinaryArray &blockblob, api::BlockHeader *info);
	bool on_submitblock(http::Client *, http::RequestBody &&, json_rpc::Request &&, api::cnd::SubmitBlock::Request &&,
	    api::cnd::SubmitBlock::Response &);
	bool on_submitblock_legacy(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::SubmitBlockLegacy::Request &&, api::cnd::SubmitBlockLegacy::Response &);
	bool on_get_last_block_header(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetLastBlockHeaderLegacy::Request &&, api::cnd::GetLastBlockHeaderLegacy::Response &);
	bool on_get_block_header_by_hash(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetBlockHeaderByHashLegacy::Request &&, api::cnd::GetBlockHeaderByHashLegacy::Response &);
	bool on_get_block_header_by_height(http::Client *, http::RequestBody &&, json_rpc::Request &&,
	    api::cnd::GetBlockHeaderByHeightLegacy::Request &&, api::cnd::GetBlockHeaderByHeightLegacy::Response &);

	bool on_json_rpc(http::Client *, http::RequestBody &&, http::ResponseBody &);
	bool on_binary_rpc(http::Client *, http::RequestBody &&, http::ResponseBody &);

	BlockChainState &m_block_chain;
	const Config &m_config;

	static void export_static_sync_blocks(const BlockChainState &block_chain, const std::string &folder);

protected:
	std::unique_ptr<http::Server> m_api;
	std::unique_ptr<platform::PreventSleep> m_prevent_sleep;
	struct LongPollClient {
		http::Client *original_who = nullptr;
		http::RequestBody original_request;
		json_rpc::Request original_json_request;
		api::cnd::GetStatus::Request original_get_status;
	};
	std::list<LongPollClient> m_long_poll_http_clients;
	void advance_long_poll();

	logging::LoggerRef m_log;
	bool m_onyx_supply_audit_cache_valid = false;
	Hash m_onyx_supply_audit_cache_tip{};
	api::cnd::GetOnyxSupplyAudit::Response m_onyx_supply_audit_cache_response;
	const std::unique_ptr<PeerDB> m_peer_db;  // compilation speed optimization
	P2P m_p2p;
	platform::UDPMulticast multicast;
	platform::Timer m_multicast_timer;
	void send_multicast();
	void on_multicast(const std::string &addr, const unsigned char *data, size_t size);

	class P2PProtocolBytecoin;
	const Timestamp m_start_time;
	platform::Timer m_commit_timer;
	void db_commit();
	struct DandelionPending {
		TransactionDesc desc;
		P2PProtocolBytecoin *stem_peer = nullptr;
		std::chrono::steady_clock::time_point deadline;
	};
	std::map<Hash, DandelionPending> m_dandelion_pending;
	P2PProtocolBytecoin *m_dandelion_stem_peer = nullptr;
	std::map<P2PProtocolBytecoin *, int> m_dandelion_peer_scores;
	std::chrono::steady_clock::time_point m_dandelion_epoch_end{};
	platform::Timer m_dandelion_embargo_timer;

	bool check_trust(const p2p::ProofOfTrust &);
	Timestamp m_last_stat_request_time = 0;
	// Prevent replay attacks by only trusting requests with timestamp > than previous request

	struct DownloadInfo {
		size_t chain_counter                 = 0;
		P2PProtocolBytecoin *who_downloading = nullptr;
		Height expected_height               = 0;  // Set during download
		bool preparing                       = false;
	};
	std::map<Hash, DownloadInfo> chain_blocks;
	void remove_chain_block(std::map<Hash, DownloadInfo>::iterator it);
	std::map<Hash, P2PProtocolBytecoin *> downloading_transactions;

	class P2PProtocolBytecoin : public P2PProtocolBasic {
		Node *const m_node;
		void after_handshake();

		bool m_chain_request_sent = false;
		platform::Timer m_chain_timer;
		platform::Timer m_download_timer;
		size_t m_downloading_block_count = 0;
		void on_chain_timer();
		void on_download_timer();
		Hash m_previous_chain_hash;
		std::deque<std::map<Hash, DownloadInfo>::iterator> m_chain;
		size_t m_chain_start_height = 0;

		bool m_syncpool_request_sent = false;
		std::pair<Amount, Hash> syncpool_start{std::numeric_limits<Amount>::max(), Hash{}};
		size_t m_downloading_transaction_count = 0;
		platform::Timer m_syncpool_timer;
		platform::Timer m_download_transactions_timer;
		std::map<Hash, TransactionDesc> m_transaction_descs;
		std::map<Hash, uint8_t> m_stem_transaction_hops;
		void on_syncpool_timer();
		void on_download_transactions_timer();
		void transaction_download_finished(const Hash &tid, bool success);
		bool on_transaction_descs(const std::vector<TransactionDesc> &descs, uint8_t stem_hop = 0);

	protected:
		void on_disconnect(const std::string &ban_reason) override;

		CoreSyncData get_my_sync_data() const override;
		std::vector<NetworkAddress> get_peers_to_share() const override;
		std::vector<PeerlistEntryLegacy> get_legacy_peers_to_share() const override;
		std::vector<AnonymityNetworkAddress> get_anonymity_peers_to_share() const override;

		void on_first_message_after_handshake() override;
		void on_msg_handshake(p2p::Handshake::Request &&) override;
		void on_msg_handshake(p2p::Handshake::Response &&) override;
		void on_msg_notify_request_chain(p2p::GetChain::Request &&) override;
		void on_msg_notify_request_chain(p2p::GetChain::Response &&) override;
		void on_msg_notify_request_objects(p2p::GetObjects::Request &&) override;
		void on_msg_notify_request_objects(p2p::GetObjects::Response &&) override;
		void on_msg_notify_request_tx_pool(p2p::SyncPool::Request &&) override;
		void on_msg_notify_request_tx_pool(p2p::SyncPool::Response &&) override;
		void on_msg_timed_sync(p2p::TimedSync::Notify &&) override;
		void on_msg_notify_new_block(p2p::RelayBlock::Notify &&) override;
		void on_msg_notify_new_transactions(p2p::RelayTransactions::Notify &&) override;
		void on_msg_notify_stem_transaction(p2p::StemTransaction::Notify &&) override;
		void on_msg_notify_checkpoint(p2p::Checkpoint::Notify &&) override;
#if bytecoin_ALLOW_DEBUG_COMMANDS
		void on_msg_stat_info(p2p::GetStatInfo::Request &&) override;
#endif
	public:
		explicit P2PProtocolBytecoin(Node *node, P2PClient *client);
		~P2PProtocolBytecoin() override;
		void advance_chain();
		void advance_blocks();
		bool on_idle(std::chrono::steady_clock::time_point idle_start);
		void advance_transactions();
	};
	std::unique_ptr<P2PProtocol> client_factory(P2PClient *client) {
		return std::make_unique<P2PProtocolBytecoin>(this, client);
	}

	std::chrono::steady_clock::time_point log_request_timestamp;
	std::chrono::steady_clock::time_point log_response_timestamp;

	void advance_all_downloads();
	std::set<P2PProtocolBytecoin *> m_broadcast_protocols;

	BlockPreparatorMulticore m_pow_checker;
	// TODO - periodically clear m_pow_checker of blocks that were not asked

	void broadcast(P2PProtocolBytecoin *exclude, const BinaryArray &data);
	void relay_transaction_dandelion(const TransactionDesc &desc, P2PProtocolBytecoin *source, uint8_t hop);
	void fluff_transaction(const TransactionDesc &desc);
	void observe_fluff(const std::vector<TransactionDesc> &descs, P2PProtocolBytecoin *source);
	void on_dandelion_embargo();
	void schedule_dandelion_embargo();
	void reward_dandelion_peer(P2PProtocolBytecoin *peer);
	void penalize_dandelion_peer(P2PProtocolBytecoin *peer);
	void dandelion_peer_disconnected(P2PProtocolBytecoin *peer);
	P2PProtocolBytecoin *select_dandelion_stem_peer(P2PProtocolBytecoin *exclude);

	void fill_cors(const http::RequestBody &req, http::ResponseBody &res);
	bool on_api_http_request(http::Client *, http::RequestBody &&, http::ResponseBody &);
	void on_api_http_disconnect(http::Client *);

	static std::unordered_map<std::string, JSONRPCHandlerFunction> m_jsonrpc_handlers;
	static const std::unordered_map<std::string, BINARYRPCHandlerFunction> m_binaryrpc_handlers;

	void fill_transaction_info(const TransactionPrefix &tx, api::Transaction *api_tx,
	    std::vector<std::vector<api::Output>> *mixed_outputs) const;
	std::vector<Hash> fill_sync_blocks_subchain(api::cnd::SyncBlocks::Request &, Height *start_height) const;
	void check_sendproof(const BinaryArray &data_inside_base58, api::cnd::CheckSendproof::Response &resp) const;
	void check_sendproof(const SendproofLegacy &sp, api::cnd::CheckSendproof::Response &resp) const;
};

}  // namespace cn
