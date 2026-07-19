// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <deque>
#include <map>
#include <memory>
#include "RequestParser.hpp"
#include "common/MemoryStreams.hpp"
#include "platform/Network.hpp"
#include "types.hpp"

namespace http {

class Client {
public:
	typedef std::function<void()> handler;
	static constexpr size_t MAX_REQUEST_BODY_SIZE = 4 * 1024 * 1024;
	static constexpr float HEADER_TIMEOUT_SECONDS = 5.0f;
	static constexpr float BODY_TIMEOUT_SECONDS   = 30.0f;

	explicit Client();

private:
	void write(ResponseBody &&response);
	void disconnect();
	bool read_next(RequestBody &request);
	void start_request_timeout();
	void on_request_timeout();

	void clear();
	friend class Server;

	common::CircularBuffer buffer;
	std::deque<common::StringStream> responses;

	http::RequestHeader request;
	http::RequestParser parser;
	bool receiving_body;
	common::StringStream receiving_body_stream;

	bool waiting_write_response;

	void advance_state(bool called_from_runloop);
	void write();
	void on_disconnect();

	handler r_handler;
	handler d_handler;

	platform::Timer request_timer;
	platform::TCPSocket sock;
	bool keep_alive;
};

}  // namespace http
