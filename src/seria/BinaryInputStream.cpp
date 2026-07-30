// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "BinaryInputStream.hpp"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include "common/Invariant.hpp"
#include "common/Math.hpp"
#include "common/Streams.hpp"

using namespace common;

using namespace seria;

void BinaryInputStream::check_sized_value(size_t size, const char *kind) const {
	if (memory_stream != nullptr && size > memory_stream->size())
		throw std::runtime_error(std::string("BinaryInputStream ") + kind + " size exceeds remaining input");
}

bool BinaryInputStream::begin_array(size_t &size, bool fixed_size) {
	if (!fixed_size) {
		size = stream.read_varint<size_t>();
		check_sized_value(size, "array");
	}
	return true;
}

bool BinaryInputStream::begin_map(size_t &size) {
	size = stream.read_varint<size_t>();
	check_sized_value(size, "map");
	return true;
}

void BinaryInputStream::next_map_key(std::string &name) { ser(name, *this); }

bool BinaryInputStream::seria_v(int64_t &value) {
	value = static_cast<int64_t>(stream.read_varint<uint64_t>());
	return true;
}

bool BinaryInputStream::seria_v(uint64_t &value) {
	value = stream.read_varint<uint64_t>();
	return true;
}

bool BinaryInputStream::seria_v(bool &value) {
	value = (stream.read_byte() != 0);
	return true;
}

bool BinaryInputStream::seria_v(BinaryArray &value) {
	auto size = stream.read_varint<size_t>();
	check_sized_value(size, "binary");
	stream.read(value, size);
	return true;
}

bool BinaryInputStream::seria_v(std::string &value) {
	auto size = stream.read_varint<size_t>();
	check_sized_value(size, "string");
	stream.read(value, size);
	return true;
}

bool BinaryInputStream::binary(void *value, size_t size) {
	stream.read(value, size);
	return true;
}
