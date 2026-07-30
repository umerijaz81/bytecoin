// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "KVBinaryInputStream.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include "KVBinaryCommon.hpp"
#include "common/Invariant.hpp"
#include "common/Streams.hpp"
#include "common/Varint.hpp"

using namespace common;
using namespace cn;
using namespace seria;

namespace {

template<typename T>
T read_pod(common::IInputStream &s) {
	unsigned char buf[sizeof(T)];
	s.read(buf, sizeof(T));
	return common::uint_le_from_bytes<typename std::make_unsigned<T>::type>(buf, sizeof(T));
}

template<typename T, typename JsonT = T>
JsonValue read_pod_json(common::IInputStream &s) {
	JsonValue jv;
	jv = static_cast<JsonT>(read_pod<T>(s));
	return jv;
}

template<typename T, typename JsonT>
JsonValue read_integer_json(common::IInputStream &s) {
	return read_pod_json<T, JsonT>(s);
}

size_t read_kv_varint(common::IInputStream &s) {
	uint8_t b         = s.read_byte();
	uint8_t size_mask = b & PORTABLE_RAW_SIZE_MARK_MASK;
	size_t bytes_left = 0;

	switch (size_mask) {
	case PORTABLE_RAW_SIZE_MARK_BYTE:
		bytes_left = 0;
		break;
	case PORTABLE_RAW_SIZE_MARK_WORD:
		bytes_left = 1;
		break;
	case PORTABLE_RAW_SIZE_MARK_DWORD:
		bytes_left = 3;
		break;
	case PORTABLE_RAW_SIZE_MARK_INT64:
		bytes_left = 7;
		break;
	}

	uint64_t value = b;

	for (size_t i = 1; i <= bytes_left; ++i) {
		size_t n = s.read_byte();
		value |= n << (i * 8);
	}

	value >>= 2;
	if ((size_mask == PORTABLE_RAW_SIZE_MARK_WORD && value <= 63) ||
	    (size_mask == PORTABLE_RAW_SIZE_MARK_DWORD && value <= 16383) ||
	    (size_mask == PORTABLE_RAW_SIZE_MARK_INT64 && value <= 1073741823))
		throw std::runtime_error("KVBinaryInputStream non-canonical size encoding");
	return integer_cast<size_t>(value);
}

std::string read_string(common::IInputStream &s) {
	auto size = read_kv_varint(s);
	if (size > KV_BINARY_MAX_STRING_SIZE)
		throw std::runtime_error("KVBinaryInputStream string too large");
	std::string str;
	s.read(str, size);
	return str;
}

JsonValue read_string_json(common::IInputStream &s) { return JsonValue(read_string(s)); }

void read_name(common::IInputStream &s, std::string &name) {
	uint8_t len = s.read_byte();  // TODO - what if name size >?
	s.read(name, len);
}

JsonValue load_value(size_t level, common::IInputStream &stream, uint8_t type, size_t &values_left);
JsonValue load_object(size_t level, common::IInputStream &stream, size_t &values_left);
JsonValue load_entry(size_t level, common::IInputStream &stream, size_t &values_left);
JsonValue load_array(
    size_t level, common::IInputStream &stream, uint8_t item_type, size_t &values_left);

void consume_value_budget(size_t &values_left) {
	if (values_left == 0)
		throw std::runtime_error("KVBinaryInputStream value limit exceeded");
	--values_left;
}

JsonValue load_object(size_t level, common::IInputStream &stream, size_t &values_left) {
	if (level > KV_BINARY_MAX_NESTING_DEPTH)
		throw std::runtime_error("KVBinaryInputStream depth too high");
	consume_value_budget(values_left);
	JsonValue sec(JsonValue::OBJECT);
	size_t count = read_kv_varint(stream);
	if (count > KV_BINARY_MAX_CONTAINER_ENTRIES || count > values_left)
		throw std::runtime_error("KVBinaryInputStream object too large");
	std::string name;

	while (count--) {
		read_name(stream, name);
		if (sec.contains(name))
			throw std::runtime_error("KVBinaryInputStream duplicate object key");
		sec.insert(name, load_entry(level, stream, values_left));
	}

	return sec;
}

JsonValue load_value(size_t level, common::IInputStream &stream, uint8_t type, size_t &values_left) {
	consume_value_budget(values_left);
	switch (type) {
	case BIN_KV_SERIALIZE_TYPE_INT64:
		return read_integer_json<int64_t, int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT32:
		return read_integer_json<int32_t, int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT16:
		return read_integer_json<int16_t, int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_INT8:
		return read_integer_json<int8_t, int64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT64:
		return read_integer_json<uint64_t, uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT32:
		return read_integer_json<uint32_t, uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT16:
		return read_integer_json<uint16_t, uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_UINT8:
		return read_integer_json<uint8_t, uint64_t>(stream);
	case BIN_KV_SERIALIZE_TYPE_DOUBLE: {
		throw std::runtime_error("KVBinaryInputStream double serialization is not supported");
		//		double dv = 0; // TODO - double as binary is a BUG
		//		stream.read(&dv, sizeof(dv));
		//		return dv;
	}
	case BIN_KV_SERIALIZE_TYPE_BOOL:
		{
			const uint8_t value = stream.read_byte();
			if (value > 1)
				throw std::runtime_error("KVBinaryInputStream invalid boolean");
			return JsonValue(value != 0);
		}
	case BIN_KV_SERIALIZE_TYPE_STRING:
		return read_string_json(stream);
	case BIN_KV_SERIALIZE_TYPE_OBJECT:
		++values_left;  // The nested container accounts for itself.
		return load_object(level + 1, stream, values_left);
	case BIN_KV_SERIALIZE_TYPE_ARRAY:
		++values_left;  // The nested container accounts for itself.
		return load_array(level + 1, stream, type, values_left);
	default:
		throw std::runtime_error("KVBinaryInputStream Unknown data type");
	}
}

JsonValue load_entry(size_t level, common::IInputStream &stream, size_t &values_left) {
	if (level > KV_BINARY_MAX_NESTING_DEPTH)
		throw std::runtime_error("KVBinaryInputStream depth too high");
	uint8_t type;
	stream.read(&type, 1);

	if (type & BIN_KV_SERIALIZE_FLAG_ARRAY) {
		type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;
		return load_array(level + 1, stream, type, values_left);
	}

	return load_value(level, stream, type, values_left);
}

JsonValue load_array(size_t level, common::IInputStream &stream, uint8_t item_type, size_t &values_left) {
	if (level > KV_BINARY_MAX_NESTING_DEPTH)
		throw std::runtime_error("KVBinaryInputStream depth too high");
	if (item_type < BIN_KV_SERIALIZE_TYPE_INT64 || item_type > BIN_KV_SERIALIZE_TYPE_ARRAY ||
	    item_type == BIN_KV_SERIALIZE_TYPE_DOUBLE)
		throw std::runtime_error("KVBinaryInputStream invalid array item type");
	consume_value_budget(values_left);
	JsonValue arr(JsonValue::ARRAY);
	size_t count = read_kv_varint(stream);
	if (count > KV_BINARY_MAX_CONTAINER_ENTRIES || count > values_left)
		throw std::runtime_error("KVBinaryInputStream array too large");

	while (count--) {
		if (item_type == BIN_KV_SERIALIZE_TYPE_ARRAY) {
			uint8_t type;
			stream.read(&type, 1);
			if ((type & BIN_KV_SERIALIZE_FLAG_ARRAY) == 0)
				throw std::runtime_error("KVBinaryInputStream Incorrect array of array encoding");
			type &= ~BIN_KV_SERIALIZE_FLAG_ARRAY;

			arr.push_back(load_array(level + 1, stream, type, values_left));
		} else
			arr.push_back(load_value(level, stream, item_type, values_left));
	}

	return arr;
}

JsonValue parse_binary(common::IInputStream &stream) {
	KVBinaryStorageBlockHeader hdr;
	hdr.m_signature_a = read_pod<uint32_t>(stream);
	hdr.m_signature_b = read_pod<uint32_t>(stream);
	stream.read(&hdr.m_ver, 1);

	if (hdr.m_signature_a != PORTABLE_STORAGE_SIGNATUREA || hdr.m_signature_b != PORTABLE_STORAGE_SIGNATUREB)
		throw std::runtime_error("KVBinaryInputStream invalid binary storage signature");
	if (hdr.m_ver != PORTABLE_STORAGE_FORMAT_VER)
		throw std::runtime_error("KVBinaryInputStream unknown binary storage format version");

	size_t values_left = KV_BINARY_MAX_TOTAL_VALUES;
	return load_object(0, stream, values_left);
}
}  // namespace

KVBinaryInputStream::KVBinaryInputStream(common::IInputStream &strm) : JsonInputStreamValue(value_storage, true) {
	is_json_value = false;  // We use JsonInputStreamValue only as a convenient storage
	// We init parent with & of value_storage, then set storage
	value_storage = parse_binary(strm);
}

bool KVBinaryInputStream::seria_v(common::BinaryArray &value) {
	std::string str;
	if (!seria_v(str))
		return false;
	value.assign(str.data(), str.data() + str.size());
	return true;
}

bool KVBinaryInputStream::binary(void *value, size_t size) {
	if (size == 0)  // This is important case, do not remove
		return true;
	std::string str;
	if (!seria_v(str))
		return false;
	if (str.size() != size)
		throw std::runtime_error("KVBinaryInputStream binary value size mismatch");
	memcpy(value, str.data(), size);
	return true;
}
