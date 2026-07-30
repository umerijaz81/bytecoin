// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for
// details.

#include "test_json.hpp"

//#include <cstddef>
#include <fstream>
#include <iostream>
#include <vector>
#include "common/Base64.hpp"
#include "common/Invariant.hpp"
#include "common/JsonValue.hpp"
#include "platform/PathTools.hpp"

void test_json(const std::string &filename, bool should_be) {
	std::string content;
	if (!platform::load_file(filename, content))
		throw std::runtime_error("test file not found " + filename);
	bool success = false;
	try {
		common::JsonValue val = common::JsonValue::from_string(content);
		success               = true;
	} catch (const std::exception &) {
		//		std::cout << filename << " fail reason: " << common::what(ex) <<
		// std::endl;
	}
	if (success != should_be)
		throw std::runtime_error("test case failed " + filename);
}

static std::map<std::string, uint64_t> cases1{
    {"20000000000000000000000000000000E-31", 2U},
    {"0.000000000000000000000000000000003E33", 3U},
    {"-0.00E1024", 0U},
    {"0.00E-1024", 0U},
    {"92233720368547758060.00E-1", 9223372036854775806U},
    {"922337203685477580.6E1", 9223372036854775806U},
    {"184467440737095516150E-1", 18446744073709551615U},
    {"1844674407370955161.5E1", 18446744073709551615U},

    {"0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001811234E206",
        1811234},
};

static std::map<std::string, int64_t> cases2{
    {"20000000000000000000000000000000E-31", 2},
    {"-20000000000000000000000000000000.0E-31", -2},
    {"-0.00E1024", 0},
    {"0.00E-1024", 0},
    {"0.000000000000000000000000000000003E33", 3},
    {"-92233720368547758070.00E-1", -9223372036854775807},
    {"-922337203685477580.7E1", -9223372036854775807},
    {"0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001811234E206",
        1811234},
};

void test_json(const std::string &test_vectors_folder) {
	common::BinaryArray all_bytes(256);
	for (size_t i = 0; i != all_bytes.size(); ++i)
		all_bytes[i] = static_cast<uint8_t>(i);
	common::BinaryArray decoded;
	invariant(common::base64::decode(common::base64::encode(all_bytes), &decoded) &&
	              decoded == all_bytes,
	    "canonical Base64 round trip failed");
	const std::map<std::string, std::string> base64_vectors{
	    {"", ""}, {"Zg==", "f"}, {"Zm8=", "fo"}, {"Zm9v", "foo"}, {"dXNlcjoxMTE=", "user:111"}};
	for (const auto &vector : base64_vectors) {
		decoded.assign(1, 0xff);
		invariant(common::base64::decode(vector.first, &decoded) &&
		              std::string(decoded.begin(), decoded.end()) == vector.second,
		    "valid canonical Base64 was rejected");
	}
	const std::vector<std::string> invalid_base64{
	    "Zg", "=m9v", "Z=9v", "Zm=v", "Zg=A", "Zg==AAAA", "Zh==", "Zm9=", "-w==", "_w==", "!!!!",
	    "Zm 9v"};
	for (const std::string &invalid : invalid_base64) {
		decoded.assign(1, 0xff);
		invariant(!common::base64::decode(invalid, &decoded) && decoded.empty(),
		    "malformed or noncanonical Base64 was accepted");
	}
	invariant(!common::base64::decode("Zg==", nullptr), "Base64 decoder accepted a null output");

	const auto parses = [](const std::string &source) {
		try {
			common::JsonValue::from_string(source);
			return true;
		} catch (const std::exception &) {
			return false;
		}
	};
	const std::string maximum_depth = std::string(common::JsonValue::MAX_NESTING_DEPTH, '[') + "0" +
	                                  std::string(common::JsonValue::MAX_NESTING_DEPTH, ']');
	invariant(parses(maximum_depth), "JSON maximum nesting depth was rejected");
	invariant(!parses("[" + maximum_depth + "]"), "JSON excessive nesting depth was accepted");
	invariant(!parses(R"({"id":1,"id":2})"), "duplicate JSON object key was accepted");
	invariant(!parses(R"({"id":1,"\u0069d":2})"),
	    "escape-equivalent duplicate JSON object key was accepted");
	invariant(!parses(R"({"outer":{"key":1,"key":2}})"),
	    "nested duplicate JSON object key was accepted");
	invariant(parses(R"({"left":{"key":1},"right":{"key":2}})"),
	    "same JSON key in distinct objects was rejected");
	const std::string unicode_bytes("\xc3\xa9\xe2\x82\xac\xf0\x9f\x98\x80", 9);
	const common::JsonValue escaped_unicode =
	    common::JsonValue::from_string(R"("\u00e9\u20ac\ud83d\ude00")");
	invariant(escaped_unicode.get_string() == unicode_bytes,
	    "JSON Unicode escapes did not produce canonical UTF-8");
	const common::JsonValue raw_unicode =
	    common::JsonValue::from_string("\"" + unicode_bytes + "\"");
	invariant(raw_unicode.get_string() == unicode_bytes, "valid raw JSON UTF-8 was rejected");
	const std::vector<std::string> invalid_unicode{
	    R"("\ud800")", R"("\udc00")", R"("\ud800\u0041")", R"("\ufffe")",
	    std::string("\"\xc0\x80\"", 4), std::string("\"\xed\xa0\x80\"", 5),
	    std::string("\"\xf4\x90\x80\x80\"", 6)};
	for (const std::string &invalid : invalid_unicode) {
		invariant(!parses(invalid), "invalid JSON Unicode encoding was accepted");
	}

	for (const auto &ca : cases1) {
		common::JsonValue jv;
		jv.set_number(ca.first);
		invariant(jv.get_unsigned() == ca.second, "");
	}
	for (const auto &ca : cases2) {
		common::JsonValue jv;
		jv.set_number(ca.first);
		invariant(jv.get_integer() == ca.second, "");
	}

	for (int i = 1; i != 4; ++i)
		test_json(test_vectors_folder + "/pass" + std::to_string(i) + ".json", true);
	for (int i = 1; i != 35; ++i)
		test_json(test_vectors_folder + "/fail" + std::to_string(i) + ".json", i == 1);
	// We pass fail1 because we relax rules on top-level object or array
}
