// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#include "test_randomx.hpp"
#include <cstring>
#include <iostream>
#include "common/Invariant.hpp"
#include "common/StringTools.hpp"
#include "crypto/RandomX.hpp"

void test_randomx() {
	crypto::Hash seed;
	for (size_t i = 0; i != sizeof(seed.data); ++i)
		seed.data[i] = static_cast<uint8_t>(i);
	const char input[] = "Bytecoin RandomX v2 consensus vector";
	crypto::RandomXContext context;
	const crypto::Hash actual = context.hash(seed, input, std::strlen(input));
	const crypto::Hash expected =
	    common::pfh<crypto::Hash>("063c470f43132f8f434ac91a0f4477a6602378365aa31a8bbb71337390fad9ed");
	invariant(actual == expected, "RandomX v2 known-answer vector mismatch");
	invariant(context.hash(seed, input, std::strlen(input)) == expected,
	    "RandomX v2 cached-seed result changed");
	std::cout << "  RandomX v2 known-answer and cached-seed vectors ok" << std::endl;
}
