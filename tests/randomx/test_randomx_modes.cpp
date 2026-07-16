#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>
#include "crypto/RandomX.hpp"

namespace {

crypto::Hash expected_hash() {
	const std::array<uint8_t, 32> bytes{{0x06, 0x3c, 0x47, 0x0f, 0x43, 0x13, 0x2f, 0x8f,
	    0x43, 0x4a, 0xc9, 0x1a, 0x0f, 0x44, 0x77, 0xa6, 0x60, 0x23, 0x78, 0x36, 0x5a, 0xa3,
	    0x1a, 0x8b, 0xbb, 0x71, 0x33, 0x73, 0x90, 0xfa, 0xd9, 0xed}};
	crypto::Hash result{};
	std::copy(bytes.begin(), bytes.end(), result.data);
	return result;
}

void require(bool condition, const char *message) {
	if (!condition)
		throw std::runtime_error(message);
}

}  // namespace

int main() try {
	crypto::Hash seed{};
	for (size_t i = 0; i != sizeof(seed.data); ++i)
		seed.data[i] = static_cast<uint8_t>(i);
	const char input[] = "Bytecoin RandomX v2 consensus vector";

	crypto::RandomXContext light;
	const crypto::Hash expected = expected_hash();
	require(light.hash(seed, input, std::strlen(input)) == expected, "RandomX light-mode vector mismatch");

	auto dataset = std::make_shared<crypto::RandomXDataset>(seed, 2, false);
	crypto::RandomXContext first(dataset);
	crypto::RandomXContext second(dataset);
	crypto::Hash first_hash{};
	crypto::Hash second_hash{};
	std::exception_ptr first_error;
	std::exception_ptr second_error;
	std::thread first_worker([&] {
		try {
			first_hash = first.hash(seed, input, std::strlen(input));
		} catch (...) {
			first_error = std::current_exception();
		}
	});
	std::thread second_worker([&] {
		try {
			second_hash = second.hash(seed, input, std::strlen(input));
		} catch (...) {
			second_error = std::current_exception();
		}
	});
	first_worker.join();
	second_worker.join();
	if (first_error)
		std::rethrow_exception(first_error);
	if (second_error)
		std::rethrow_exception(second_error);
	require(first_hash == expected && second_hash == expected,
	    "RandomX full-memory contexts diverged from the consensus vector");

	crypto::Hash wrong_seed = seed;
	wrong_seed.data[0] ^= 1;
	bool mismatch_rejected = false;
	try {
		(void)first.hash(wrong_seed, input, std::strlen(input));
	} catch (const std::invalid_argument &) {
		mismatch_rejected = true;
	}
	require(mismatch_rejected, "RandomX full-memory context accepted a mismatched seed");
	std::cout << "RandomX v2 light/full-memory equality and shared-dataset concurrency: OK" << std::endl;
	return 0;
} catch (const std::exception &error) {
	std::cerr << error.what() << std::endl;
	return 1;
}
