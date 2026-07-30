// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include <stddef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define CRYPTO_RESEED_INTERVAL_BYTES (1u << 20)

void crypto_unsafe_generate_random_bytes(unsigned char *result, size_t n);  // Not thread-safe
void crypto_initialize_random(void);
void crypto_reseed_random(void);  // Mixes fresh system entropy into the sponge state. Not thread-safe.
size_t crypto_unsafe_random_reseed_count(void);  // Diagnostic counter. Not thread-safe.
void crypto_initialize_random_for_tests(void);

#if defined(__cplusplus)
}
#endif
