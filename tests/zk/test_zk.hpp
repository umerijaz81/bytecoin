// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

// Onyx O0: asserts the vendored Halo2 backend (via cn::zk::Halo2ProofSystem) reproduces the
// Poseidon/Sinsemilla known-answer vectors and that the toy prove->verify pipeline round-trips
// across the FFI. Built only when configured with -DONYX_ZK=ON.
void test_zk();
