// Copyright (c) 2012-2018, The CryptoNote developers, The Bytecoin developers.
// Licensed under the GNU Lesser General Public License. See LICENSE for details.

#pragma once

#include "common/CommandLine.hpp"

// Exercises the Jade (V5) consensus-enforced minimum ring size directly against
// validate_tx_semantic: undersized/zero-mixin rings are rejected, full rings accepted, and
// pre-fork (Amethyst/V4) semantic validation is left unchanged.
void test_jade_consensus(common::CommandLine &cmd);
