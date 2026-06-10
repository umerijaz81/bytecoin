// PoC (dynamic) for Bytecoin finding C-3 — zero-mixin / consensus-unenforced ring size.
//
// This test constructs a minimal amethyst Transaction whose single InputKey has a ring of
// size 1 (output_indexes == {idx}, i.e. ZERO decoys) and asserts that the consensus semantic
// validator accepts it. A privacy-preserving currency should reject any ring smaller than
// minimum_anonymity + 1; Bytecoin accepts ring size 1 because the minimum is enforced only by
// the wallet (WalletNode.cpp:469), never by validate_tx_semantic (BlockChainState.cpp:117).
//
// ---------------------------------------------------------------------------------------------
// HOW TO BUILD / RUN
// ---------------------------------------------------------------------------------------------
// `validate_tx_semantic` is a file-static function in src/Core/BlockChainState.cpp, so it is not
// directly linkable. Two supported options:
//
//   Option A (recommended, exercises the REAL function):
//     1. In src/Core/BlockChainState.cpp, temporarily change the line
//            static Amount validate_tx_semantic(const Currency &currency, ...)
//        to (remove `static`)
//            Amount validate_tx_semantic(const Currency &currency, ...)
//        and add a matching non-static forward declaration to BlockChainState.hpp.
//     2. Add this file to the `tests` target in CMakeLists.txt and rebuild:
//            cmake --build build --target tests
//     3. Run: ./build/tests --poc-zero-mixin
//
//   Option B (no source edit): paste the assertion body below into an existing test in
//     tests/blockchain/test_blockchain.cpp, which is already compiled in the same translation
//     unit graph as the core and can reach the validator via a small helper.
//
// EXPECTED RESULT (demonstrating the vulnerability):
//     [PoC C-3] ring size 1 (zero mixin) ACCEPTED by validate_tx_semantic  -> LOOPHOLE CONFIRMED
//
// After applying the suggested fix from README.md, the same test should instead observe a
// ConsensusError("Ring size too small ...") and the PoC should report the loophole CLOSED.
// ---------------------------------------------------------------------------------------------

#include <iostream>
#include "Core/BlockChainState.hpp"
#include "Core/Currency.hpp"
#include "CryptoNote.hpp"
#include "crypto/crypto.hpp"

// Forward declaration matching the (de-static-ified) signature from BlockChainState.cpp.
namespace cn {
Amount validate_tx_semantic(const Currency &currency, uint8_t block_major_version, bool coinbase,
    const Transaction &tx, bool check_keys, bool key_image_subgroup_check);
}

namespace cn {

// Build a 1-in / 1-out amethyst transaction with a ZERO-mixin input (ring size 1).
static Transaction build_zero_mixin_tx() {
	Transaction tx;
	tx.version = 4;  // amethyst_transaction_version

	InputKey in;
	in.amount = 1000000;
	// Ring size 1: a single (absolute->relative) output offset. This is the whole point.
	in.output_indexes = {42};
	in.key_image      = crypto::rand<KeyImage>();
	tx.inputs.push_back(in);

	OutputKey out;
	out.amount     = 999000;  // < input so sum(out) <= sum(in)
	out.public_key = crypto::rand<PublicKey>();
	tx.outputs.push_back(out);

	return tx;
}

int run_poc_zero_mixin(const Currency &currency) {
	const Transaction tx = build_zero_mixin_tx();
	const uint8_t block_major_version = currency.amethyst_block_version;  // = 4

	// check_keys=false / subgroup=false: we are proving the *structural* gap (ring-size rule),
	// not signature validity. The validator still runs every structural rule it knows about.
	bool accepted = true;
	std::string err;
	try {
		(void)validate_tx_semantic(currency, block_major_version, /*coinbase=*/false, tx,
		    /*check_keys=*/false, /*key_image_subgroup_check=*/false);
	} catch (const std::exception &e) {
		accepted = false;
		err      = e.what();
	}

	if (accepted) {
		std::cout << "[PoC C-3] ring size 1 (zero mixin) ACCEPTED by validate_tx_semantic"
		          << "  -> LOOPHOLE CONFIRMED" << std::endl;
		return 0;  // vulnerability present
	}
	std::cout << "[PoC C-3] ring size 1 REJECTED: \"" << err << "\"  -> loophole CLOSED"
	          << std::endl;
	return 1;  // fix is in place
}

}  // namespace cn
