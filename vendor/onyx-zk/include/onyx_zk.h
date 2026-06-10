/* Onyx (V6) zero-knowledge backend — C ABI.
 *
 * Stable, audit-sized boundary between the C++ node and the vendored Halo2/PLONKish (Pasta) proving
 * stack. Hand-authored (not cbindgen-generated) because the surface is intentionally tiny. Backs
 * cn::zk::Halo2ProofSystem (src/Core/zk). See ONYX_ARCHITECTURE.md / ONYX_O0_PLAN.md.
 *
 * Return convention for predicate calls: 1 = valid, 0 = invalid, < 0 = malformed input / error.
 * Buffers returned via out-params are owned by the callee and MUST be released with onyx_free.
 */
#ifndef ONYX_ZK_H
#define ONYX_ZK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backend identity, e.g. "halo2-ipa-pasta vX.Y". Static string; do not free. */
const char *onyx_backend_id(void);

/* Orchard Poseidon (P128Pow5T3, arity 2) over the Pallas base field.
 * in: two 32-byte canonical little-endian field elements (64 bytes total).
 * out: 32-byte digest. Returns 0 on success, <0 if an input is not a canonical field element. */
int onyx_poseidon_hash2(const uint8_t in[64], uint8_t out[32]);

/* Sinsemilla hash over a fixed test domain. Input bytes are expanded LSB-first to a bit string.
 * out: 32-byte digest (Pallas base field element). Returns 0 on success, <0 on the (negligible)
 * exceptional case or bad input. */
int onyx_sinsemilla_hash(const uint8_t *in, size_t in_len, uint8_t out[32]);

/* Toy circuit (knowledge of a, b with a*b = public), used only to validate the prove->verify
 * pipeline end-to-end. Writes a freshly-allocated proof, verifying key, and the 32-byte public
 * input. Returns 0 on success, <0 on error. Release *proof_out and *vk_out with onyx_free. */
int onyx_toy_prove(uint64_t a, uint64_t b,
                   uint8_t **proof_out, size_t *proof_len,
                   uint8_t **vk_out, size_t *vk_len,
                   uint8_t public_out[32]);

/* Verify a toy-circuit proof against (vk, public_input). 1 = valid, 0 = invalid, <0 = malformed. */
int onyx_toy_verify(const uint8_t *vk, size_t vk_len,
                    const uint8_t *proof, size_t proof_len,
                    const uint8_t public_input[32]);

/* Release a buffer previously returned by this library. */
void onyx_free(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ONYX_ZK_H */
