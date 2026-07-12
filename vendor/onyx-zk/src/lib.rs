//! Onyx (V6) zero-knowledge backend — C ABI over a vendored Halo2/PLONKish (Pasta) stack.
//!
//! This crate is **wrappers only** — it contains no bespoke cryptography. It exposes the Orchard
//! Poseidon and Sinsemilla primitives and a toy prove/verify pipeline so the Rust<->C++ boundary,
//! the CMake/cargo integration, and the proving stack can be validated end-to-end before any
//! protocol logic (notes, nullifiers, value transfer — Onyx phase O1) is built on top.
//!
//! See ONYX_ARCHITECTURE.md and ONYX_O0_PLAN.md.

use std::convert::TryInto;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_gadgets::sinsemilla::primitives::HashDomain;

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error as PlonkError, Instance, Selector, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

pub mod authorization;
pub mod bundle_circuit;
pub mod keys;
pub mod linked_transfer_circuit;
pub mod membership_circuit;
pub mod multi_transfer_circuit;
pub mod note_commitment_circuit;
pub mod proof;
pub mod spend_auth_circuit;
pub mod state;
pub mod transaction;
pub mod transfer_circuit;
pub mod types;
pub mod value_commitment_circuit;

const SINSEMILLA_DOMAIN: &str = "z.cash:Onyx-test-v6";
const TOY_K: u32 = 4; // 2^4 rows is ample for the one-multiplication toy circuit
const MAX_HASH_INPUT: usize = 4 * 1024;
const MAX_PROOF_BYTES: usize = 192 * 1024;
const MAX_VK_BYTES: usize = 1024 * 1024;
const ERR_PANIC: i32 = -127;

fn ffi_i32(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(ERR_PANIC)
}

#[no_mangle]
pub extern "C" fn onyx_backend_id() -> *const std::os::raw::c_char {
    // Static, NUL-terminated; never freed by the caller.
    b"halo2-ipa-pasta v0.0.1\0".as_ptr() as *const std::os::raw::c_char
}

fn fp_from_le(bytes: &[u8; 32]) -> Option<Fp> {
    Option::from(Fp::from_repr(*bytes))
}

/// Orchard Poseidon (P128Pow5T3, arity 2) over the Pallas base field.
#[no_mangle]
pub extern "C" fn onyx_poseidon_hash2(input: *const u8, out: *mut u8) -> i32 {
    ffi_i32(|| poseidon_hash2_impl(input, out))
}

fn poseidon_hash2_impl(input: *const u8, out: *mut u8) -> i32 {
    if input.is_null() || out.is_null() {
        return -1;
    }
    let in_slice = unsafe { slice::from_raw_parts(input, 64) };
    let a_bytes: [u8; 32] = in_slice[0..32].try_into().unwrap();
    let b_bytes: [u8; 32] = in_slice[32..64].try_into().unwrap();
    let (a, b) = match (fp_from_le(&a_bytes), fp_from_le(&b_bytes)) {
        (Some(a), Some(b)) => (a, b),
        _ => return -2, // not canonical field elements
    };
    let digest: Fp = PoseidonHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b]);
    let repr = digest.to_repr();
    unsafe { slice::from_raw_parts_mut(out, 32).copy_from_slice(&repr) };
    0
}

/// Sinsemilla hash over a fixed test domain; input bytes expanded LSB-first to bits.
#[no_mangle]
pub extern "C" fn onyx_sinsemilla_hash(input: *const u8, in_len: usize, out: *mut u8) -> i32 {
    ffi_i32(|| sinsemilla_hash_impl(input, in_len, out))
}

fn sinsemilla_hash_impl(input: *const u8, in_len: usize, out: *mut u8) -> i32 {
    if out.is_null() || (input.is_null() && in_len != 0) || in_len > MAX_HASH_INPUT {
        return -1;
    }
    let bytes = if in_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(input, in_len) }
    };
    let bits = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1 == 1));
    let domain = HashDomain::new(SINSEMILLA_DOMAIN);
    match Option::<Fp>::from(domain.hash(bits)) {
        Some(p) => {
            unsafe { slice::from_raw_parts_mut(out, 32).copy_from_slice(&p.to_repr()) };
            0
        }
        None => -2, // negligible exceptional case
    }
}

// ----------------------------------------------------------------------------------------------
// Toy circuit: knowledge of (a, b) such that a * b = public. Validates the proving pipeline only.
// ----------------------------------------------------------------------------------------------

#[derive(Clone)]
struct ToyConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    s: Selector,
    instance: Column<Instance>,
}

#[derive(Default, Clone)]
struct ToyCircuit {
    a: Value<Fp>,
    b: Value<Fp>,
}

impl Circuit<Fp> for ToyCircuit {
    type Config = ToyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        ToyCircuit {
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> ToyConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let instance = meta.instance_column();
        let s = meta.selector();
        meta.enable_equality(c);
        meta.enable_equality(instance);

        meta.create_gate("mul", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());
            let s = meta.query_selector(s);
            vec![s * (a * b - c)]
        });

        ToyConfig {
            a,
            b,
            c,
            s,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: ToyConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), PlonkError> {
        let c_cell = layouter.assign_region(
            || "a*b=c",
            |mut region| {
                config.s.enable(&mut region, 0)?;
                region.assign_advice(|| "a", config.a, 0, || self.a)?;
                region.assign_advice(|| "b", config.b, 0, || self.b)?;
                let c_val = self.a * self.b;
                region.assign_advice(|| "c", config.c, 0, || c_val)
            },
        )?;
        layouter.constrain_instance(c_cell.cell(), config.instance, 0)
    }
}

fn fp_from_u64(x: u64) -> Fp {
    Fp::from(x)
}

struct ToyProof {
    proof: Vec<u8>,
    vk: Vec<u8>,
    public: [u8; 32],
}

fn toy_prove(a: u64, b: u64) -> Result<ToyProof, String> {
    let a_f = fp_from_u64(a);
    let b_f = fp_from_u64(b);
    let public = a_f * b_f;

    let params: Params<EqAffine> = Params::new(TOY_K);
    let circuit = ToyCircuit {
        a: Value::known(a_f),
        b: Value::known(b_f),
    };
    let vk = keygen_vk(&params, &circuit).map_err(|e| format!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|e| format!("keygen_pk: {e:?}"))?;

    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(vec![]);
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[public]]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|e| format!("create_proof: {e:?}"))?;
    let proof = transcript.finalize();

    // The toy verifying key is determined solely by the circuit structure, so the verifier
    // regenerates it via keygen_vk rather than deserializing. (halo2_proofs 0.3.2 has no VK serde;
    // O4's program registry will publish vks once the protocol circuits exist.)
    Ok(ToyProof {
        proof,
        vk: Vec::new(),
        public: public.to_repr(),
    })
}

fn toy_verify(_vk_bytes: &[u8], proof: &[u8], public: &[u8; 32]) -> Result<bool, String> {
    let public = match Option::<Fp>::from(Fp::from_repr(*public)) {
        Some(p) => p,
        None => return Err("public input not a canonical field element".into()),
    };
    let params: Params<EqAffine> = Params::new(TOY_K);
    let vk = keygen_vk(
        &params,
        &ToyCircuit {
            a: Value::unknown(),
            b: Value::unknown(),
        },
    )
    .map_err(|e| format!("keygen_vk: {e:?}"))?;

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(proof);
    let ok = verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        strategy,
        &[&[&[public]]],
        &mut transcript,
    )
    .is_ok();
    Ok(ok)
}

#[no_mangle]
pub extern "C" fn onyx_toy_prove(
    a: u64,
    b: u64,
    proof_out: *mut *mut u8,
    proof_len: *mut usize,
    vk_out: *mut *mut u8,
    vk_len: *mut usize,
    public_out: *mut u8,
) -> i32 {
    ffi_i32(|| toy_prove_ffi_impl(a, b, proof_out, proof_len, vk_out, vk_len, public_out))
}

fn toy_prove_ffi_impl(
    a: u64,
    b: u64,
    proof_out: *mut *mut u8,
    proof_len: *mut usize,
    vk_out: *mut *mut u8,
    vk_len: *mut usize,
    public_out: *mut u8,
) -> i32 {
    if proof_out.is_null()
        || proof_len.is_null()
        || vk_out.is_null()
        || vk_len.is_null()
        || public_out.is_null()
    {
        return -1;
    }
    let r = match toy_prove(a, b) {
        Ok(r) => r,
        Err(_) => return -2,
    };
    unsafe {
        slice::from_raw_parts_mut(public_out, 32).copy_from_slice(&r.public);
        let (p_ptr, p_len) = into_raw(r.proof);
        let (v_ptr, v_len) = into_raw(r.vk);
        *proof_out = p_ptr;
        *proof_len = p_len;
        *vk_out = v_ptr;
        *vk_len = v_len;
    }
    0
}

#[no_mangle]
pub extern "C" fn onyx_toy_verify(
    vk: *const u8,
    vk_len: usize,
    proof: *const u8,
    proof_len: usize,
    public_input: *const u8,
) -> i32 {
    ffi_i32(|| toy_verify_ffi_impl(vk, vk_len, proof, proof_len, public_input))
}

fn toy_verify_ffi_impl(
    vk: *const u8,
    vk_len: usize,
    proof: *const u8,
    proof_len: usize,
    public_input: *const u8,
) -> i32 {
    // The toy verifier regenerates its vk from the circuit structure, so a null/empty vk is allowed
    // here (a real program vk in O4 will not be optional). proof and public_input are required.
    if proof.is_null()
        || public_input.is_null()
        || proof_len == 0
        || proof_len > MAX_PROOF_BYTES
        || vk_len > MAX_VK_BYTES
        || (vk.is_null() && vk_len != 0)
    {
        return -1;
    }
    let vk = if vk.is_null() || vk_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(vk, vk_len) }
    };
    let proof = unsafe { slice::from_raw_parts(proof, proof_len) };
    let public: [u8; 32] = match unsafe { slice::from_raw_parts(public_input, 32) }.try_into() {
        Ok(p) => p,
        Err(_) => return -1,
    };
    match toy_verify(vk, proof, &public) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -2,
    }
}

fn into_raw(mut v: Vec<u8>) -> (*mut u8, usize) {
    v.shrink_to_fit();
    let ptr = v.as_mut_ptr();
    let len = v.len();
    std::mem::forget(v);
    (ptr, len)
}

#[no_mangle]
pub extern "C" fn onyx_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        // Reconstruct with capacity == len (we shrank_to_fit in into_raw) so Vec frees correctly.
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_is_deterministic_and_nonzero() {
        let input = [7u8; 64];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        assert_eq!(onyx_poseidon_hash2(input.as_ptr(), out1.as_mut_ptr()), 0);
        assert_eq!(onyx_poseidon_hash2(input.as_ptr(), out2.as_mut_ptr()), 0);
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
        // Print the KAT so it can be frozen into the C++ test vectors.
        println!("poseidon2([7;32],[7;32]) = {}", hex(&out1));
    }

    #[test]
    fn sinsemilla_runs() {
        let input = b"onyx";
        let mut out = [0u8; 32];
        assert_eq!(
            onyx_sinsemilla_hash(input.as_ptr(), input.len(), out.as_mut_ptr()),
            0
        );
        assert_ne!(out, [0u8; 32]);
        println!("sinsemilla(\"onyx\") = {}", hex(&out));
    }

    #[test]
    fn ffi_rejects_oversized_inputs() {
        let input = [0u8; 1];
        let mut out = [0u8; 32];
        assert_eq!(
            onyx_sinsemilla_hash(input.as_ptr(), MAX_HASH_INPUT + 1, out.as_mut_ptr()),
            -1
        );

        let proof = [0u8; 1];
        let public = [0u8; 32];
        assert_eq!(
            onyx_toy_verify(
                std::ptr::null(),
                0,
                proof.as_ptr(),
                MAX_PROOF_BYTES + 1,
                public.as_ptr(),
            ),
            -1
        );
        assert_eq!(
            onyx_toy_verify(
                std::ptr::null(),
                1,
                proof.as_ptr(),
                proof.len(),
                public.as_ptr(),
            ),
            -1
        );
    }

    #[test]
    fn toy_proof_round_trips() {
        let mut proof: *mut u8 = std::ptr::null_mut();
        let mut proof_len = 0usize;
        let mut vk: *mut u8 = std::ptr::null_mut();
        let mut vk_len = 0usize;
        let mut public = [0u8; 32];
        let rc = onyx_toy_prove(
            6,
            7,
            &mut proof,
            &mut proof_len,
            &mut vk,
            &mut vk_len,
            public.as_mut_ptr(),
        );
        assert_eq!(rc, 0);
        let ok = onyx_toy_verify(vk, vk_len, proof, proof_len, public.as_ptr());
        assert_eq!(ok, 1, "valid proof must verify");
        // Tamper the public input -> must fail.
        let mut bad = public;
        bad[0] ^= 1;
        let bad_rc = onyx_toy_verify(vk, vk_len, proof, proof_len, bad.as_ptr());
        assert_eq!(bad_rc, 0, "tampered public input must not verify");
        onyx_free(proof, proof_len);
        onyx_free(vk, vk_len);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
