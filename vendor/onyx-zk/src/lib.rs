//! Onyx (V6) zero-knowledge backend — C ABI over a vendored Halo2/PLONKish (Pasta) stack.
//!
//! The crate exposes a bounded panic-contained C ABI over the vendored Halo2/IPA/Pasta stack. Typed
//! consensus entry points cover canonical private transfers, bridge operations, program deployment,
//! token issuance, atomic state transitions, wallet scanning/proving, and SDK descriptors. The toy
//! circuit remains an FFI smoke test only and is forbidden on consensus paths.

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
pub mod bridge;
pub mod bridge_circuit;
pub mod bundle_circuit;
pub mod compiler_backend;
pub mod keys;
pub mod linked_transfer_circuit;
pub mod membership_circuit;
pub mod mixed_token_circuit;
pub mod multi_transfer_circuit;
pub mod note_commitment_circuit;
pub mod program;
pub mod program_context;
pub mod program_deployment;
pub mod proof;
pub mod spend_auth_circuit;
pub mod standard_programs;
pub mod state;
pub mod token_issuance;
pub mod token_issuance_circuit;
pub mod token_program;
pub mod transaction;
pub mod transfer_circuit;
pub mod types;
pub mod value_commitment_circuit;
pub mod wallet;

const SINSEMILLA_DOMAIN: &str = "z.cash:Onyx-test-v6";
const TOY_K: u32 = 4; // 2^4 rows is ample for the one-multiplication toy circuit
const MAX_HASH_INPUT: usize = 4 * 1024;
const MAX_PROOF_BYTES: usize = 192 * 1024;
const MAX_VK_BYTES: usize = 1024 * 1024;
const MAX_AUTHORIZED_TRANSACTION_BYTES: usize = 384 * 1024;
const MAX_STATE_SNAPSHOT_BYTES: usize = 128 * 1024 * 1024;
const MAX_EXPIRY_DISTANCE_BLOCKS: u64 = 100;
const ERR_PANIC: i32 = -127;
const ABI_VERSION: u32 = 1;

fn ffi_i32(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(ERR_PANIC)
}

#[no_mangle]
pub extern "C" fn onyx_abi_version() -> u32 {
    ABI_VERSION
}

fn verify_mixed_transfer_dispatch(
    transaction: &transaction::AuthorizedTransaction,
    merkle_depth: u32,
    circuit_k: u32,
    registry: Option<&program::ProgramRegistry>,
    block_height: u64,
) -> Result<(), proof::ProofError> {
    let call = transaction
        .preimage
        .programs
        .first()
        .ok_or(proof::ProofError::InvalidShape)?;
    let token_spends = ((call.function_id >> 12) & 0xf) as usize;
    let token_outputs = ((call.function_id >> 8) & 0xf) as usize;
    let native_spends = (call.function_id & 0xff) as usize;
    if token_program::mixed_transfer_function_id(token_spends, token_outputs, native_spends)
        != Some(call.function_id)
    {
        return Err(proof::ProofError::InvalidShape);
    }
    macro_rules! dispatch_depth {
        ($depth:literal) => {
            match (token_spends, token_outputs, native_spends) {
                (1, 1, 1) => proof::verify_authorized_mixed_token_transfer::<$depth, 1, 1, 1>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (1, 1, 2) => proof::verify_authorized_mixed_token_transfer::<$depth, 1, 1, 2>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (1, 2, 1) => proof::verify_authorized_mixed_token_transfer::<$depth, 1, 2, 1>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (1, 2, 2) => proof::verify_authorized_mixed_token_transfer::<$depth, 1, 2, 2>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (2, 1, 1) => proof::verify_authorized_mixed_token_transfer::<$depth, 2, 1, 1>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (2, 1, 2) => proof::verify_authorized_mixed_token_transfer::<$depth, 2, 1, 2>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (2, 2, 1) => proof::verify_authorized_mixed_token_transfer::<$depth, 2, 2, 1>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                (2, 2, 2) => proof::verify_authorized_mixed_token_transfer::<$depth, 2, 2, 2>(
                    circuit_k,
                    transaction,
                    registry,
                    block_height,
                ),
                _ => Err(proof::ProofError::InvalidShape),
            }
        };
    }
    match merkle_depth {
        2 => dispatch_depth!(2),
        4 => dispatch_depth!(4),
        32 => dispatch_depth!(32),
        _ => Err(proof::ProofError::InvalidShape),
    }
}

fn verify_transfer_dispatch(
    transaction: &transaction::AuthorizedTransaction,
    merkle_depth: u32,
    circuit_k: u32,
    registry: Option<&program::ProgramRegistry>,
    block_height: u64,
) -> i32 {
    if !(10..=20).contains(&circuit_k) {
        return -3;
    }
    let shape = (
        merkle_depth,
        transaction.preimage.spends.len(),
        transaction.preimage.outputs.len(),
    );
    let result = if transaction.backend_id == token_program::TOKEN_PROGRAM_BACKEND
        && transaction.preimage.programs.first().is_some_and(|call| {
            call.function_id & 0xffff_0000 == token_program::TOKEN_MIXED_TRANSFER_FUNCTION_BASE
        }) {
        verify_mixed_transfer_dispatch(transaction, merkle_depth, circuit_k, registry, block_height)
    } else if transaction.backend_id == token_program::TOKEN_PROGRAM_BACKEND {
        match shape {
            (2, 1, 1) => proof::verify_authorized_token_transfer::<2, 1, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (2, 1, 2) => proof::verify_authorized_token_transfer::<2, 1, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (2, 2, 1) => proof::verify_authorized_token_transfer::<2, 2, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (2, 2, 2) => proof::verify_authorized_token_transfer::<2, 2, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (4, 1, 1) => proof::verify_authorized_token_transfer::<4, 1, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (4, 1, 2) => proof::verify_authorized_token_transfer::<4, 1, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (4, 2, 1) => proof::verify_authorized_token_transfer::<4, 2, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (4, 2, 2) => proof::verify_authorized_token_transfer::<4, 2, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (32, 1, 1) => proof::verify_authorized_token_transfer::<32, 1, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (32, 1, 2) => proof::verify_authorized_token_transfer::<32, 1, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (32, 2, 1) => proof::verify_authorized_token_transfer::<32, 2, 1>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            (32, 2, 2) => proof::verify_authorized_token_transfer::<32, 2, 2>(
                circuit_k,
                transaction,
                registry,
                block_height,
            ),
            _ => return -3,
        }
    } else {
        match shape {
            (2, 1, 1) => proof::verify_authorized_multi_transfer::<2, 1, 1>(circuit_k, transaction),
            (2, 1, 2) => proof::verify_authorized_multi_transfer::<2, 1, 2>(circuit_k, transaction),
            (2, 2, 1) => proof::verify_authorized_multi_transfer::<2, 2, 1>(circuit_k, transaction),
            (2, 2, 2) => proof::verify_authorized_multi_transfer::<2, 2, 2>(circuit_k, transaction),
            (4, 1, 1) if transaction.backend_id == proof::EXPERIMENTAL_TRANSFER_BACKEND => {
                proof::verify_authorized_transfer::<4>(circuit_k, transaction)
            }
            (4, 1, 1) => proof::verify_authorized_multi_transfer::<4, 1, 1>(circuit_k, transaction),
            (4, 1, 2) => proof::verify_authorized_multi_transfer::<4, 1, 2>(circuit_k, transaction),
            (4, 2, 1) => proof::verify_authorized_multi_transfer::<4, 2, 1>(circuit_k, transaction),
            (4, 2, 2) => proof::verify_authorized_multi_transfer::<4, 2, 2>(circuit_k, transaction),
            (32, 1, 1) => {
                proof::verify_authorized_multi_transfer::<32, 1, 1>(circuit_k, transaction)
            }
            (32, 1, 2) => {
                proof::verify_authorized_multi_transfer::<32, 1, 2>(circuit_k, transaction)
            }
            (32, 2, 1) => {
                proof::verify_authorized_multi_transfer::<32, 2, 1>(circuit_k, transaction)
            }
            (32, 2, 2) => {
                proof::verify_authorized_multi_transfer::<32, 2, 2>(circuit_k, transaction)
            }
            _ => return -3,
        }
    };
    if result.is_ok() {
        1
    } else {
        0
    }
}

fn transfer_circuit_k(
    transaction: &transaction::AuthorizedTransaction,
    native_k: u32,
    token_k: u32,
) -> Result<u32, ()> {
    if !(10..=20).contains(&native_k) || !(10..=20).contains(&token_k) {
        return Err(());
    }
    Ok(
        if transaction.backend_id == token_program::TOKEN_PROGRAM_BACKEND {
            token_k
        } else {
            native_k
        },
    )
}

fn verify_program_deployment_dispatch(
    deployment: &program_deployment::AuthorizedProgramDeployment,
    merkle_depth: u32,
    funding_k: u32,
    program_k: u32,
    block_height: Option<u64>,
) -> Result<program::ProgramEntry, ()> {
    if !(10..=20).contains(&funding_k) || !(10..=20).contains(&program_k) {
        return Err(());
    }
    let height = match block_height {
        Some(height) => height,
        None => deployment.activation_height.checked_sub(1).ok_or(())?,
    };
    let shape = (
        merkle_depth,
        deployment.funding.preimage.spends.len(),
        deployment.funding.preimage.outputs.len(),
    );
    let result = match shape {
        (2, 1, 1) => program_deployment::verify_standard_deployment::<2, 1, 1>(
            funding_k, program_k, deployment, height,
        ),
        (2, 1, 2) => program_deployment::verify_standard_deployment::<2, 1, 2>(
            funding_k, program_k, deployment, height,
        ),
        (2, 2, 1) => program_deployment::verify_standard_deployment::<2, 2, 1>(
            funding_k, program_k, deployment, height,
        ),
        (2, 2, 2) => program_deployment::verify_standard_deployment::<2, 2, 2>(
            funding_k, program_k, deployment, height,
        ),
        (4, 1, 1) => program_deployment::verify_standard_deployment::<4, 1, 1>(
            funding_k, program_k, deployment, height,
        ),
        (4, 1, 2) => program_deployment::verify_standard_deployment::<4, 1, 2>(
            funding_k, program_k, deployment, height,
        ),
        (4, 2, 1) => program_deployment::verify_standard_deployment::<4, 2, 1>(
            funding_k, program_k, deployment, height,
        ),
        (4, 2, 2) => program_deployment::verify_standard_deployment::<4, 2, 2>(
            funding_k, program_k, deployment, height,
        ),
        (32, 1, 1) => program_deployment::verify_standard_deployment::<32, 1, 1>(
            funding_k, program_k, deployment, height,
        ),
        (32, 1, 2) => program_deployment::verify_standard_deployment::<32, 1, 2>(
            funding_k, program_k, deployment, height,
        ),
        (32, 2, 1) => program_deployment::verify_standard_deployment::<32, 2, 1>(
            funding_k, program_k, deployment, height,
        ),
        (32, 2, 2) => program_deployment::verify_standard_deployment::<32, 2, 2>(
            funding_k, program_k, deployment, height,
        ),
        _ => return Err(()),
    };
    result.map_err(|_| ())
}

fn verify_token_issuance_dispatch(
    issuance: &token_issuance::AuthorizedTokenIssuance,
    merkle_depth: u32,
    circuit_k: u32,
    registry: Option<&program::ProgramRegistry>,
    block_height: u64,
) -> Result<(), ()> {
    if !(10..=20).contains(&circuit_k) {
        return Err(());
    }
    let outputs = issuance.transaction.preimage.outputs.len();
    match (merkle_depth, outputs, registry) {
        (2, 1, Some(registry)) => token_issuance::verify_token_issuance::<2, 1>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (2, 2, Some(registry)) => token_issuance::verify_token_issuance::<2, 2>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (4, 1, Some(registry)) => token_issuance::verify_token_issuance::<4, 1>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (4, 2, Some(registry)) => token_issuance::verify_token_issuance::<4, 2>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (32, 1, Some(registry)) => token_issuance::verify_token_issuance::<32, 1>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (32, 2, Some(registry)) => token_issuance::verify_token_issuance::<32, 2>(
            circuit_k,
            issuance,
            registry,
            block_height,
        ),
        (2, 1, None) => token_issuance::verify_token_issuance_proof::<2, 1>(circuit_k, issuance),
        (2, 2, None) => token_issuance::verify_token_issuance_proof::<2, 2>(circuit_k, issuance),
        (4, 1, None) => token_issuance::verify_token_issuance_proof::<4, 1>(circuit_k, issuance),
        (4, 2, None) => token_issuance::verify_token_issuance_proof::<4, 2>(circuit_k, issuance),
        (32, 1, None) => token_issuance::verify_token_issuance_proof::<32, 1>(circuit_k, issuance),
        (32, 2, None) => token_issuance::verify_token_issuance_proof::<32, 2>(circuit_k, issuance),
        _ => return Err(()),
    }
    .map_err(|_| ())
}

/// Verify a canonical authorized Onyx transfer envelope.
///
/// This bounded integration surface deliberately supports only audited circuit-family shapes.
/// Return values: 1 valid, 0 cryptographically invalid, -1 bad pointer/length, -2 malformed
/// encoding, -3 unsupported depth/shape/K.
#[no_mangle]
pub extern "C" fn onyx_verify_authorized_transfer(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    circuit_k: u32,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null() || encoded_len == 0 || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES {
            return -1;
        }
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        let bytes = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let transaction = match transaction::AuthorizedTransaction::decode(bytes) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        verify_transfer_dispatch(&transaction, merkle_depth, circuit_k, None, 0)
    })
}

#[no_mangle]
pub extern "C" fn onyx_verify_and_extract_transfer(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    native_k: u32,
    token_k: u32,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    fee_out: *mut u64,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || fee_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *fee_out = 0;
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
        }
        let bytes = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let transaction = match transaction::AuthorizedTransaction::decode(bytes) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        let circuit_k = match transfer_circuit_k(&transaction, native_k, token_k) {
            Ok(circuit_k) => circuit_k,
            Err(_) => return -3,
        };
        if nullifier_capacity < transaction.preimage.spends.len()
            || commitment_capacity < transaction.preimage.outputs.len()
        {
            return -4;
        }
        let verified = verify_transfer_dispatch(&transaction, merkle_depth, circuit_k, None, 0);
        if verified != 1 {
            return verified;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                transaction.preimage.network_id.as_ptr(),
                network_out,
                16,
            );
            std::ptr::copy_nonoverlapping(
                transaction.preimage.anchor.bytes().as_ptr(),
                anchor_out,
                32,
            );
            *expiry_height_out = transaction.preimage.expiry_height;
            *fee_out = transaction.preimage.fee;
            *nullifier_count_out = transaction.preimage.spends.len();
            *commitment_count_out = transaction.preimage.outputs.len();
            for (index, spend) in transaction.preimage.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in transaction.preimage.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

/// Authenticate a canonical transfer envelope and extract its signed public delta without
/// invoking Halo2. This is suitable for fee calculation, pool bookkeeping, and rejection-only
/// admission filters; callers must still perform full proof verification before acceptance.
#[no_mangle]
pub extern "C" fn onyx_extract_authenticated_transfer_delta(
    encoded: *const u8,
    encoded_len: usize,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    fee_out: *mut u64,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || fee_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *fee_out = 0;
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
        }
        let transaction = match transaction::AuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        if nullifier_capacity < transaction.preimage.spends.len()
            || commitment_capacity < transaction.preimage.outputs.len()
        {
            return -4;
        }
        if authorization::verify_authorized_transaction(&transaction).is_err() {
            return 0;
        }
        let preimage = &transaction.preimage;
        unsafe {
            std::ptr::copy_nonoverlapping(preimage.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(preimage.anchor.bytes().as_ptr(), anchor_out, 32);
            *expiry_height_out = preimage.expiry_height;
            *fee_out = preimage.fee;
            *nullifier_count_out = preimage.spends.len();
            *commitment_count_out = preimage.outputs.len();
            for (index, spend) in preimage.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in preimage.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

/// Verify and extract a canonical fee-funded standard-program deployment.
#[no_mangle]
pub extern "C" fn onyx_verify_program_deployment(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    funding_k: u32,
    program_k: u32,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    fee_out: *mut u64,
    program_id_out: *mut u8,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || fee_out.is_null()
            || program_id_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *fee_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
        }
        let deployment = match program_deployment::AuthorizedProgramDeployment::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(deployment) => deployment,
            Err(_) => return -2,
        };
        let funding = &deployment.funding.preimage;
        if nullifier_capacity < funding.spends.len() || commitment_capacity < funding.outputs.len()
        {
            return -4;
        }
        let entry = match verify_program_deployment_dispatch(
            &deployment,
            merkle_depth,
            funding_k,
            program_k,
            None,
        ) {
            Ok(entry) => entry,
            Err(_) => return 0,
        };
        let program_id = match entry.id() {
            Ok(program_id) => program_id,
            Err(_) => return 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(funding.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(funding.anchor.bytes().as_ptr(), anchor_out, 32);
            *expiry_height_out = funding.expiry_height;
            *fee_out = funding.fee;
            *nullifier_count_out = funding.spends.len();
            *commitment_count_out = funding.outputs.len();
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
            for (index, spend) in funding.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in funding.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

fn authenticated_program_deployment_entry(
    deployment: &program_deployment::AuthorizedProgramDeployment,
    merkle_depth: u32,
    program_k: u32,
) -> Result<program::ProgramEntry, ()> {
    if !(10..=20).contains(&program_k) {
        return Err(());
    }
    let spends = deployment.funding.preimage.spends.len();
    let outputs = deployment.funding.preimage.outputs.len();
    if !(1..=2).contains(&spends)
        || !(1..=2).contains(&outputs)
        || deployment.funding.backend_id != proof::multi_transfer_backend_id(spends, outputs)
    {
        return Err(());
    }
    authorization::verify_authorized_transaction(&deployment.funding).map_err(|_| ())?;
    let entry = match merkle_depth {
        2 => deployment.program_entry::<2>(program_k),
        4 => deployment.program_entry::<4>(program_k),
        32 => deployment.program_entry::<32>(program_k),
        _ => return Err(()),
    }
    .map_err(|_| ())?;
    let program_id = entry.id().map_err(|_| ())?;
    if deployment.funding.preimage.programs[0].program_id != program_id {
        return Err(());
    }
    Ok(entry)
}

/// Authenticate deployment funding and recompute its canonical manifest-derived program id without
/// invoking Halo2. This can drive fee calculation and rejection-only pool conflict checks.
#[no_mangle]
pub extern "C" fn onyx_extract_authenticated_program_deployment(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    program_k: u32,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    fee_out: *mut u64,
    program_id_out: *mut u8,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || fee_out.is_null()
            || program_id_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *fee_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
        }
        let deployment = match program_deployment::AuthorizedProgramDeployment::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(deployment) => deployment,
            Err(_) => return -2,
        };
        let funding = &deployment.funding.preimage;
        if nullifier_capacity < funding.spends.len() || commitment_capacity < funding.outputs.len()
        {
            return -4;
        }
        let entry =
            match authenticated_program_deployment_entry(&deployment, merkle_depth, program_k) {
                Ok(entry) => entry,
                Err(_) => return 0,
            };
        let program_id = match entry.id() {
            Ok(program_id) => program_id,
            Err(_) => return 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(funding.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(funding.anchor.bytes().as_ptr(), anchor_out, 32);
            *expiry_height_out = funding.expiry_height;
            *fee_out = funding.fee;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
            *nullifier_count_out = funding.spends.len();
            *commitment_count_out = funding.outputs.len();
            for (index, spend) in funding.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in funding.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

fn apply_program_deployment_to_snapshot<const DEPTH: usize>(
    snapshot: &[u8],
    anchor_window_blocks: u64,
    deployment: &program_deployment::AuthorizedProgramDeployment,
    entry: program::ProgramEntry,
    block_height: u64,
) -> Result<Vec<u8>, ()> {
    let mut state = if snapshot.is_empty() {
        if anchor_window_blocks == 0 {
            return Err(());
        }
        state::ShieldedState::<DEPTH>::new(anchor_window_blocks)
    } else {
        state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| ())?
    };
    let mut funding = deployment.funding.preimage.clone();
    funding.programs.clear();
    state
        .apply_program_deployment(
            &funding,
            entry,
            program_deployment::PROGRAM_DEPLOYMENT_COST,
            block_height,
        )
        .map_err(|_| ())?;
    Ok(state.encode_snapshot())
}

/// Verify, fee-fund, and atomically register a standard program in a consensus snapshot.
#[no_mangle]
pub extern "C" fn onyx_verify_apply_program_deployment(
    snapshot: *const u8,
    snapshot_len: usize,
    anchor_window_blocks: u64,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    funding_k: u32,
    program_k: u32,
    expected_network: *const u8,
    block_height: u64,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    fee_out: *mut u64,
    program_id_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || expected_network.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || fee_out.is_null()
            || program_id_out.is_null()
            || encoded_len == 0
            || encoded_len > program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || (snapshot.is_null() && snapshot_len != 0)
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *fee_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
        }
        let deployment = match program_deployment::AuthorizedProgramDeployment::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(deployment) => deployment,
            Err(_) => return -2,
        };
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if deployment.funding.preimage.network_id.as_slice() != network
            || block_height > deployment.funding.preimage.expiry_height
            || deployment.funding.preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        let entry = match verify_program_deployment_dispatch(
            &deployment,
            merkle_depth,
            funding_k,
            program_k,
            Some(block_height),
        ) {
            Ok(entry) => entry,
            Err(_) => return 0,
        };
        let program_id = match entry.id() {
            Ok(program_id) => program_id,
            Err(_) => return 0,
        };
        let snapshot_bytes = if snapshot_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(snapshot, snapshot_len) }
        };
        let next = match merkle_depth {
            2 => apply_program_deployment_to_snapshot::<2>(
                snapshot_bytes,
                anchor_window_blocks,
                &deployment,
                entry,
                block_height,
            ),
            4 => apply_program_deployment_to_snapshot::<4>(
                snapshot_bytes,
                anchor_window_blocks,
                &deployment,
                entry,
                block_height,
            ),
            32 => apply_program_deployment_to_snapshot::<32>(
                snapshot_bytes,
                anchor_window_blocks,
                &deployment,
                entry,
                block_height,
            ),
            _ => return -3,
        };
        let next = match next {
            Ok(next) => next,
            Err(_) => return -5,
        };
        if next.len() > MAX_STATE_SNAPSHOT_BYTES {
            return -6;
        }
        let (ptr, len) = into_raw(next);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            *fee_out = deployment.funding.preimage.fee;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
        }
        1
    })
}

/// Verify the proof and binding signature of a canonical token issuance and extract its delta.
/// Issuer authorization and cumulative supply are snapshot-dependent and are checked by apply.
#[no_mangle]
pub extern "C" fn onyx_verify_and_extract_token_issuance(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    circuit_k: u32,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    program_id_out: *mut u8,
    sequence_out: *mut u64,
    issued_amount_out: *mut u64,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > token_issuance::MAX_TOKEN_ISSUANCE_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || program_id_out.is_null()
            || sequence_out.is_null()
            || issued_amount_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
            *sequence_out = 0;
            *issued_amount_out = 0;
            *commitment_count_out = 0;
        }
        let issuance = match token_issuance::AuthorizedTokenIssuance::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(issuance) => issuance,
            Err(_) => return -2,
        };
        let preimage = &issuance.transaction.preimage;
        if commitment_capacity < preimage.outputs.len() {
            return -4;
        }
        if verify_token_issuance_dispatch(&issuance, merkle_depth, circuit_k, None, 0).is_err() {
            return 0;
        }
        let program_id = preimage.programs[0].program_id;
        unsafe {
            std::ptr::copy_nonoverlapping(preimage.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(preimage.anchor.bytes().as_ptr(), anchor_out, 32);
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
            *expiry_height_out = preimage.expiry_height;
            *sequence_out = issuance.sequence;
            *issued_amount_out = issuance.issued_amount;
            *commitment_count_out = preimage.outputs.len();
            for (index, output) in preimage.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

fn apply_token_issuance_to_snapshot<const DEPTH: usize>(
    snapshot: &[u8],
    issuance: &token_issuance::AuthorizedTokenIssuance,
    block_height: u64,
    circuit_k: u32,
) -> Result<Vec<u8>, ()> {
    let mut state = state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| ())?;
    verify_token_issuance_dispatch(
        issuance,
        DEPTH as u32,
        circuit_k,
        Some(state.program_registry()),
        block_height,
    )?;
    state
        .apply_token_issuance(
            &issuance.transaction.preimage,
            issuance.sequence,
            issuance.issued_amount,
            block_height,
        )
        .map_err(|_| ())?;
    Ok(state.encode_snapshot())
}

/// Verify issuer, proof, cap, sequence, and active registry entry, then atomically apply issuance.
#[no_mangle]
pub extern "C" fn onyx_verify_apply_token_issuance(
    snapshot: *const u8,
    snapshot_len: usize,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    circuit_k: u32,
    expected_network: *const u8,
    block_height: u64,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    program_id_out: *mut u8,
    sequence_out: *mut u64,
    issued_amount_out: *mut u64,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > token_issuance::MAX_TOKEN_ISSUANCE_BYTES
            || expected_network.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || program_id_out.is_null()
            || sequence_out.is_null()
            || issued_amount_out.is_null()
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *sequence_out = 0;
            *issued_amount_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
        }
        let issuance = match token_issuance::AuthorizedTokenIssuance::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(issuance) => issuance,
            Err(_) => return -2,
        };
        let preimage = &issuance.transaction.preimage;
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if preimage.network_id.as_slice() != network
            || block_height > preimage.expiry_height
            || preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        let snapshot = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };
        let next = match merkle_depth {
            2 => {
                apply_token_issuance_to_snapshot::<2>(snapshot, &issuance, block_height, circuit_k)
            }
            4 => {
                apply_token_issuance_to_snapshot::<4>(snapshot, &issuance, block_height, circuit_k)
            }
            32 => {
                apply_token_issuance_to_snapshot::<32>(snapshot, &issuance, block_height, circuit_k)
            }
            _ => return -3,
        };
        let next = match next {
            Ok(next) => next,
            Err(_) => return -5,
        };
        if next.len() > MAX_STATE_SNAPSHOT_BYTES {
            return -6;
        }
        let program_id = preimage.programs[0].program_id;
        let (ptr, len) = into_raw(next);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
            *sequence_out = issuance.sequence;
            *issued_amount_out = issuance.issued_amount;
        }
        1
    })
}

fn apply_transfer_to_snapshot<const DEPTH: usize>(
    snapshot: &[u8],
    anchor_window_blocks: u64,
    transaction: &transaction::AuthorizedTransaction,
    block_height: u64,
    circuit_k: u32,
) -> Result<Vec<u8>, i32> {
    let mut state = if snapshot.is_empty() {
        if anchor_window_blocks == 0 {
            return Err(-5);
        }
        state::ShieldedState::<DEPTH>::new(anchor_window_blocks)
    } else {
        state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| -5)?
    };
    let verified = verify_transfer_dispatch(
        transaction,
        DEPTH as u32,
        circuit_k,
        Some(state.program_registry()),
        block_height,
    );
    if verified != 1 {
        return Err(verified);
    }
    state
        .apply_transfer(&transaction.preimage, block_height)
        .map_err(|_| -5)?;
    Ok(state.encode_snapshot())
}

/// Verify an authorized transfer and atomically advance a canonical shielded-state snapshot.
/// An empty input snapshot initializes state using `anchor_window_blocks`; subsequent calls decode
/// the window from the snapshot. Return values extend the verifier convention with -5 for a
/// network/expiry/state transition violation and -6 for an oversized resulting snapshot.
#[no_mangle]
pub extern "C" fn onyx_verify_apply_transfer(
    snapshot: *const u8,
    snapshot_len: usize,
    anchor_window_blocks: u64,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    native_k: u32,
    token_k: u32,
    expected_network: *const u8,
    block_height: u64,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    fee_out: *mut u64,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || expected_network.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || fee_out.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || (snapshot.is_null() && snapshot_len != 0)
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *fee_out = 0;
        }
        let transaction = match transaction::AuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        let circuit_k = match transfer_circuit_k(&transaction, native_k, token_k) {
            Ok(circuit_k) => circuit_k,
            Err(_) => return -3,
        };
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if transaction.preimage.network_id.as_slice() != network
            || block_height > transaction.preimage.expiry_height
            || transaction.preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        let snapshot_bytes = if snapshot_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(snapshot, snapshot_len) }
        };
        let next = match merkle_depth {
            2 => apply_transfer_to_snapshot::<2>(
                snapshot_bytes,
                anchor_window_blocks,
                &transaction,
                block_height,
                circuit_k,
            ),
            4 => apply_transfer_to_snapshot::<4>(
                snapshot_bytes,
                anchor_window_blocks,
                &transaction,
                block_height,
                circuit_k,
            ),
            32 => apply_transfer_to_snapshot::<32>(
                snapshot_bytes,
                anchor_window_blocks,
                &transaction,
                block_height,
                circuit_k,
            ),
            _ => return -3,
        };
        let next = match next {
            Ok(next) => next,
            Err(code) => return code,
        };
        if next.len() > MAX_STATE_SNAPSHOT_BYTES {
            return -6;
        }
        let fee = transaction.preimage.fee;
        let (ptr, len) = into_raw(next);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            *fee_out = fee;
        }
        1
    })
}

fn apply_standard_contextual_to_snapshot<const DEPTH: usize>(
    snapshot: &[u8],
    envelope: &program_context::ContextualAuthorizedTransaction,
    block_height: u64,
    circuit_k: u32,
) -> Result<Vec<u8>, ()> {
    let mut state = state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| ())?;
    envelope
        .verify_standard(
            state.program_registry(),
            block_height,
            DEPTH as u32,
            circuit_k,
        )
        .map_err(|_| ())?;
    state
        .apply_contextual_transaction(
            &envelope.transaction.preimage,
            block_height,
            &envelope.contexts,
        )
        .map_err(|_| ())?;
    Ok(state.encode_snapshot())
}

/// Verify a pinned standard-program proof bundle and atomically apply its value and program-state
/// transitions to an existing registry-bearing consensus snapshot.
#[no_mangle]
pub extern "C" fn onyx_verify_apply_standard_program_transaction(
    snapshot: *const u8,
    snapshot_len: usize,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    circuit_k: u32,
    expected_network: *const u8,
    block_height: u64,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
            || expected_network.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
        }
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        let envelope = match program_context::ContextualAuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(envelope) => envelope,
            Err(_) => return -2,
        };
        let preimage = &envelope.transaction.preimage;
        if nullifier_capacity < preimage.spends.len()
            || commitment_capacity < preimage.outputs.len()
        {
            return -4;
        }
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if preimage.network_id.as_slice() != network
            || block_height > preimage.expiry_height
            || preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        let snapshot = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };
        let next = match merkle_depth {
            2 => apply_standard_contextual_to_snapshot::<2>(
                snapshot,
                &envelope,
                block_height,
                circuit_k,
            ),
            4 => apply_standard_contextual_to_snapshot::<4>(
                snapshot,
                &envelope,
                block_height,
                circuit_k,
            ),
            32 => apply_standard_contextual_to_snapshot::<32>(
                snapshot,
                &envelope,
                block_height,
                circuit_k,
            ),
            _ => return -3,
        };
        let next = match next {
            Ok(next) => next,
            Err(_) => return -5,
        };
        if next.len() > MAX_STATE_SNAPSHOT_BYTES {
            return -6;
        }
        let (ptr, len) = into_raw(next);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            std::ptr::copy_nonoverlapping(preimage.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(preimage.anchor.bytes().as_ptr(), anchor_out, 32);
            *expiry_height_out = preimage.expiry_height;
            *nullifier_count_out = preimage.spends.len();
            *commitment_count_out = preimage.outputs.len();
            for (index, spend) in preimage.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in preimage.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
        }
        1
    })
}

/// Extract the signed value-layer delta from a contextual standard-program envelope. This helper
/// is intentionally state-independent so pool bookkeeping can remove an already-applied envelope;
/// consensus admission must still use `onyx_verify_apply_standard_program_transaction`.
#[no_mangle]
pub extern "C" fn onyx_extract_authenticated_standard_program_delta(
    encoded: *const u8,
    encoded_len: usize,
    network_out: *mut u8,
    anchor_out: *mut u8,
    expiry_height_out: *mut u64,
    nullifiers_out: *mut u8,
    nullifier_capacity: usize,
    nullifier_count_out: *mut usize,
    commitments_out: *mut u8,
    commitment_capacity: usize,
    commitment_count_out: *mut usize,
    state_keys_out: *mut u8,
    state_key_capacity: usize,
    state_key_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
            || network_out.is_null()
            || anchor_out.is_null()
            || expiry_height_out.is_null()
            || nullifiers_out.is_null()
            || nullifier_count_out.is_null()
            || commitments_out.is_null()
            || commitment_count_out.is_null()
            || state_keys_out.is_null()
            || state_key_count_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(network_out, 0, 16);
            std::ptr::write_bytes(anchor_out, 0, 32);
            *expiry_height_out = 0;
            *nullifier_count_out = 0;
            *commitment_count_out = 0;
            *state_key_count_out = 0;
        }
        let envelope = match program_context::ContextualAuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(envelope) => envelope,
            Err(_) => return -2,
        };
        let preimage = &envelope.transaction.preimage;
        if nullifier_capacity < preimage.spends.len()
            || commitment_capacity < preimage.outputs.len()
            || state_key_capacity < envelope.contexts.len()
        {
            return -4;
        }
        if authorization::verify_authorized_transaction(&envelope.transaction).is_err() {
            return 0;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(preimage.network_id.as_ptr(), network_out, 16);
            std::ptr::copy_nonoverlapping(preimage.anchor.bytes().as_ptr(), anchor_out, 32);
            *expiry_height_out = preimage.expiry_height;
            *nullifier_count_out = preimage.spends.len();
            *commitment_count_out = preimage.outputs.len();
            *state_key_count_out = envelope.contexts.len();
            for (index, spend) in preimage.spends.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    spend.nullifier.0.as_ptr(),
                    nullifiers_out.add(index * 32),
                    32,
                );
            }
            for (index, output) in preimage.outputs.iter().enumerate() {
                std::ptr::copy_nonoverlapping(
                    output.commitment.bytes().as_ptr(),
                    commitments_out.add(index * 32),
                    32,
                );
            }
            for (index, context) in envelope.contexts.iter().enumerate() {
                let application =
                    match standard_programs::StandardApplication::decode(&context.application_data)
                    {
                        Ok(application) => application,
                        Err(_) => return -2,
                    };
                let key = match application.state_key(&context.program_id) {
                    Ok(key) => key,
                    Err(_) => return -2,
                };
                std::ptr::copy_nonoverlapping(key.as_ptr(), state_keys_out.add(index * 32), 32);
            }
        }
        1
    })
}

fn precheck_authenticated_standard_program_state<const DEPTH: usize>(
    snapshot: &[u8],
    envelope: &program_context::ContextualAuthorizedTransaction,
) -> Result<bool, ()> {
    let state = state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| ())?;
    if envelope
        .transaction
        .preimage
        .spends
        .iter()
        .any(|spend| state.is_spent(&spend.nullifier))
    {
        return Ok(false);
    }
    for (call, context) in envelope
        .transaction
        .preimage
        .programs
        .iter()
        .zip(&envelope.contexts)
    {
        let application = standard_programs::StandardApplication::decode(&context.application_data)
            .map_err(|_| ())?;
        let state_key = application.state_key(&call.program_id).map_err(|_| ())?;
        let transition = context.state.as_ref().ok_or(())?;
        let prior = state::CanonicalField::from_bytes(transition.prior).ok_or(())?;
        if state
            .standard_program_state_by_key(&state_key)
            .is_some_and(|current| current != prior)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn precheck_authenticated_transfer_state<const DEPTH: usize>(
    snapshot: &[u8],
    transaction: &transaction::AuthorizedTransaction,
) -> Result<bool, ()> {
    let state = state::ShieldedState::<DEPTH>::decode_snapshot(snapshot).map_err(|_| ())?;
    Ok(!transaction
        .preimage
        .spends
        .iter()
        .any(|spend| state.is_spent(&spend.nullifier)))
}

/// Authenticate a transfer and cheaply reject nullifiers already spent in the snapshot. Full
/// proof verification and state application remain mandatory after an eligible result.
#[no_mangle]
pub extern "C" fn onyx_precheck_authenticated_transfer_state(
    snapshot: *const u8,
    snapshot_len: usize,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
        {
            return -1;
        }
        let transaction = match transaction::AuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        if authorization::verify_authorized_transaction(&transaction).is_err() {
            return -2;
        }
        let snapshot = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };
        let eligible = match merkle_depth {
            2 => precheck_authenticated_transfer_state::<2>(snapshot, &transaction),
            4 => precheck_authenticated_transfer_state::<4>(snapshot, &transaction),
            32 => precheck_authenticated_transfer_state::<32>(snapshot, &transaction),
            _ => return -3,
        };
        match eligible {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -2,
        }
    })
}

/// Authenticate and decode a contextual standard-program envelope, then reject already-spent
/// nullifiers or stale prior states without invoking Halo2. This is a mempool admission precheck
/// only; callers must still run the complete verifier before admission and block application.
/// Returns 1 when no cheap conflict is present, 0 for a chain-state conflict, and a negative value
/// for malformed input, invalid authorization, snapshot failure, or unsupported depth.
#[no_mangle]
pub extern "C" fn onyx_precheck_authenticated_standard_program_state(
    snapshot: *const u8,
    snapshot_len: usize,
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
        {
            return -1;
        }
        let envelope = match program_context::ContextualAuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(envelope) => envelope,
            Err(_) => return -2,
        };
        if authorization::verify_authorized_transaction(&envelope.transaction).is_err() {
            return -2;
        }
        let snapshot = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };
        let eligible = match merkle_depth {
            2 => precheck_authenticated_standard_program_state::<2>(snapshot, &envelope),
            4 => precheck_authenticated_standard_program_state::<4>(snapshot, &envelope),
            32 => precheck_authenticated_standard_program_state::<32>(snapshot, &envelope),
            _ => return -3,
        };
        match eligible {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -2,
        }
    })
}

/// Verify and apply a one-way legacy bridge envelope. The C++ caller must additionally validate
/// the returned ownership signature against the disclosed legacy output public key, then atomically
/// record the returned key image in legacy spent state together with this snapshot.
#[no_mangle]
pub extern "C" fn onyx_verify_apply_bridge(
    snapshot: *const u8,
    snapshot_len: usize,
    anchor_window_blocks: u64,
    encoded: *const u8,
    encoded_len: usize,
    circuit_k: u32,
    expected_network: *const u8,
    block_height: u64,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    legacy_amount_out: *mut u64,
    legacy_stack_index_out: *mut u64,
    legacy_key_image_out: *mut u8,
    ownership_sighash_out: *mut u8,
    ownership_signature_out: *mut u8,
    fee_out: *mut u64,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || expected_network.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || legacy_amount_out.is_null()
            || legacy_stack_index_out.is_null()
            || legacy_key_image_out.is_null()
            || ownership_sighash_out.is_null()
            || ownership_signature_out.is_null()
            || fee_out.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || (snapshot.is_null() && snapshot_len != 0)
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *legacy_amount_out = 0;
            *legacy_stack_index_out = 0;
            std::ptr::write_bytes(legacy_key_image_out, 0, 32);
            std::ptr::write_bytes(ownership_sighash_out, 0, 32);
            std::ptr::write_bytes(ownership_signature_out, 0, 64);
            *fee_out = 0;
        }
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        let bridge = match bridge::AuthorizedBridge::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(bridge) => bridge,
            Err(_) => return -2,
        };
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if bridge.preimage.network_id.as_slice() != network
            || block_height > bridge.preimage.expiry_height
            || bridge.preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        if proof::verify_bridge_proof(circuit_k, &bridge).is_err() {
            return 0;
        }
        let snapshot_bytes = if snapshot_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(snapshot, snapshot_len) }
        };
        let mut state = if snapshot_bytes.is_empty() {
            if anchor_window_blocks == 0 {
                return -5;
            }
            state::ShieldedState::<32>::new(anchor_window_blocks)
        } else {
            match state::ShieldedState::<32>::decode_snapshot(snapshot_bytes) {
                Ok(state) => state,
                Err(_) => return -5,
            }
        };
        let transition = transaction::TransactionPreimage {
            network_id: bridge.preimage.network_id,
            anchor: state.root(),
            expiry_height: bridge.preimage.expiry_height,
            fee: 0,
            spends: vec![],
            outputs: vec![bridge.preimage.output.clone()],
            programs: vec![],
        };
        if state
            .apply_bridge(
                &transition,
                bridge.preimage.legacy_key_image,
                bridge.preimage.legacy_amount,
                bridge.preimage.fee,
                block_height,
            )
            .is_err()
        {
            return -5;
        }
        let next = state.encode_snapshot();
        if next.len() > MAX_STATE_SNAPSHOT_BYTES {
            return -6;
        }
        let ownership_sighash = match bridge.ownership_sighash() {
            Ok(hash) => hash,
            Err(_) => return -2,
        };
        let (ptr, len) = into_raw(next);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            *legacy_amount_out = bridge.preimage.legacy_amount;
            *legacy_stack_index_out = bridge.preimage.legacy_stack_index;
            *fee_out = bridge.preimage.fee;
            std::ptr::copy_nonoverlapping(
                bridge.preimage.legacy_key_image.as_ptr(),
                legacy_key_image_out,
                32,
            );
            std::ptr::copy_nonoverlapping(ownership_sighash.as_ptr(), ownership_sighash_out, 32);
            std::ptr::copy_nonoverlapping(
                bridge.ownership_signature.as_ptr(),
                ownership_signature_out,
                64,
            );
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_state_supply_audit(
    snapshot: *const u8,
    snapshot_len: usize,
    total_bridged_out: *mut u64,
    total_fees_out: *mut u64,
    circulating_supply_out: *mut u64,
    leaf_count_out: *mut u64,
    program_count_out: *mut u64,
    current_block_program_cost_out: *mut u64,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || total_bridged_out.is_null()
            || total_fees_out.is_null()
            || circulating_supply_out.is_null()
            || leaf_count_out.is_null()
            || program_count_out.is_null()
            || current_block_program_cost_out.is_null()
            || root_out.is_null()
        {
            return -1;
        }
        unsafe {
            *total_bridged_out = 0;
            *total_fees_out = 0;
            *circulating_supply_out = 0;
            *leaf_count_out = 0;
            *program_count_out = 0;
            *current_block_program_cost_out = 0;
            std::ptr::write_bytes(root_out, 0, 32);
        }
        let state = match state::ShieldedState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(state) => state,
            Err(_) => return -2,
        };
        unsafe {
            *total_bridged_out = state.total_bridged();
            *total_fees_out = state.total_fees();
            *circulating_supply_out = state.circulating_supply();
            *leaf_count_out = state.leaf_count();
            *program_count_out = state.program_count() as u64;
            *current_block_program_cost_out = state.current_block_program_cost();
            std::ptr::copy_nonoverlapping(state.root().bytes().as_ptr(), root_out, 32);
        }
        1
    })
}

/// Query the consensus-tracked state for a stable standard-program application identity.
#[no_mangle]
pub extern "C" fn onyx_state_standard_program_state(
    snapshot: *const u8,
    snapshot_len: usize,
    program_id: *const u8,
    application: *const u8,
    application_len: usize,
    state_out: *mut u8,
    found_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || program_id.is_null()
            || application.is_null()
            || application_len == 0
            || application_len > program_context::MAX_PROGRAM_PUBLIC_DATA_BYTES
            || state_out.is_null()
            || found_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(state_out, 0, 32);
            *found_out = 0;
        }
        let state = match state::ShieldedState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(state) => state,
            Err(_) => return -2,
        };
        let application = match standard_programs::StandardApplication::decode(unsafe {
            slice::from_raw_parts(application, application_len)
        }) {
            Ok(application) => application,
            Err(_) => return -3,
        };
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .unwrap();
        let value = match state.standard_program_state(&program_id, &application) {
            Ok(value) => value,
            Err(_) => return -3,
        };
        unsafe {
            *found_out = u8::from(value.is_some());
            if let Some(value) = value {
                let bytes = value.bytes();
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), state_out, 32);
            } else {
                std::ptr::write_bytes(state_out, 0, 32);
            }
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_verify_bridge(
    encoded: *const u8,
    encoded_len: usize,
    circuit_k: u32,
    legacy_amount_out: *mut u64,
    legacy_stack_index_out: *mut u64,
    legacy_key_image_out: *mut u8,
    ownership_sighash_out: *mut u8,
    ownership_signature_out: *mut u8,
    fee_out: *mut u64,
) -> i32 {
    ffi_i32(|| {
        if encoded.is_null()
            || legacy_amount_out.is_null()
            || legacy_stack_index_out.is_null()
            || legacy_key_image_out.is_null()
            || ownership_sighash_out.is_null()
            || ownership_signature_out.is_null()
            || fee_out.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
        {
            return -1;
        }
        unsafe {
            *legacy_amount_out = 0;
            *legacy_stack_index_out = 0;
            std::ptr::write_bytes(legacy_key_image_out, 0, 32);
            std::ptr::write_bytes(ownership_sighash_out, 0, 32);
            std::ptr::write_bytes(ownership_signature_out, 0, 64);
            *fee_out = 0;
        }
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        let bridge = match bridge::AuthorizedBridge::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(bridge) => bridge,
            Err(_) => return -2,
        };
        if proof::verify_bridge_proof(circuit_k, &bridge).is_err() {
            return 0;
        }
        let sighash = match bridge.ownership_sighash() {
            Ok(hash) => hash,
            Err(_) => return -2,
        };
        unsafe {
            *legacy_amount_out = bridge.preimage.legacy_amount;
            *legacy_stack_index_out = bridge.preimage.legacy_stack_index;
            *fee_out = bridge.preimage.fee;
            std::ptr::copy_nonoverlapping(
                bridge.preimage.legacy_key_image.as_ptr(),
                legacy_key_image_out,
                32,
            );
            std::ptr::copy_nonoverlapping(sighash.as_ptr(), ownership_sighash_out, 32);
            std::ptr::copy_nonoverlapping(
                bridge.ownership_signature.as_ptr(),
                ownership_signature_out,
                64,
            );
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_address(
    seed: *const u8,
    network: *const u8,
    address_index: u32,
    address_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if address_out.is_null() {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(address_out, 0, 91);
        }
        if seed.is_null() || network.is_null() {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .expect("fixed seed length");
        let network: [u8; 16] = unsafe { slice::from_raw_parts(network, 16) }
            .try_into()
            .expect("fixed network length");
        let address = match keys::MasterSeed::new(seed)
            .derive(network)
            .and_then(|keys| keys.address(address_index))
        {
            Ok(address) => address,
            Err(_) => return -2,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(address.network_id.as_ptr(), address_out, 16);
            std::ptr::copy_nonoverlapping(address.diversifier.as_ptr(), address_out.add(16), 11);
            std::ptr::copy_nonoverlapping(
                address.transmission_key.as_ptr(),
                address_out.add(27),
                32,
            );
            std::ptr::copy_nonoverlapping(
                address.spend_authority_key.as_ptr(),
                address_out.add(59),
                32,
            );
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn onyx_full_viewing_key(
    seed: *const u8,
    network: *const u8,
    viewing_key_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if viewing_key_out.is_null() {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(viewing_key_out, 0, keys::FULL_VIEWING_KEY_BYTES);
        }
        if seed.is_null() || network.is_null() {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .expect("fixed seed length");
        let network: [u8; 16] = unsafe { slice::from_raw_parts(network, 16) }
            .try_into()
            .expect("fixed network length");
        let viewing = match keys::MasterSeed::new(seed)
            .derive(network)
            .and_then(|keys| keys.full_viewing_key())
        {
            Ok(viewing) => viewing.encode(),
            Err(_) => return -2,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(viewing.as_ptr(), viewing_key_out, viewing.len());
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_scan(
    snapshot: *const u8,
    snapshot_len: usize,
    seed: *const u8,
    expected_network: *const u8,
    envelope_type: u8,
    block_height: u64,
    circuit_k: u32,
    program_k: u32,
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || balance_out.is_null()
            || note_count_out.is_null()
            || root_out.is_null()
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *balance_out = 0;
            *note_count_out = 0;
            std::ptr::write_bytes(root_out, 0, 32);
        }
        if seed.is_null()
            || expected_network.is_null()
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
            || !(10..=20).contains(&circuit_k)
            || !(10..=20).contains(&program_k)
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || (snapshot.is_null() && snapshot_len != 0)
        {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .expect("fixed seed length");
        let network: [u8; 16] = unsafe { slice::from_raw_parts(expected_network, 16) }
            .try_into()
            .expect("fixed network length");
        let keys = match keys::MasterSeed::new(seed)
            .derive(network)
            .and_then(|keys| keys.full_viewing_key())
        {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let mut wallet = if snapshot_len == 0 {
            wallet::WalletState::<32>::new(network)
        } else {
            match wallet::WalletState::<32>::decode_snapshot(unsafe {
                slice::from_raw_parts(snapshot, snapshot_len)
            }) {
                Ok(wallet) => wallet,
                Err(_) => return -2,
            }
        };
        let encoded = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let scanned = match envelope_type {
            0 => transaction::AuthorizedTransaction::decode(encoded)
                .map_err(|_| ())
                .and_then(|transaction| wallet.scan_transfer(&keys, &transaction).map_err(|_| ())),
            1 => bridge::AuthorizedBridge::decode(encoded)
                .map_err(|_| ())
                .and_then(|bridge| wallet.scan_bridge(&keys, &bridge).map_err(|_| ())),
            2 => program_deployment::AuthorizedProgramDeployment::decode(encoded)
                .map_err(|_| ())
                .and_then(|deployment| {
                    wallet
                        .record_program_deployment(&deployment, block_height, program_k)
                        .map_err(|_| ())?;
                    wallet
                        .scan_transfer(&keys, &deployment.funding)
                        .map_err(|_| ())
                }),
            3 => token_issuance::AuthorizedTokenIssuance::decode(encoded)
                .map_err(|_| ())
                .and_then(|issuance| {
                    wallet
                        .record_token_issuance_envelope(&issuance, block_height)
                        .map_err(|_| ())?;
                    wallet
                        .scan_transfer(&keys, &issuance.transaction)
                        .map_err(|_| ())
                }),
            4 => program_context::ContextualAuthorizedTransaction::decode(encoded)
                .map_err(|_| ())
                .and_then(|envelope| {
                    wallet
                        .scan_transfer(&keys, &envelope.transaction)
                        .map_err(|_| ())
                }),
            _ => return -3,
        };
        if scanned.is_err() {
            return -2;
        }
        let balance = match wallet.unspent_balance() {
            Ok(balance) => balance,
            Err(_) => return -2,
        };
        let root = wallet.root().bytes();
        let encoded = match wallet.encode_snapshot() {
            Ok(encoded) if encoded.len() <= MAX_STATE_SNAPSHOT_BYTES => encoded,
            _ => return -6,
        };
        let note_count = wallet.notes().len();
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            *balance_out = balance;
            *note_count_out = note_count;
            std::ptr::copy_nonoverlapping(root.as_ptr(), root_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_scan_viewing(
    snapshot: *const u8,
    snapshot_len: usize,
    viewing_key: *const u8,
    viewing_key_len: usize,
    envelope_type: u8,
    block_height: u64,
    circuit_k: u32,
    program_k: u32,
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || balance_out.is_null()
            || note_count_out.is_null()
            || root_out.is_null()
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *balance_out = 0;
            *note_count_out = 0;
            std::ptr::write_bytes(root_out, 0, 32);
        }
        if viewing_key.is_null()
            || viewing_key_len != keys::FULL_VIEWING_KEY_BYTES
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
            || !(10..=20).contains(&circuit_k)
            || !(10..=20).contains(&program_k)
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || (snapshot.is_null() && snapshot_len != 0)
        {
            return -1;
        }
        let keys = match keys::FullViewingKey::decode(unsafe {
            slice::from_raw_parts(viewing_key, viewing_key_len)
        }) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let network = keys.network_id();
        let mut wallet = if snapshot_len == 0 {
            wallet::WalletState::<32>::new(network)
        } else {
            match wallet::WalletState::<32>::decode_snapshot(unsafe {
                slice::from_raw_parts(snapshot, snapshot_len)
            }) {
                Ok(wallet) => wallet,
                Err(_) => return -2,
            }
        };
        let encoded = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let scanned = match envelope_type {
            0 => transaction::AuthorizedTransaction::decode(encoded)
                .map_err(|_| ())
                .and_then(|transaction| wallet.scan_transfer(&keys, &transaction).map_err(|_| ())),
            1 => bridge::AuthorizedBridge::decode(encoded)
                .map_err(|_| ())
                .and_then(|bridge| wallet.scan_bridge(&keys, &bridge).map_err(|_| ())),
            2 => program_deployment::AuthorizedProgramDeployment::decode(encoded)
                .map_err(|_| ())
                .and_then(|deployment| {
                    wallet
                        .record_program_deployment(&deployment, block_height, program_k)
                        .map_err(|_| ())?;
                    wallet
                        .scan_transfer(&keys, &deployment.funding)
                        .map_err(|_| ())
                }),
            3 => token_issuance::AuthorizedTokenIssuance::decode(encoded)
                .map_err(|_| ())
                .and_then(|issuance| {
                    wallet
                        .record_token_issuance_envelope(&issuance, block_height)
                        .map_err(|_| ())?;
                    wallet
                        .scan_transfer(&keys, &issuance.transaction)
                        .map_err(|_| ())
                }),
            4 => program_context::ContextualAuthorizedTransaction::decode(encoded)
                .map_err(|_| ())
                .and_then(|envelope| {
                    wallet
                        .scan_transfer(&keys, &envelope.transaction)
                        .map_err(|_| ())
                }),
            _ => return -3,
        };
        if scanned.is_err() {
            return -2;
        }
        let balance = match wallet.unspent_balance() {
            Ok(balance) => balance,
            Err(_) => return -2,
        };
        let root = wallet.root().bytes();
        let encoded = match wallet.encode_snapshot() {
            Ok(encoded) if encoded.len() <= MAX_STATE_SNAPSHOT_BYTES => encoded,
            _ => return -6,
        };
        let note_count = wallet.notes().len();
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
            *balance_out = balance;
            *note_count_out = note_count;
            std::ptr::copy_nonoverlapping(root.as_ptr(), root_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_reserve_spends(
    snapshot: *const u8,
    snapshot_len: usize,
    seed: *const u8,
    expected_network: *const u8,
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if snapshot_out.is_null() || snapshot_len_out.is_null() {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || expected_network.is_null()
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES
        {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .expect("fixed seed length");
        let network: [u8; 16] = unsafe { slice::from_raw_parts(expected_network, 16) }
            .try_into()
            .expect("fixed network length");
        let keys = match keys::MasterSeed::new(seed)
            .derive(network)
            .and_then(|keys| keys.full_viewing_key())
        {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let mut wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let encoded = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let transaction = match transaction::AuthorizedTransaction::decode(encoded) {
            Ok(transaction) => transaction,
            Err(_) => match program_context::ContextualAuthorizedTransaction::decode(encoded) {
                Ok(envelope) => envelope.transaction,
                Err(_) => return -2,
            },
        };
        if wallet.reserve_transfer_spends(&keys, &transaction).is_err() {
            return -2;
        }
        let encoded = match wallet.encode_snapshot() {
            Ok(encoded) if encoded.len() <= MAX_STATE_SNAPSHOT_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_reserve_deployment_spends(
    snapshot: *const u8,
    snapshot_len: usize,
    seed: *const u8,
    expected_network: *const u8,
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if snapshot_out.is_null() || snapshot_len_out.is_null() {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || expected_network.is_null()
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES
        {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let network: [u8; 16] = unsafe { slice::from_raw_parts(expected_network, 16) }
            .try_into()
            .unwrap();
        let keys = match keys::MasterSeed::new(seed)
            .derive(network)
            .and_then(|keys| keys.full_viewing_key())
        {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let mut wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let deployment = match program_deployment::AuthorizedProgramDeployment::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(deployment) => deployment,
            Err(_) => return -2,
        };
        if wallet
            .reserve_transfer_spends(&keys, &deployment.funding)
            .is_err()
        {
            return -2;
        }
        let encoded = match wallet.encode_snapshot() {
            Ok(encoded) if encoded.len() <= MAX_STATE_SNAPSHOT_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *snapshot_out = ptr;
            *snapshot_len_out = len;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_summary(
    snapshot: *const u8,
    snapshot_len: usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if balance_out.is_null() || note_count_out.is_null() || root_out.is_null() {
            return -1;
        }
        unsafe {
            *balance_out = 0;
            *note_count_out = 0;
            std::ptr::write_bytes(root_out, 0, 32);
        }
        if snapshot.is_null() || snapshot_len == 0 || snapshot_len > MAX_STATE_SNAPSHOT_BYTES {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let balance = match wallet.unspent_balance() {
            Ok(balance) => balance,
            Err(_) => return -2,
        };
        unsafe {
            *balance_out = balance;
            *note_count_out = wallet.notes().len();
            std::ptr::copy_nonoverlapping(wallet.root().bytes().as_ptr(), root_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_asset_balance(
    snapshot: *const u8,
    snapshot_len: usize,
    program_id: *const u8,
    asset_id: *const u8,
    balance_out: *mut u64,
    unspent_note_count_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if balance_out.is_null() || unspent_note_count_out.is_null() {
            return -1;
        }
        unsafe {
            *balance_out = 0;
            *unspent_note_count_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || program_id.is_null()
            || asset_id.is_null()
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .expect("fixed program id length");
        let asset_id: [u8; 32] = unsafe { slice::from_raw_parts(asset_id, 32) }
            .try_into()
            .expect("fixed asset id length");
        let balance = match wallet.unspent_asset_balance(&program_id, &asset_id) {
            Ok(balance) => balance,
            Err(_) => return -2,
        };
        unsafe {
            *balance_out = balance;
            *unspent_note_count_out = wallet.unspent_asset_note_count(&program_id, &asset_id);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_token_program_status(
    snapshot: *const u8,
    snapshot_len: usize,
    program_id: *const u8,
    query_height: u64,
    issuer_out: *mut u8,
    max_supply_out: *mut u64,
    issued_supply_out: *mut u64,
    next_sequence_out: *mut u64,
    activation_height_out: *mut u64,
    deactivation_height_out: *mut u64,
    active_out: *mut i32,
    metadata_out: *mut *mut u8,
    metadata_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if issuer_out.is_null()
            || max_supply_out.is_null()
            || issued_supply_out.is_null()
            || next_sequence_out.is_null()
            || activation_height_out.is_null()
            || deactivation_height_out.is_null()
            || active_out.is_null()
            || metadata_out.is_null()
            || metadata_len_out.is_null()
        {
            return -1;
        }
        unsafe {
            std::ptr::write_bytes(issuer_out, 0, 32);
            *max_supply_out = 0;
            *issued_supply_out = 0;
            *next_sequence_out = 0;
            *activation_height_out = 0;
            *deactivation_height_out = 0;
            *active_out = 0;
            *metadata_out = std::ptr::null_mut();
            *metadata_len_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || program_id.is_null()
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .unwrap();
        let entry = match wallet.program_registry().get(&program_id) {
            Some(entry) => entry,
            None => return -5,
        };
        let (_, _, policy) = match token_program::issuance_policy_from_entry(entry) {
            Ok(policy) => policy,
            Err(_) => return -5,
        };
        let active = query_height >= entry.activation_height
            && entry
                .deactivation_height
                .is_none_or(|height| query_height < height);
        let (metadata_ptr, metadata_len) = into_raw(policy.metadata);
        unsafe {
            std::ptr::copy_nonoverlapping(policy.issuer.as_ptr(), issuer_out, 32);
            *max_supply_out = policy.max_supply;
            *issued_supply_out = wallet.token_issued_supply(&program_id);
            *next_sequence_out = wallet.token_next_issuance_sequence(&program_id);
            *activation_height_out = entry.activation_height;
            *deactivation_height_out = entry.deactivation_height.unwrap_or(0);
            *active_out = i32::from(active);
            *metadata_out = metadata_ptr;
            *metadata_len_out = metadata_len;
        }
        1
    })
}

fn token_program_descriptor<const DEPTH: usize>(
    issuer: [u8; 32],
    max_supply: u64,
    metadata: Vec<u8>,
    activation_height: u64,
    deactivation_height: Option<u64>,
    circuit_k: u32,
) -> Result<(Vec<u8>, [u8; 32]), ()> {
    let manifest = (token_program::TokenIssuancePolicy {
        issuer,
        max_supply,
        metadata,
    })
    .encode()
    .map_err(|_| ())?;
    let entry = token_program::standard_token_program::<DEPTH>(
        circuit_k,
        &manifest,
        activation_height,
        deactivation_height,
    )
    .map_err(|_| ())?;
    let program_id = entry.id().map_err(|_| ())?;
    Ok((manifest, program_id))
}

#[no_mangle]
pub extern "C" fn onyx_token_program_descriptor(
    issuer: *const u8,
    max_supply: u64,
    metadata: *const u8,
    metadata_len: usize,
    activation_height: u64,
    deactivation_height: u64,
    circuit_k: u32,
    manifest_out: *mut *mut u8,
    manifest_len_out: *mut usize,
    program_id_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if manifest_out.is_null() || manifest_len_out.is_null() || program_id_out.is_null() {
            return -1;
        }
        unsafe {
            *manifest_out = std::ptr::null_mut();
            *manifest_len_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
        }
        if issuer.is_null()
            || max_supply == 0
            || metadata.is_null()
            || metadata_len == 0
            || metadata_len > 128
            || (deactivation_height != 0 && deactivation_height <= activation_height)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let issuer = unsafe { slice::from_raw_parts(issuer, 32) }
            .try_into()
            .unwrap();
        let metadata = unsafe { slice::from_raw_parts(metadata, metadata_len) }.to_vec();
        let deactivation = (deactivation_height != 0).then_some(deactivation_height);
        let (manifest, program_id) = match token_program_descriptor::<32>(
            issuer,
            max_supply,
            metadata,
            activation_height,
            deactivation,
            circuit_k,
        ) {
            Ok(descriptor) => descriptor,
            Err(()) => return -2,
        };
        let (manifest_ptr, manifest_len) = into_raw(manifest);
        unsafe {
            *manifest_out = manifest_ptr;
            *manifest_len_out = manifest_len;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_bridge(
    seed: *const u8,
    recipient: *const u8,
    expiry_height: u64,
    fee: u64,
    legacy_amount: u64,
    legacy_stack_index: u64,
    legacy_key_image: *const u8,
    memo: *const u8,
    memo_len: usize,
    circuit_k: u32,
    bridge_out: *mut *mut u8,
    bridge_len_out: *mut usize,
    ownership_sighash_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if bridge_out.is_null() || bridge_len_out.is_null() || ownership_sighash_out.is_null() {
            return -1;
        }
        unsafe {
            *bridge_out = std::ptr::null_mut();
            *bridge_len_out = 0;
            std::ptr::write_bytes(ownership_sighash_out, 0, 32);
        }
        if seed.is_null()
            || recipient.is_null()
            || legacy_key_image.is_null()
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .expect("fixed seed length");
        let recipient = unsafe { slice::from_raw_parts(recipient, 91) };
        let address = keys::RecipientAddress {
            network_id: recipient[0..16].try_into().unwrap(),
            diversifier: recipient[16..27].try_into().unwrap(),
            transmission_key: recipient[27..59].try_into().unwrap(),
            spend_authority_key: recipient[59..91].try_into().unwrap(),
        };
        let sender = match keys::MasterSeed::new(seed).derive(address.network_id) {
            Ok(sender) => sender,
            Err(_) => return -2,
        };
        let bridge = match wallet::build_bridge(
            &sender,
            &address,
            expiry_height,
            fee,
            legacy_amount,
            legacy_stack_index,
            unsafe { slice::from_raw_parts(legacy_key_image, 32) }
                .try_into()
                .unwrap(),
            if memo_len == 0 {
                vec![]
            } else {
                unsafe { slice::from_raw_parts(memo, memo_len) }.to_vec()
            },
            circuit_k,
        ) {
            Ok(bridge) => bridge,
            Err(_) => return -2,
        };
        let sighash = match bridge.ownership_sighash() {
            Ok(sighash) => sighash,
            Err(_) => return -2,
        };
        let encoded = match bridge.encode() {
            Ok(encoded) if encoded.len() <= MAX_AUTHORIZED_TRANSACTION_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *bridge_out = ptr;
            *bridge_len_out = len;
            std::ptr::copy_nonoverlapping(sighash.as_ptr(), ownership_sighash_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_finalize_bridge(
    unsigned_bridge: *const u8,
    unsigned_bridge_len: usize,
    ownership_signature: *const u8,
    bridge_out: *mut *mut u8,
    bridge_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if bridge_out.is_null() || bridge_len_out.is_null() {
            return -1;
        }
        unsafe {
            *bridge_out = std::ptr::null_mut();
            *bridge_len_out = 0;
        }
        if unsigned_bridge.is_null()
            || ownership_signature.is_null()
            || unsigned_bridge_len == 0
            || unsigned_bridge_len > MAX_AUTHORIZED_TRANSACTION_BYTES
        {
            return -1;
        }
        let mut bridge = match bridge::AuthorizedBridge::decode(unsafe {
            slice::from_raw_parts(unsigned_bridge, unsigned_bridge_len)
        }) {
            Ok(bridge) => bridge,
            Err(_) => return -2,
        };
        bridge.ownership_signature = unsafe { slice::from_raw_parts(ownership_signature, 64) }
            .try_into()
            .unwrap();
        let encoded = match bridge.encode() {
            Ok(encoded) => encoded,
            Err(_) => return -2,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *bridge_out = ptr;
            *bridge_len_out = len;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_token_issuance(
    wallet_snapshot: *const u8,
    wallet_snapshot_len: usize,
    seed: *const u8,
    recipient: *const u8,
    program_id: *const u8,
    issued_amount: u64,
    inclusion_height: u64,
    expiry_height: u64,
    memo: *const u8,
    memo_len: usize,
    circuit_k: u32,
    issuance_out: *mut *mut u8,
    issuance_len_out: *mut usize,
    sequence_out: *mut u64,
) -> i32 {
    ffi_i32(|| {
        if issuance_out.is_null() || issuance_len_out.is_null() || sequence_out.is_null() {
            return -1;
        }
        unsafe {
            *issuance_out = std::ptr::null_mut();
            *issuance_len_out = 0;
            *sequence_out = 0;
        }
        if wallet_snapshot.is_null()
            || wallet_snapshot_len == 0
            || wallet_snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || recipient.is_null()
            || program_id.is_null()
            || issued_amount == 0
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(wallet_snapshot, wallet_snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .unwrap();
        let entry = match wallet.program_registry().get(&program_id) {
            Some(entry) => entry,
            None => return -5,
        };
        let (depth, manifest_k, policy) = match token_program::issuance_policy_from_entry(entry) {
            Ok(policy) => policy,
            Err(_) => return -5,
        };
        let sequence = wallet.token_next_issuance_sequence(&program_id);
        let remaining = match policy
            .max_supply
            .checked_sub(wallet.token_issued_supply(&program_id))
        {
            Some(remaining) => remaining,
            None => return -5,
        };
        if depth != 32
            || manifest_k != circuit_k
            || issued_amount > remaining
            || expiry_height < inclusion_height
            || expiry_height - inclusion_height > MAX_EXPIRY_DISTANCE_BLOCKS
            || wallet
                .program_registry()
                .active_function(
                    &program_id,
                    token_program::issuance_function_id(1).unwrap(),
                    inclusion_height,
                )
                .is_err()
        {
            return -5;
        }
        let recipient = unsafe { slice::from_raw_parts(recipient, 91) };
        let address = keys::RecipientAddress {
            network_id: recipient[0..16].try_into().unwrap(),
            diversifier: recipient[16..27].try_into().unwrap(),
            transmission_key: recipient[27..59].try_into().unwrap(),
            spend_authority_key: recipient[59..91].try_into().unwrap(),
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        if wallet.network_id() != address.network_id {
            return -8;
        }
        let issuer = match keys::MasterSeed::new(seed).derive(address.network_id) {
            Ok(issuer) => issuer,
            Err(_) => return -2,
        };
        if issuer
            .address(0)
            .map(|address| address.spend_authority_key)
            .ok()
            != Some(policy.issuer)
        {
            return -8;
        }
        let issuance = match wallet::build_token_issuance(
            &issuer,
            &address,
            wallet.root(),
            program_id,
            sequence,
            issued_amount,
            expiry_height,
            if memo_len == 0 {
                vec![]
            } else {
                unsafe { slice::from_raw_parts(memo, memo_len) }.to_vec()
            },
            circuit_k,
        ) {
            Ok(issuance) => issuance,
            Err(_) => return -2,
        };
        if verify_token_issuance_dispatch(
            &issuance,
            32,
            circuit_k,
            Some(wallet.program_registry()),
            inclusion_height,
        )
        .is_err()
        {
            return -2;
        }
        let encoded = match issuance.encode() {
            Ok(encoded) if encoded.len() <= token_issuance::MAX_TOKEN_ISSUANCE_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *issuance_out = ptr;
            *issuance_len_out = len;
            *sequence_out = sequence;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_program_deployment(
    wallet_snapshot: *const u8,
    wallet_snapshot_len: usize,
    seed: *const u8,
    max_supply: u64,
    metadata: *const u8,
    metadata_len: usize,
    inclusion_height: u64,
    activation_height: u64,
    deactivation_height: u64,
    expiry_height: u64,
    fee: u64,
    funding_k: u32,
    program_k: u32,
    deployment_out: *mut *mut u8,
    deployment_len_out: *mut usize,
    program_id_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if deployment_out.is_null() || deployment_len_out.is_null() || program_id_out.is_null() {
            return -1;
        }
        unsafe {
            *deployment_out = std::ptr::null_mut();
            *deployment_len_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
        }
        if wallet_snapshot.is_null()
            || wallet_snapshot_len == 0
            || wallet_snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || max_supply == 0
            || metadata.is_null()
            || metadata_len == 0
            || metadata_len > 128
            || activation_height <= inclusion_height
            || activation_height - inclusion_height
                > program_deployment::MAX_PROGRAM_ACTIVATION_DELAY
            || (deactivation_height != 0 && deactivation_height <= activation_height)
            || expiry_height < inclusion_height
            || expiry_height - inclusion_height > MAX_EXPIRY_DISTANCE_BLOCKS
            || fee < program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE
            || !(10..=20).contains(&funding_k)
            || !(10..=20).contains(&program_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(wallet_snapshot, wallet_snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let keys = match keys::MasterSeed::new(seed).derive(wallet.network_id()) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let issuer = match keys.address(0) {
            Ok(address) => address.spend_authority_key,
            Err(_) => return -2,
        };
        let manifest = match (token_program::TokenIssuancePolicy {
            issuer,
            max_supply,
            metadata: unsafe { slice::from_raw_parts(metadata, metadata_len) }.to_vec(),
        })
        .encode()
        {
            Ok(manifest) => manifest,
            Err(_) => return -1,
        };
        let deactivation = (deactivation_height != 0).then_some(deactivation_height);
        let deployment = match wallet.build_program_deployment(
            &keys,
            manifest,
            activation_height,
            deactivation,
            expiry_height,
            fee,
            program_k,
            funding_k,
        ) {
            Ok(deployment) => deployment,
            Err(_) => return -5,
        };
        if verify_program_deployment_dispatch(
            &deployment,
            32,
            funding_k,
            program_k,
            Some(inclusion_height),
        )
        .is_err()
        {
            return -2;
        }
        let program_id = deployment.funding.preimage.programs[0].program_id;
        let encoded = match deployment.encode() {
            Ok(encoded) if encoded.len() <= program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES => {
                encoded
            }
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *deployment_out = ptr;
            *deployment_len_out = len;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_standard_program_deployment(
    wallet_snapshot: *const u8,
    wallet_snapshot_len: usize,
    seed: *const u8,
    kind: u8,
    inclusion_height: u64,
    activation_height: u64,
    deactivation_height: u64,
    expiry_height: u64,
    fee: u64,
    circuit_k: u32,
    deployment_out: *mut *mut u8,
    deployment_len_out: *mut usize,
    program_id_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if deployment_out.is_null() || deployment_len_out.is_null() || program_id_out.is_null() {
            return -1;
        }
        unsafe {
            *deployment_out = std::ptr::null_mut();
            *deployment_len_out = 0;
            std::ptr::write_bytes(program_id_out, 0, 32);
        }
        let kind = match kind {
            1 => standard_programs::StandardProgramKind::Nft,
            2 => standard_programs::StandardProgramKind::Vesting,
            3 => standard_programs::StandardProgramKind::Multisig,
            4 => standard_programs::StandardProgramKind::Swap,
            _ => return -1,
        };
        if wallet_snapshot.is_null()
            || wallet_snapshot_len == 0
            || wallet_snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || activation_height <= inclusion_height
            || activation_height - inclusion_height
                > program_deployment::MAX_PROGRAM_ACTIVATION_DELAY
            || (deactivation_height != 0 && deactivation_height <= activation_height)
            || expiry_height < inclusion_height
            || expiry_height - inclusion_height > MAX_EXPIRY_DISTANCE_BLOCKS
            || fee < program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(wallet_snapshot, wallet_snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let keys = match keys::MasterSeed::new(seed).derive(wallet.network_id()) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let deactivation = (deactivation_height != 0).then_some(deactivation_height);
        let deployment = match wallet.build_standard_program_deployment(
            &keys,
            kind,
            activation_height,
            deactivation,
            expiry_height,
            fee,
            circuit_k,
        ) {
            Ok(deployment) => deployment,
            Err(_) => return -5,
        };
        if verify_program_deployment_dispatch(
            &deployment,
            32,
            circuit_k,
            circuit_k,
            Some(inclusion_height),
        )
        .is_err()
        {
            return -2;
        }
        let program_id = deployment.funding.preimage.programs[0].program_id;
        let encoded = match deployment.encode() {
            Ok(encoded) if encoded.len() <= program_deployment::MAX_PROGRAM_DEPLOYMENT_BYTES => {
                encoded
            }
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *deployment_out = ptr;
            *deployment_len_out = len;
            std::ptr::copy_nonoverlapping(program_id.as_ptr(), program_id_out, 32);
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_standard_program_call(
    wallet_snapshot: *const u8,
    wallet_snapshot_len: usize,
    seed: *const u8,
    program_id: *const u8,
    inclusion_height: u64,
    valid_from_height: u64,
    expiry_height: u64,
    application: *const u8,
    application_len: usize,
    prior_state: *const u8,
    next_state: *const u8,
    witness: *const u8,
    witness_count: usize,
    circuit_k: u32,
    transaction_out: *mut *mut u8,
    transaction_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if transaction_out.is_null() || transaction_len_out.is_null() {
            return -1;
        }
        unsafe {
            *transaction_out = std::ptr::null_mut();
            *transaction_len_out = 0;
        }
        if wallet_snapshot.is_null()
            || wallet_snapshot_len == 0
            || wallet_snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || program_id.is_null()
            || application.is_null()
            || application_len == 0
            || application_len > program_context::MAX_PROGRAM_PUBLIC_DATA_BYTES
            || prior_state.is_null()
            || next_state.is_null()
            || witness.is_null()
            || witness_count == 0
            || witness_count > 48
            || valid_from_height > inclusion_height
            || inclusion_height > expiry_height
            || expiry_height - inclusion_height > MAX_EXPIRY_DISTANCE_BLOCKS
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(wallet_snapshot, wallet_snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let keys = match keys::MasterSeed::new(seed).derive(wallet.network_id()) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .unwrap();
        let application = match standard_programs::StandardApplication::decode(unsafe {
            slice::from_raw_parts(application, application_len)
        }) {
            Ok(application) => application,
            Err(_) => return -1,
        };
        let prior_state = match state::CanonicalField::from_bytes(
            unsafe { slice::from_raw_parts(prior_state, 32) }
                .try_into()
                .unwrap(),
        ) {
            Some(value) => value,
            None => return -1,
        };
        let next_state = match state::CanonicalField::from_bytes(
            unsafe { slice::from_raw_parts(next_state, 32) }
                .try_into()
                .unwrap(),
        ) {
            Some(value) => value,
            None => return -1,
        };
        let witness_bytes = unsafe { slice::from_raw_parts(witness, witness_count * 32) };
        let mut witness_fields = Vec::with_capacity(witness_count);
        for encoded in witness_bytes.chunks_exact(32) {
            let Some(value) = state::CanonicalField::from_bytes(encoded.try_into().unwrap()) else {
                return -1;
            };
            witness_fields.push(value);
        }
        let envelope = match wallet.build_standard_program_call(
            &keys,
            program_id,
            valid_from_height,
            expiry_height,
            application,
            prior_state,
            next_state,
            witness_fields,
            circuit_k,
        ) {
            Ok(envelope) => envelope,
            Err(_) => return -5,
        };
        if envelope
            .verify_standard(wallet.program_registry(), inclusion_height, 32, circuit_k)
            .is_err()
        {
            return -2;
        }
        let encoded = match envelope.encode() {
            Ok(encoded) if encoded.len() <= program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES => {
                encoded
            }
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *transaction_out = ptr;
            *transaction_len_out = len;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_transfer(
    snapshot: *const u8,
    snapshot_len: usize,
    seed: *const u8,
    recipient: *const u8,
    amount: u64,
    fee: u64,
    expiry_height: u64,
    memo: *const u8,
    memo_len: usize,
    circuit_k: u32,
    transaction_out: *mut *mut u8,
    transaction_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if transaction_out.is_null() || transaction_len_out.is_null() {
            return -1;
        }
        unsafe {
            *transaction_out = std::ptr::null_mut();
            *transaction_len_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || recipient.is_null()
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let recipient = unsafe { slice::from_raw_parts(recipient, 91) };
        let address = keys::RecipientAddress {
            network_id: recipient[0..16].try_into().unwrap(),
            diversifier: recipient[16..27].try_into().unwrap(),
            transmission_key: recipient[27..59].try_into().unwrap(),
            spend_authority_key: recipient[59..91].try_into().unwrap(),
        };
        let keys = match keys::MasterSeed::new(seed).derive(address.network_id) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let transaction = match wallet.build_transfer(
            &keys,
            &address,
            amount,
            fee,
            expiry_height,
            if memo_len == 0 {
                vec![]
            } else {
                unsafe { slice::from_raw_parts(memo, memo_len) }.to_vec()
            },
            circuit_k,
        ) {
            Ok(transaction) => transaction,
            Err(wallet::WalletBuildError::InsufficientFunds) => return -7,
            Err(_) => return -2,
        };
        let encoded = match transaction.encode() {
            Ok(encoded) if encoded.len() <= MAX_AUTHORIZED_TRANSACTION_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *transaction_out = ptr;
            *transaction_len_out = len;
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn onyx_wallet_create_mixed_token_transfer(
    snapshot: *const u8,
    snapshot_len: usize,
    seed: *const u8,
    recipient: *const u8,
    program_id: *const u8,
    token_amount: u64,
    fee: u64,
    expiry_height: u64,
    memo: *const u8,
    memo_len: usize,
    circuit_k: u32,
    transaction_out: *mut *mut u8,
    transaction_len_out: *mut usize,
) -> i32 {
    ffi_i32(|| {
        if transaction_out.is_null() || transaction_len_out.is_null() {
            return -1;
        }
        unsafe {
            *transaction_out = std::ptr::null_mut();
            *transaction_len_out = 0;
        }
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || recipient.is_null()
            || program_id.is_null()
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        let wallet = match wallet::WalletState::<32>::decode_snapshot(unsafe {
            slice::from_raw_parts(snapshot, snapshot_len)
        }) {
            Ok(wallet) => wallet,
            Err(_) => return -2,
        };
        let seed: [u8; 32] = unsafe { slice::from_raw_parts(seed, 32) }
            .try_into()
            .unwrap();
        let program_id: [u8; 32] = unsafe { slice::from_raw_parts(program_id, 32) }
            .try_into()
            .unwrap();
        let recipient = unsafe { slice::from_raw_parts(recipient, 91) };
        let address = keys::RecipientAddress {
            network_id: recipient[0..16].try_into().unwrap(),
            diversifier: recipient[16..27].try_into().unwrap(),
            transmission_key: recipient[27..59].try_into().unwrap(),
            spend_authority_key: recipient[59..91].try_into().unwrap(),
        };
        let keys = match keys::MasterSeed::new(seed).derive(address.network_id) {
            Ok(keys) => keys,
            Err(_) => return -2,
        };
        let transaction = match wallet.build_mixed_token_transfer(
            &keys,
            &address,
            program_id,
            token_amount,
            fee,
            expiry_height,
            if memo_len == 0 {
                vec![]
            } else {
                unsafe { slice::from_raw_parts(memo, memo_len) }.to_vec()
            },
            circuit_k,
        ) {
            Ok(transaction) => transaction,
            Err(wallet::WalletBuildError::InsufficientFunds) => return -7,
            Err(_) => return -2,
        };
        if verify_transfer_dispatch(&transaction, 32, circuit_k, None, 0) != 1 {
            return -2;
        }
        let encoded = match transaction.encode() {
            Ok(encoded) if encoded.len() <= MAX_AUTHORIZED_TRANSACTION_BYTES => encoded,
            _ => return -6,
        };
        let (ptr, len) = into_raw(encoded);
        unsafe {
            *transaction_out = ptr;
            *transaction_len_out = len;
        }
        1
    })
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
    let input: [u8; 64] = unsafe { slice::from_raw_parts(input, 64) }
        .try_into()
        .expect("fixed Poseidon input length");
    unsafe {
        std::ptr::write_bytes(out, 0, 32);
    }
    let in_slice = input.as_slice();
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
    if out.is_null() {
        return -1;
    }
    if (input.is_null() && in_len != 0) || in_len > MAX_HASH_INPUT {
        unsafe {
            std::ptr::write_bytes(out, 0, 32);
        }
        return -1;
    }
    let bytes = if in_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(input, in_len) }.to_vec()
    };
    unsafe {
        std::ptr::write_bytes(out, 0, 32);
    }
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
    unsafe {
        *proof_out = std::ptr::null_mut();
        *proof_len = 0;
        *vk_out = std::ptr::null_mut();
        *vk_len = 0;
        std::ptr::write_bytes(public_out, 0, 32);
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

fn into_raw(v: Vec<u8>) -> (*mut u8, usize) {
    let boxed = v.into_boxed_slice();
    let len = boxed.len();
    (Box::into_raw(boxed) as *mut u8, len)
}

#[no_mangle]
pub extern "C" fn onyx_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        // Returned buffers are boxed slices, so pointer + length fully recover the allocation
        // layout without relying on an unobservable Vec capacity.
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_ffi_clears_outputs_before_input_validation() {
        let mut fixed = [0xffu8; 91];
        assert_eq!(
            onyx_wallet_address(std::ptr::null(), std::ptr::null(), 0, fixed.as_mut_ptr()),
            -1
        );
        assert_eq!(fixed, [0u8; 91]);

        let mut snapshot_out = 1usize as *mut u8;
        let mut snapshot_len = usize::MAX;
        let mut balance = u64::MAX;
        let mut note_count = usize::MAX;
        let mut root = [0xffu8; 32];
        assert_eq!(
            onyx_wallet_scan(
                std::ptr::null(),
                MAX_STATE_SNAPSHOT_BYTES + 1,
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                9,
                9,
                std::ptr::null(),
                0,
                &mut snapshot_out,
                &mut snapshot_len,
                &mut balance,
                &mut note_count,
                root.as_mut_ptr(),
            ),
            -1
        );
        assert!(snapshot_out.is_null());
        assert_eq!((snapshot_len, balance, note_count), (0, 0, 0));
        assert_eq!(root, [0u8; 32]);

        balance = u64::MAX;
        note_count = usize::MAX;
        root.fill(0xff);
        assert_eq!(
            onyx_wallet_summary(
                std::ptr::null(),
                MAX_STATE_SNAPSHOT_BYTES + 1,
                &mut balance,
                &mut note_count,
                root.as_mut_ptr(),
            ),
            -1
        );
        assert_eq!((balance, note_count), (0, 0));
        assert_eq!(root, [0u8; 32]);

        let mut encoded_out = 1usize as *mut u8;
        let mut encoded_len = usize::MAX;
        assert_eq!(
            onyx_wallet_finalize_bridge(
                std::ptr::null(),
                MAX_AUTHORIZED_TRANSACTION_BYTES + 1,
                std::ptr::null(),
                &mut encoded_out,
                &mut encoded_len,
            ),
            -1
        );
        assert!(encoded_out.is_null());
        assert_eq!(encoded_len, 0);

        let mut program_id = [0xffu8; 32];
        encoded_out = 1usize as *mut u8;
        encoded_len = usize::MAX;
        assert_eq!(
            onyx_wallet_create_standard_program_deployment(
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                0,
                9,
                &mut encoded_out,
                &mut encoded_len,
                program_id.as_mut_ptr(),
            ),
            -1
        );
        assert!(encoded_out.is_null());
        assert_eq!(encoded_len, 0);
        assert_eq!(program_id, [0u8; 32]);

        encoded_out = 1usize as *mut u8;
        encoded_len = usize::MAX;
        assert_eq!(
            onyx_wallet_create_transfer(
                std::ptr::null(),
                MAX_STATE_SNAPSHOT_BYTES + 1,
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                0,
                std::ptr::null(),
                types::MAX_MEMO_BYTES + 1,
                9,
                &mut encoded_out,
                &mut encoded_len,
            ),
            -1
        );
        assert!(encoded_out.is_null());
        assert_eq!(encoded_len, 0);
    }

    #[test]
    fn ffi_standard_state_query_reports_absent_identity() {
        let snapshot = state::ShieldedState::<32>::new(3).encode_snapshot();
        let program_id = [9u8; 32];
        let application = standard_programs::StandardApplication::Nft {
            collection_id: [1u8; 32],
            token_id: [2u8; 32],
            serial: 3,
            transfer_nonce: 1,
        }
        .encode()
        .unwrap();
        let mut value = [0xffu8; 32];
        let mut found = 0xff;
        assert_eq!(
            onyx_state_standard_program_state(
                snapshot.as_ptr(),
                snapshot.len(),
                program_id.as_ptr(),
                application.as_ptr(),
                application.len(),
                value.as_mut_ptr(),
                &mut found,
            ),
            1
        );
        assert_eq!(found, 0);
        assert_eq!(value, [0u8; 32]);
    }

    #[test]
    fn poseidon_is_deterministic_and_nonzero() {
        assert_eq!(onyx_abi_version(), ABI_VERSION);
        let input = [7u8; 64];
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        assert_eq!(onyx_poseidon_hash2(input.as_ptr(), out1.as_mut_ptr()), 0);
        assert_eq!(onyx_poseidon_hash2(input.as_ptr(), out2.as_mut_ptr()), 0);
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
        let mut in_place = input;
        let in_place_ptr = in_place.as_mut_ptr();
        assert_eq!(onyx_poseidon_hash2(in_place_ptr, in_place_ptr), 0);
        assert_eq!(&in_place[..32], &out1);
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
        let mut alias = [7u8; 32];
        let mut expected = [0u8; 32];
        assert_eq!(
            onyx_sinsemilla_hash(alias.as_ptr(), alias.len(), expected.as_mut_ptr()),
            0
        );
        let alias_ptr = alias.as_mut_ptr();
        assert_eq!(onyx_sinsemilla_hash(alias_ptr, alias.len(), alias_ptr), 0);
        assert_eq!(alias, expected);
        println!("sinsemilla(\"onyx\") = {}", hex(&out));
    }

    #[test]
    fn wallet_key_helpers_overwrite_caller_outputs() {
        let seed = [7u8; 32];
        let network = [9u8; 16];
        let mut address = [0xffu8; 91];
        assert_eq!(
            onyx_wallet_address(seed.as_ptr(), network.as_ptr(), 3, address.as_mut_ptr(),),
            0
        );
        assert_eq!(&address[..16], &network);
        assert_ne!(address, [0u8; 91]);

        let mut viewing_key = [0xffu8; keys::FULL_VIEWING_KEY_BYTES];
        assert_eq!(
            onyx_full_viewing_key(seed.as_ptr(), network.as_ptr(), viewing_key.as_mut_ptr()),
            0
        );
        assert_ne!(viewing_key, [0u8; keys::FULL_VIEWING_KEY_BYTES]);
    }

    #[test]
    fn ffi_rejects_oversized_inputs() {
        let input = [0u8; 1];
        let mut out = [0xffu8; 32];
        assert_eq!(
            onyx_sinsemilla_hash(input.as_ptr(), MAX_HASH_INPUT + 1, out.as_mut_ptr()),
            -1
        );
        assert_eq!(out, [0u8; 32]);
        out.fill(0xff);
        let invalid_field = [0xffu8; 64];
        assert_eq!(
            onyx_poseidon_hash2(invalid_field.as_ptr(), out.as_mut_ptr()),
            -2
        );
        assert_eq!(out, [0u8; 32]);

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
            onyx_verify_authorized_transfer(
                input.as_ptr(),
                MAX_AUTHORIZED_TRANSACTION_BYTES + 1,
                32,
                20,
            ),
            -1
        );
        assert_eq!(
            onyx_verify_authorized_transfer(input.as_ptr(), 1, 32, 20),
            -2
        );
        assert_eq!(
            onyx_verify_authorized_transfer(input.as_ptr(), 1, 32, 21),
            -3
        );
        assert_eq!(
            onyx_verify_authorized_transfer(std::ptr::null(), 1, 32, 20),
            -1
        );
        let mut expiry = u64::MAX;
        let mut nullifier_count = usize::MAX;
        let mut commitment_count = usize::MAX;
        let mut state_key_count = usize::MAX;
        assert_eq!(
            onyx_extract_authenticated_standard_program_delta(
                input.as_ptr(),
                program_context::MAX_CONTEXTUAL_TRANSACTION_BYTES + 1,
                out.as_mut_ptr(),
                out.as_mut_ptr(),
                &mut expiry,
                out.as_mut_ptr(),
                1,
                &mut nullifier_count,
                out.as_mut_ptr(),
                1,
                &mut commitment_count,
                out.as_mut_ptr(),
                1,
                &mut state_key_count,
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

        let invalid_issuer = [0u8; 32];
        let metadata = b"symbol=TEST";
        let mut manifest = 1usize as *mut u8;
        let mut manifest_len = usize::MAX;
        let mut program_id = [0xffu8; 32];
        assert_eq!(
            onyx_token_program_descriptor(
                invalid_issuer.as_ptr(),
                1_000_000,
                metadata.as_ptr(),
                metadata.len(),
                10,
                20,
                14,
                &mut manifest,
                &mut manifest_len,
                program_id.as_mut_ptr(),
            ),
            -2
        );
        assert!(manifest.is_null());
        assert_eq!(manifest_len, 0);
        assert_eq!(program_id, [0u8; 32]);
    }

    #[test]
    fn state_queries_clear_outputs_before_decode_failure() {
        let malformed = [0u8; 1];
        let mut total_bridged = u64::MAX;
        let mut total_fees = u64::MAX;
        let mut circulating_supply = u64::MAX;
        let mut leaf_count = u64::MAX;
        let mut program_count = u64::MAX;
        let mut current_block_program_cost = u64::MAX;
        let mut root = [0xffu8; 32];
        assert_eq!(
            onyx_state_supply_audit(
                malformed.as_ptr(),
                malformed.len(),
                &mut total_bridged,
                &mut total_fees,
                &mut circulating_supply,
                &mut leaf_count,
                &mut program_count,
                &mut current_block_program_cost,
                root.as_mut_ptr(),
            ),
            -2
        );
        assert_eq!(
            (
                total_bridged,
                total_fees,
                circulating_supply,
                leaf_count,
                program_count,
                current_block_program_cost,
            ),
            (0, 0, 0, 0, 0, 0)
        );
        assert_eq!(root, [0u8; 32]);

        let program_id = [1u8; 32];
        let mut state = [0xffu8; 32];
        let mut found = u8::MAX;
        assert_eq!(
            onyx_state_standard_program_state(
                malformed.as_ptr(),
                malformed.len(),
                program_id.as_ptr(),
                malformed.as_ptr(),
                malformed.len(),
                state.as_mut_ptr(),
                &mut found,
            ),
            -2
        );
        assert_eq!(state, [0u8; 32]);
        assert_eq!(found, 0);

        let snapshot = state::ShieldedState::<32>::new(10).encode_snapshot();
        state.fill(0xff);
        found = u8::MAX;
        assert_eq!(
            onyx_state_standard_program_state(
                snapshot.as_ptr(),
                snapshot.len(),
                program_id.as_ptr(),
                malformed.as_ptr(),
                malformed.len(),
                state.as_mut_ptr(),
                &mut found,
            ),
            -3
        );
        assert_eq!(state, [0u8; 32]);
        assert_eq!(found, 0);
    }

    #[test]
    fn verification_extractors_clear_outputs_before_failure() {
        let malformed = [0u8; 1];
        let expected_network = [0u8; 16];
        let mut network = [0xffu8; 16];
        let mut anchor = [0xffu8; 32];
        let mut program_id = [0xffu8; 32];
        let mut rows = [0xffu8; 32];
        let mut expiry = u64::MAX;
        let mut fee = u64::MAX;
        let mut first_count = usize::MAX;
        let mut second_count = usize::MAX;

        assert_eq!(
            onyx_verify_and_extract_transfer(
                malformed.as_ptr(),
                malformed.len(),
                32,
                21,
                21,
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                &mut fee,
                rows.as_mut_ptr(),
                1,
                &mut first_count,
                rows.as_mut_ptr(),
                1,
                &mut second_count,
            ),
            -3
        );
        assert_eq!(
            (network, anchor, expiry, fee, first_count, second_count),
            ([0; 16], [0; 32], 0, 0, 0, 0)
        );

        network.fill(0xff);
        anchor.fill(0xff);
        expiry = u64::MAX;
        fee = u64::MAX;
        first_count = usize::MAX;
        second_count = usize::MAX;
        assert_eq!(
            onyx_extract_authenticated_transfer_delta(
                malformed.as_ptr(),
                malformed.len(),
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                &mut fee,
                rows.as_mut_ptr(),
                1,
                &mut first_count,
                rows.as_mut_ptr(),
                1,
                &mut second_count,
            ),
            -2
        );
        assert_eq!(
            (network, anchor, expiry, fee, first_count, second_count),
            ([0; 16], [0; 32], 0, 0, 0, 0)
        );

        network.fill(0xff);
        anchor.fill(0xff);
        program_id.fill(0xff);
        expiry = u64::MAX;
        fee = u64::MAX;
        first_count = usize::MAX;
        second_count = usize::MAX;
        assert_eq!(
            onyx_verify_program_deployment(
                malformed.as_ptr(),
                malformed.len(),
                32,
                20,
                20,
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                &mut fee,
                program_id.as_mut_ptr(),
                rows.as_mut_ptr(),
                1,
                &mut first_count,
                rows.as_mut_ptr(),
                1,
                &mut second_count,
            ),
            -2
        );
        assert_eq!(
            (
                network,
                anchor,
                program_id,
                expiry,
                fee,
                first_count,
                second_count
            ),
            ([0; 16], [0; 32], [0; 32], 0, 0, 0, 0)
        );

        network.fill(0xff);
        anchor.fill(0xff);
        program_id.fill(0xff);
        expiry = u64::MAX;
        let mut sequence = u64::MAX;
        let mut issued_amount = u64::MAX;
        first_count = usize::MAX;
        assert_eq!(
            onyx_verify_and_extract_token_issuance(
                malformed.as_ptr(),
                malformed.len(),
                32,
                20,
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                program_id.as_mut_ptr(),
                &mut sequence,
                &mut issued_amount,
                rows.as_mut_ptr(),
                1,
                &mut first_count,
            ),
            -2
        );
        assert_eq!(
            (
                network,
                anchor,
                program_id,
                expiry,
                sequence,
                issued_amount,
                first_count
            ),
            ([0; 16], [0; 32], [0; 32], 0, 0, 0, 0)
        );

        network.fill(0xff);
        anchor.fill(0xff);
        expiry = u64::MAX;
        first_count = usize::MAX;
        second_count = usize::MAX;
        let mut third_count = usize::MAX;
        assert_eq!(
            onyx_extract_authenticated_standard_program_delta(
                malformed.as_ptr(),
                malformed.len(),
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                rows.as_mut_ptr(),
                1,
                &mut first_count,
                rows.as_mut_ptr(),
                1,
                &mut second_count,
                rows.as_mut_ptr(),
                1,
                &mut third_count,
            ),
            -2
        );
        assert_eq!(
            (
                network,
                anchor,
                expiry,
                first_count,
                second_count,
                third_count
            ),
            ([0; 16], [0; 32], 0, 0, 0, 0)
        );

        let mut legacy_amount = u64::MAX;
        let mut legacy_stack_index = u64::MAX;
        let mut key_image = [0xffu8; 32];
        let mut sighash = [0xffu8; 32];
        let mut signature = [0xffu8; 64];
        fee = u64::MAX;
        assert_eq!(
            onyx_verify_bridge(
                malformed.as_ptr(),
                malformed.len(),
                20,
                &mut legacy_amount,
                &mut legacy_stack_index,
                key_image.as_mut_ptr(),
                sighash.as_mut_ptr(),
                signature.as_mut_ptr(),
                &mut fee,
            ),
            -2
        );
        assert_eq!(
            (
                legacy_amount,
                legacy_stack_index,
                key_image,
                sighash,
                signature,
                fee
            ),
            (0, 0, [0; 32], [0; 32], [0; 64], 0)
        );

        let mut snapshot_out = 1usize as *mut u8;
        let mut snapshot_len = usize::MAX;
        fee = u64::MAX;
        assert_eq!(
            onyx_verify_apply_transfer(
                std::ptr::null(),
                0,
                10,
                malformed.as_ptr(),
                malformed.len(),
                32,
                21,
                21,
                expected_network.as_ptr(),
                1,
                &mut snapshot_out,
                &mut snapshot_len,
                &mut fee,
            ),
            -3
        );
        assert!(snapshot_out.is_null());
        assert_eq!((snapshot_len, fee), (0, 0));

        snapshot_out = 1usize as *mut u8;
        snapshot_len = usize::MAX;
        legacy_amount = u64::MAX;
        legacy_stack_index = u64::MAX;
        key_image.fill(0xff);
        sighash.fill(0xff);
        signature.fill(0xff);
        fee = u64::MAX;
        assert_eq!(
            onyx_verify_apply_bridge(
                std::ptr::null(),
                0,
                10,
                malformed.as_ptr(),
                malformed.len(),
                21,
                expected_network.as_ptr(),
                1,
                &mut snapshot_out,
                &mut snapshot_len,
                &mut legacy_amount,
                &mut legacy_stack_index,
                key_image.as_mut_ptr(),
                sighash.as_mut_ptr(),
                signature.as_mut_ptr(),
                &mut fee,
            ),
            -3
        );
        assert!(snapshot_out.is_null());
        assert_eq!(
            (
                snapshot_len,
                legacy_amount,
                legacy_stack_index,
                key_image,
                sighash,
                signature,
                fee,
            ),
            (0, 0, 0, [0; 32], [0; 32], [0; 64], 0)
        );

        snapshot_out = 1usize as *mut u8;
        snapshot_len = usize::MAX;
        network.fill(0xff);
        anchor.fill(0xff);
        expiry = u64::MAX;
        first_count = usize::MAX;
        second_count = usize::MAX;
        assert_eq!(
            onyx_verify_apply_standard_program_transaction(
                malformed.as_ptr(),
                malformed.len(),
                malformed.as_ptr(),
                malformed.len(),
                32,
                21,
                expected_network.as_ptr(),
                1,
                &mut snapshot_out,
                &mut snapshot_len,
                network.as_mut_ptr(),
                anchor.as_mut_ptr(),
                &mut expiry,
                rows.as_mut_ptr(),
                1,
                &mut first_count,
                rows.as_mut_ptr(),
                1,
                &mut second_count,
            ),
            -3
        );
        assert!(snapshot_out.is_null());
        assert_eq!(
            (
                snapshot_len,
                network,
                anchor,
                expiry,
                first_count,
                second_count
            ),
            (0, [0; 16], [0; 32], 0, 0, 0)
        );
    }

    #[test]
    fn wallet_program_status_fails_closed_for_unknown_program() {
        let wallet = wallet::WalletState::<32>::new([9u8; 16]);
        let snapshot = wallet.encode_snapshot().unwrap();
        let program_id = [7u8; 32];
        let mut issuer = [0xffu8; 32];
        let mut max_supply = u64::MAX;
        let mut issued_supply = u64::MAX;
        let mut next_sequence = u64::MAX;
        let mut activation_height = u64::MAX;
        let mut deactivation_height = u64::MAX;
        let mut active = -1;
        let mut metadata = 1usize as *mut u8;
        let mut metadata_len = usize::MAX;

        assert_eq!(
            onyx_wallet_token_program_status(
                snapshot.as_ptr(),
                snapshot.len(),
                program_id.as_ptr(),
                10,
                issuer.as_mut_ptr(),
                &mut max_supply,
                &mut issued_supply,
                &mut next_sequence,
                &mut activation_height,
                &mut deactivation_height,
                &mut active,
                &mut metadata,
                &mut metadata_len,
            ),
            -5
        );
        assert_eq!(issuer, [0u8; 32]);
        assert_eq!(max_supply, 0);
        assert_eq!(issued_supply, 0);
        assert_eq!(next_sequence, 0);
        assert_eq!(activation_height, 0);
        assert_eq!(deactivation_height, 0);
        assert_eq!(active, 0);
        assert!(metadata.is_null());
        assert_eq!(metadata_len, 0);
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
