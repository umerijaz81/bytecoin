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
pub mod bridge;
pub mod bridge_circuit;
pub mod bundle_circuit;
pub mod keys;
pub mod linked_transfer_circuit;
pub mod membership_circuit;
pub mod multi_transfer_circuit;
pub mod note_commitment_circuit;
pub mod program;
pub mod proof;
pub mod spend_auth_circuit;
pub mod state;
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

fn ffi_i32(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(ERR_PANIC)
}

fn verify_transfer_dispatch(
    transaction: &transaction::AuthorizedTransaction,
    merkle_depth: u32,
    circuit_k: u32,
) -> i32 {
    if !(10..=20).contains(&circuit_k) {
        return -3;
    }
    let shape = (
        merkle_depth,
        transaction.preimage.spends.len(),
        transaction.preimage.outputs.len(),
    );
    let result = match shape {
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
        (32, 1, 1) => proof::verify_authorized_multi_transfer::<32, 1, 1>(circuit_k, transaction),
        (32, 1, 2) => proof::verify_authorized_multi_transfer::<32, 1, 2>(circuit_k, transaction),
        (32, 2, 1) => proof::verify_authorized_multi_transfer::<32, 2, 1>(circuit_k, transaction),
        (32, 2, 2) => proof::verify_authorized_multi_transfer::<32, 2, 2>(circuit_k, transaction),
        _ => return -3,
    };
    if result.is_ok() {
        1
    } else {
        0
    }
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
        verify_transfer_dispatch(&transaction, merkle_depth, circuit_k)
    })
}

#[no_mangle]
pub extern "C" fn onyx_verify_and_extract_transfer(
    encoded: *const u8,
    encoded_len: usize,
    merkle_depth: u32,
    circuit_k: u32,
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
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        let bytes = unsafe { slice::from_raw_parts(encoded, encoded_len) };
        let transaction = match transaction::AuthorizedTransaction::decode(bytes) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
        };
        if nullifier_capacity < transaction.preimage.spends.len()
            || commitment_capacity < transaction.preimage.outputs.len()
        {
            return -4;
        }
        let verified = verify_transfer_dispatch(&transaction, merkle_depth, circuit_k);
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

fn apply_transfer_to_snapshot<const DEPTH: usize>(
    snapshot: &[u8],
    anchor_window_blocks: u64,
    transaction: &transaction::AuthorizedTransaction,
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
    state
        .apply_transfer(&transaction.preimage, block_height)
        .map_err(|_| ())?;
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
    circuit_k: u32,
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
        if !(10..=20).contains(&circuit_k) {
            return -3;
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
        let network = unsafe { slice::from_raw_parts(expected_network, 16) };
        if transaction.preimage.network_id.as_slice() != network
            || block_height > transaction.preimage.expiry_height
            || transaction.preimage.expiry_height - block_height > MAX_EXPIRY_DISTANCE_BLOCKS
        {
            return -5;
        }
        let verified = verify_transfer_dispatch(&transaction, merkle_depth, circuit_k);
        if verified != 1 {
            return verified;
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
            ),
            4 => apply_transfer_to_snapshot::<4>(
                snapshot_bytes,
                anchor_window_blocks,
                &transaction,
                block_height,
            ),
            32 => apply_transfer_to_snapshot::<32>(
                snapshot_bytes,
                anchor_window_blocks,
                &transaction,
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
        if !(10..=20).contains(&circuit_k) {
            return -3;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
            *legacy_amount_out = 0;
            *legacy_stack_index_out = 0;
            *fee_out = 0;
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
            || root_out.is_null()
        {
            return -1;
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
            std::ptr::copy_nonoverlapping(state.root().bytes().as_ptr(), root_out, 32);
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
        if seed.is_null() || network.is_null() || address_out.is_null() {
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
        if seed.is_null() || network.is_null() || viewing_key_out.is_null() {
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
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if seed.is_null()
            || expected_network.is_null()
            || encoded.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || balance_out.is_null()
            || note_count_out.is_null()
            || root_out.is_null()
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
            *balance_out = 0;
            *note_count_out = 0;
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
    encoded: *const u8,
    encoded_len: usize,
    snapshot_out: *mut *mut u8,
    snapshot_len_out: *mut usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if viewing_key.is_null()
            || viewing_key_len != keys::FULL_VIEWING_KEY_BYTES
            || encoded.is_null()
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
            || balance_out.is_null()
            || note_count_out.is_null()
            || root_out.is_null()
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
            *balance_out = 0;
            *note_count_out = 0;
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
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || expected_network.is_null()
            || encoded.is_null()
            || encoded_len == 0
            || encoded_len > MAX_AUTHORIZED_TRANSACTION_BYTES
            || snapshot_out.is_null()
            || snapshot_len_out.is_null()
        {
            return -1;
        }
        unsafe {
            *snapshot_out = std::ptr::null_mut();
            *snapshot_len_out = 0;
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
        let transaction = match transaction::AuthorizedTransaction::decode(unsafe {
            slice::from_raw_parts(encoded, encoded_len)
        }) {
            Ok(transaction) => transaction,
            Err(_) => return -2,
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
pub extern "C" fn onyx_wallet_summary(
    snapshot: *const u8,
    snapshot_len: usize,
    balance_out: *mut u64,
    note_count_out: *mut usize,
    root_out: *mut u8,
) -> i32 {
    ffi_i32(|| {
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || balance_out.is_null()
            || note_count_out.is_null()
            || root_out.is_null()
        {
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
        if seed.is_null()
            || recipient.is_null()
            || legacy_key_image.is_null()
            || bridge_out.is_null()
            || bridge_len_out.is_null()
            || ownership_sighash_out.is_null()
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        unsafe {
            *bridge_out = std::ptr::null_mut();
            *bridge_len_out = 0;
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
        if unsigned_bridge.is_null()
            || ownership_signature.is_null()
            || bridge_out.is_null()
            || bridge_len_out.is_null()
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
        if snapshot.is_null()
            || snapshot_len == 0
            || snapshot_len > MAX_STATE_SNAPSHOT_BYTES
            || seed.is_null()
            || recipient.is_null()
            || transaction_out.is_null()
            || transaction_len_out.is_null()
            || memo_len > types::MAX_MEMO_BYTES
            || (memo.is_null() && memo_len != 0)
            || !(10..=20).contains(&circuit_k)
        {
            return -1;
        }
        unsafe {
            *transaction_out = std::ptr::null_mut();
            *transaction_len_out = 0;
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
