//! Audited standard private fungible-token program metadata.

use group::{Curve, Group};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{keygen_vk, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::pallas;
use sha2::{Digest, Sha256};

use crate::membership_circuit::MembershipCircuit;
use crate::multi_transfer_circuit::{LinkedSpend, MultiTransferCircuit};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::program::{ProgramEntry, ProgramFunction, MAX_MANIFEST_BYTES};
use crate::spend_auth_circuit::{binding_generator, SpendAuthCircuit};

pub const TOKEN_PROGRAM_BACKEND: &str = "halo2-ipa-pasta-onyx-token-v1";
pub const TOKEN_TRANSFER_FUNCTION_BASE: u32 = 0x0001_0000;
const TOKEN_MANIFEST_PREFIX: &[u8] = b"onyx.standard.private-fungible-token/v1\0";
const VK_DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-vk-descriptor";
const SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-public-input-schema";
const PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-transfer-public-data";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenProgramError {
    InvalidParameter,
    Circuit,
    KeyGeneration,
}

pub fn transfer_function_id(spends: usize, outputs: usize) -> Option<u32> {
    if !(1..=2).contains(&spends) || !(1..=2).contains(&outputs) {
        return None;
    }
    Some(TOKEN_TRANSFER_FUNCTION_BASE | ((spends as u32) << 8) | outputs as u32)
}

pub fn transfer_public_data_hash() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PUBLIC_DATA_DOMAIN);
    hash.update([1]);
    hash.finalize().into()
}

pub fn transfer_schema_hash(
    depth: usize,
    spends: usize,
    outputs: usize,
) -> Result<[u8; 32], TokenProgramError> {
    let function_id =
        transfer_function_id(spends, outputs).ok_or(TokenProgramError::InvalidParameter)?;
    let mut hash = Sha256::new();
    hash.update(SCHEMA_DOMAIN);
    hash.update((depth as u64).to_le_bytes());
    hash.update(function_id.to_le_bytes());
    hash.update(b"fee[1]=0|anchor+nullifiers|output-commitments+network+program[2]|rk+cv");
    Ok(hash.finalize().into())
}

pub fn standard_token_program<const DEPTH: usize>(
    k: u32,
    token_manifest: &[u8],
    activation_height: u64,
    deactivation_height: Option<u64>,
) -> Result<ProgramEntry, TokenProgramError> {
    if !(10..=20).contains(&k)
        || DEPTH == 0
        || token_manifest.is_empty()
        || TOKEN_MANIFEST_PREFIX.len() + 12 + token_manifest.len() > MAX_MANIFEST_BYTES
        || deactivation_height.is_some_and(|height| height <= activation_height)
    {
        return Err(TokenProgramError::InvalidParameter);
    }
    let mut manifest = Vec::with_capacity(TOKEN_MANIFEST_PREFIX.len() + token_manifest.len() + 16);
    manifest.extend_from_slice(TOKEN_MANIFEST_PREFIX);
    manifest.extend_from_slice(&(DEPTH as u64).to_le_bytes());
    manifest.extend_from_slice(&k.to_le_bytes());
    manifest.extend_from_slice(token_manifest);
    let functions = vec![
        standard_function::<DEPTH, 1, 1>(k)?,
        standard_function::<DEPTH, 1, 2>(k)?,
        standard_function::<DEPTH, 2, 1>(k)?,
        standard_function::<DEPTH, 2, 2>(k)?,
    ];
    Ok(ProgramEntry {
        manifest,
        backend: TOKEN_PROGRAM_BACKEND.to_owned(),
        activation_height,
        deactivation_height,
        functions,
    })
}

pub(crate) fn expected_vk_descriptor<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
) -> Result<Vec<u8>, TokenProgramError> {
    if !(10..=20).contains(&k) || transfer_function_id(SPENDS, OUTPUTS).is_none() {
        return Err(TokenProgramError::InvalidParameter);
    }
    let circuit = empty_program_circuit::<DEPTH, SPENDS, OUTPUTS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| TokenProgramError::KeyGeneration)?;
    Ok(descriptor_from_vk::<DEPTH, SPENDS, OUTPUTS>(k, &vk))
}

pub(crate) fn descriptor_from_vk<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize>(
    k: u32,
    vk: &VerifyingKey<EqAffine>,
) -> Vec<u8> {
    let pinned = format!("{:?}", vk.pinned());
    let mut hash = Sha256::new();
    hash.update(VK_DESCRIPTOR_DOMAIN);
    hash.update((DEPTH as u64).to_le_bytes());
    hash.update(k.to_le_bytes());
    hash.update((SPENDS as u64).to_le_bytes());
    hash.update((OUTPUTS as u64).to_le_bytes());
    hash.update((pinned.len() as u64).to_le_bytes());
    hash.update(pinned.as_bytes());
    let mut descriptor = Vec::with_capacity(47);
    descriptor.push(1);
    descriptor.extend_from_slice(&k.to_le_bytes());
    descriptor.extend_from_slice(&(DEPTH as u64).to_le_bytes());
    descriptor.push(SPENDS as u8);
    descriptor.push(OUTPUTS as u8);
    descriptor.extend_from_slice(&hash.finalize());
    descriptor
}

fn standard_function<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize>(
    k: u32,
) -> Result<ProgramFunction, TokenProgramError> {
    Ok(ProgramFunction {
        function_id: transfer_function_id(SPENDS, OUTPUTS)
            .ok_or(TokenProgramError::InvalidParameter)?,
        verifying_key: expected_vk_descriptor::<DEPTH, SPENDS, OUTPUTS>(k)?,
        public_input_schema_hash: transfer_schema_hash(DEPTH, SPENDS, OUTPUTS)?,
        max_cost: 100_000
            + (DEPTH as u64)
                .checked_mul(SPENDS as u64)
                .and_then(|cost| cost.checked_mul(2_000))
                .ok_or(TokenProgramError::InvalidParameter)?
            + OUTPUTS as u64 * 25_000,
    })
}

pub(crate) fn empty_program_circuit<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>() -> Result<MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>, TokenProgramError> {
    let siblings = vec![Fp::zero(); DEPTH];
    let generator = pallas::Point::generator().to_affine();
    let spends = (0..SPENDS)
        .map(|_| {
            Ok(LinkedSpend::new(
                MembershipCircuit::new(Fp::zero(), &siblings, 0, Fp::zero(), Fp::zero())
                    .map_err(|_| TokenProgramError::Circuit)?,
                [Fp::zero(); NOTE_COMMITMENT_INPUTS],
                SpendAuthCircuit::new(generator, Fp::zero(), generator),
                Fp::one(),
                binding_generator(),
            ))
        })
        .collect::<Result<Vec<_>, TokenProgramError>>()?;
    MultiTransferCircuit::new_program(
        &vec![0; SPENDS],
        &vec![0; OUTPUTS],
        spends,
        vec![[Fp::zero(); NOTE_COMMITMENT_INPUTS]; OUTPUTS],
        vec![Fp::one(); OUTPUTS],
        vec![binding_generator(); OUTPUTS],
    )
    .map_err(|_| TokenProgramError::Circuit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_program_is_deterministic_shape_bound_and_canonical() {
        let first = standard_token_program::<2>(14, b"TEST/USD", 10, Some(20)).unwrap();
        let second = standard_token_program::<2>(14, b"TEST/USD", 10, Some(20)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.functions.len(), 4);
        assert!(first.validate().is_ok());
        assert_ne!(
            first.functions[0].verifying_key,
            first.functions[1].verifying_key
        );
        assert_ne!(
            first.id().unwrap(),
            standard_token_program::<2>(14, b"TEST/EUR", 10, Some(20))
                .unwrap()
                .id()
                .unwrap()
        );
    }
}
