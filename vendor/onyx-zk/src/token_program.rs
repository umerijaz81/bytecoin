//! Audited standard private fungible-token program metadata.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use group::{Curve, Group, GroupEncoding};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{keygen_vk, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::{arithmetic::CurveAffine, pallas};
use sha2::{Digest, Sha256};

use crate::membership_circuit::MembershipCircuit;
use crate::mixed_token_circuit::MixedTokenCircuit;
use crate::multi_transfer_circuit::{LinkedSpend, MultiTransferCircuit};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::program::{ProgramEntry, ProgramFunction, MAX_MANIFEST_BYTES};
use crate::spend_auth_circuit::{binding_generator, SpendAuthCircuit};
use crate::token_issuance_circuit::TokenIssuanceCircuit;
use crate::transaction::{read_bytes, write_bytes};
use crate::types::{write_varint, Reader};

pub const TOKEN_PROGRAM_BACKEND: &str = "halo2-ipa-pasta-onyx-token-v1";
pub const TOKEN_TRANSFER_FUNCTION_BASE: u32 = 0x0001_0000;
pub const TOKEN_ISSUANCE_FUNCTION_BASE: u32 = 0x0002_0000;
pub const TOKEN_MIXED_TRANSFER_FUNCTION_BASE: u32 = 0x0003_0000;
pub const TOKEN_ISSUANCE_MANIFEST_MAGIC: &[u8; 4] = b"ONXM";
const TOKEN_MANIFEST_PREFIX: &[u8] = b"onyx.standard.private-fungible-token/v1\0";
const VK_DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-vk-descriptor";
const SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-public-input-schema";
const PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-transfer-public-data";
const ISSUANCE_VK_DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-issuance-vk-descriptor";
const ISSUANCE_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-issuance-schema";
const ISSUANCE_PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-issuance-public-data";
const MIXED_VK_DESCRIPTOR_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-mixed-vk-descriptor";
const MIXED_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-mixed-schema";
const MIXED_PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-mixed-public-data";
const TOKEN_ISSUANCE_MANIFEST_VERSION: u8 = 1;
const MAX_TOKEN_METADATA_BYTES: usize = 128;
type MixedShapeKey = (usize, u32, usize, usize, usize);
static MIXED_VK_DESCRIPTOR_CACHE: OnceLock<Mutex<BTreeMap<MixedShapeKey, Vec<u8>>>> =
    OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenIssuancePolicy {
    pub issuer: [u8; 32],
    pub max_supply: u64,
    pub metadata: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenProgramError {
    InvalidParameter,
    Circuit,
    KeyGeneration,
}

impl TokenIssuancePolicy {
    pub fn encode(&self) -> Result<Vec<u8>, TokenProgramError> {
        self.validate()?;
        let mut out = TOKEN_ISSUANCE_MANIFEST_MAGIC.to_vec();
        out.push(TOKEN_ISSUANCE_MANIFEST_VERSION);
        out.extend_from_slice(&self.issuer);
        write_varint(self.max_supply, &mut out);
        write_bytes(&self.metadata, &mut out);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TokenProgramError> {
        let mut reader = Reader::new(input);
        if reader
            .take(TOKEN_ISSUANCE_MANIFEST_MAGIC.len())
            .map_err(|_| TokenProgramError::InvalidParameter)?
            != TOKEN_ISSUANCE_MANIFEST_MAGIC
            || reader
                .byte()
                .map_err(|_| TokenProgramError::InvalidParameter)?
                != TOKEN_ISSUANCE_MANIFEST_VERSION
        {
            return Err(TokenProgramError::InvalidParameter);
        }
        let policy = Self {
            issuer: reader
                .array()
                .map_err(|_| TokenProgramError::InvalidParameter)?,
            max_supply: reader
                .varint()
                .map_err(|_| TokenProgramError::InvalidParameter)?,
            metadata: read_bytes(&mut reader, MAX_TOKEN_METADATA_BYTES)
                .map_err(|_| TokenProgramError::InvalidParameter)?,
        };
        if !reader.is_empty() {
            return Err(TokenProgramError::InvalidParameter);
        }
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), TokenProgramError> {
        let issuer = Option::<pallas::Point>::from(pallas::Point::from_bytes(&self.issuer))
            .ok_or(TokenProgramError::InvalidParameter)?;
        if bool::from(issuer.to_affine().coordinates().is_none())
            || self.max_supply == 0
            || self.metadata.is_empty()
            || self.metadata.len() > MAX_TOKEN_METADATA_BYTES
            || !self
                .metadata
                .iter()
                .all(|byte| (0x20..=0x7e).contains(byte))
        {
            return Err(TokenProgramError::InvalidParameter);
        }
        Ok(())
    }
}

pub fn transfer_function_id(spends: usize, outputs: usize) -> Option<u32> {
    if !(1..=2).contains(&spends) || !(1..=2).contains(&outputs) {
        return None;
    }
    Some(TOKEN_TRANSFER_FUNCTION_BASE | ((spends as u32) << 8) | outputs as u32)
}

pub fn issuance_function_id(outputs: usize) -> Option<u32> {
    (1..=2)
        .contains(&outputs)
        .then_some(TOKEN_ISSUANCE_FUNCTION_BASE | outputs as u32)
}

pub fn mixed_transfer_function_id(
    token_spends: usize,
    token_outputs: usize,
    native_spends: usize,
) -> Option<u32> {
    if !(1..=2).contains(&token_spends)
        || !(1..=2).contains(&token_outputs)
        || !(1..=2).contains(&native_spends)
    {
        return None;
    }
    Some(
        TOKEN_MIXED_TRANSFER_FUNCTION_BASE
            | ((token_spends as u32) << 12)
            | ((token_outputs as u32) << 8)
            | native_spends as u32,
    )
}

pub fn mixed_transfer_public_data_hash() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(MIXED_PUBLIC_DATA_DOMAIN);
    hash.update([1]);
    hash.finalize().into()
}

pub fn mixed_transfer_schema_hash(
    depth: usize,
    token_spends: usize,
    token_outputs: usize,
    native_spends: usize,
) -> Result<[u8; 32], TokenProgramError> {
    let function_id = mixed_transfer_function_id(token_spends, token_outputs, native_spends)
        .ok_or(TokenProgramError::InvalidParameter)?;
    let mut hash = Sha256::new();
    hash.update(MIXED_SCHEMA_DOMAIN);
    hash.update((depth as u64).to_le_bytes());
    hash.update(function_id.to_le_bytes());
    hash.update(b"token:fee=0+program|native:fee+native-asset|ordered-token-then-native");
    Ok(hash.finalize().into())
}

pub fn issuance_public_data_hash(sequence: u64, issued_amount: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ISSUANCE_PUBLIC_DATA_DOMAIN);
    hash.update([1]);
    hash.update(sequence.to_le_bytes());
    hash.update(issued_amount.to_le_bytes());
    hash.finalize().into()
}

pub fn issuance_schema_hash(depth: usize, outputs: usize) -> Result<[u8; 32], TokenProgramError> {
    let function_id = issuance_function_id(outputs).ok_or(TokenProgramError::InvalidParameter)?;
    let mut hash = Sha256::new();
    hash.update(ISSUANCE_SCHEMA_DOMAIN);
    hash.update((depth as u64).to_le_bytes());
    hash.update(function_id.to_le_bytes());
    hash.update(b"issued-amount|output-commitments+network+program[2]|output-cv");
    Ok(hash.finalize().into())
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
    let mut functions = vec![
        standard_function::<DEPTH, 1, 1>(k)?,
        standard_function::<DEPTH, 1, 2>(k)?,
        standard_function::<DEPTH, 2, 1>(k)?,
        standard_function::<DEPTH, 2, 2>(k)?,
    ];
    if token_manifest.starts_with(TOKEN_ISSUANCE_MANIFEST_MAGIC) {
        TokenIssuancePolicy::decode(token_manifest)?;
        functions.push(standard_issuance_function::<DEPTH, 1>(k)?);
        functions.push(standard_issuance_function::<DEPTH, 2>(k)?);
    }
    functions.extend([
        standard_mixed_function::<DEPTH, 1, 1, 1>(k)?,
        standard_mixed_function::<DEPTH, 1, 1, 2>(k)?,
        standard_mixed_function::<DEPTH, 1, 2, 1>(k)?,
        standard_mixed_function::<DEPTH, 1, 2, 2>(k)?,
        standard_mixed_function::<DEPTH, 2, 1, 1>(k)?,
        standard_mixed_function::<DEPTH, 2, 1, 2>(k)?,
        standard_mixed_function::<DEPTH, 2, 2, 1>(k)?,
        standard_mixed_function::<DEPTH, 2, 2, 2>(k)?,
    ]);
    Ok(ProgramEntry {
        manifest,
        backend: TOKEN_PROGRAM_BACKEND.to_owned(),
        activation_height,
        deactivation_height,
        functions,
    })
}

pub fn issuance_policy_from_entry(
    entry: &ProgramEntry,
) -> Result<(usize, u32, TokenIssuancePolicy), TokenProgramError> {
    if !entry.manifest.starts_with(TOKEN_MANIFEST_PREFIX)
        || entry.manifest.len() < TOKEN_MANIFEST_PREFIX.len() + 12
    {
        return Err(TokenProgramError::InvalidParameter);
    }
    let offset = TOKEN_MANIFEST_PREFIX.len();
    let depth = u64::from_le_bytes(
        entry.manifest[offset..offset + 8]
            .try_into()
            .map_err(|_| TokenProgramError::InvalidParameter)?,
    );
    let k = u32::from_le_bytes(
        entry.manifest[offset + 8..offset + 12]
            .try_into()
            .map_err(|_| TokenProgramError::InvalidParameter)?,
    );
    let depth = usize::try_from(depth).map_err(|_| TokenProgramError::InvalidParameter)?;
    let policy = TokenIssuancePolicy::decode(&entry.manifest[offset + 12..])?;
    Ok((depth, k, policy))
}

pub(crate) fn empty_issuance_circuit<const OUTPUTS: usize>(
) -> Result<TokenIssuanceCircuit<OUTPUTS>, TokenProgramError> {
    TokenIssuanceCircuit::new(
        &vec![0; OUTPUTS],
        vec![[Fp::zero(); NOTE_COMMITMENT_INPUTS]; OUTPUTS],
        vec![Fp::one(); OUTPUTS],
        vec![binding_generator(); OUTPUTS],
    )
    .map_err(|_| TokenProgramError::Circuit)
}

pub(crate) fn expected_issuance_vk_descriptor<const OUTPUTS: usize>(
    k: u32,
) -> Result<Vec<u8>, TokenProgramError> {
    if !(10..=20).contains(&k) || issuance_function_id(OUTPUTS).is_none() {
        return Err(TokenProgramError::InvalidParameter);
    }
    let circuit = empty_issuance_circuit::<OUTPUTS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| TokenProgramError::KeyGeneration)?;
    Ok(issuance_descriptor_from_vk(OUTPUTS, k, &vk))
}

pub(crate) fn issuance_descriptor_from_vk(
    outputs: usize,
    k: u32,
    vk: &VerifyingKey<EqAffine>,
) -> Vec<u8> {
    let pinned = format!("{:?}", vk.pinned());
    let mut hash = Sha256::new();
    hash.update(ISSUANCE_VK_DESCRIPTOR_DOMAIN);
    hash.update(k.to_le_bytes());
    hash.update((outputs as u64).to_le_bytes());
    hash.update((pinned.len() as u64).to_le_bytes());
    hash.update(pinned.as_bytes());
    let mut descriptor = Vec::with_capacity(38);
    descriptor.push(1);
    descriptor.extend_from_slice(&k.to_le_bytes());
    descriptor.push(outputs as u8);
    descriptor.extend_from_slice(&hash.finalize());
    descriptor
}

fn standard_issuance_function<const DEPTH: usize, const OUTPUTS: usize>(
    k: u32,
) -> Result<ProgramFunction, TokenProgramError> {
    Ok(ProgramFunction {
        function_id: issuance_function_id(OUTPUTS).ok_or(TokenProgramError::InvalidParameter)?,
        verifying_key: expected_issuance_vk_descriptor::<OUTPUTS>(k)?,
        public_input_schema_hash: issuance_schema_hash(DEPTH, OUTPUTS)?,
        max_cost: 100_000 + OUTPUTS as u64 * 40_000,
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

fn standard_mixed_function<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
    k: u32,
) -> Result<ProgramFunction, TokenProgramError> {
    Ok(ProgramFunction {
        function_id: mixed_transfer_function_id(TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS)
            .ok_or(TokenProgramError::InvalidParameter)?,
        verifying_key: expected_mixed_vk_descriptor::<
            DEPTH,
            TOKEN_SPENDS,
            TOKEN_OUTPUTS,
            NATIVE_SPENDS,
        >(k)?,
        public_input_schema_hash: mixed_transfer_schema_hash(
            DEPTH,
            TOKEN_SPENDS,
            TOKEN_OUTPUTS,
            NATIVE_SPENDS,
        )?,
        max_cost: 175_000
            + (DEPTH as u64)
                .checked_mul((TOKEN_SPENDS + NATIVE_SPENDS) as u64)
                .and_then(|cost| cost.checked_mul(2_000))
                .ok_or(TokenProgramError::InvalidParameter)?
            + (TOKEN_OUTPUTS as u64 + 1) * 25_000,
    })
}

pub(crate) fn expected_mixed_vk_descriptor<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
    k: u32,
) -> Result<Vec<u8>, TokenProgramError> {
    if !(10..=20).contains(&k)
        || mixed_transfer_function_id(TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS).is_none()
    {
        return Err(TokenProgramError::InvalidParameter);
    }
    let key = (DEPTH, k, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS);
    let cache = MIXED_VK_DESCRIPTOR_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(descriptor) = cache
        .lock()
        .map_err(|_| TokenProgramError::KeyGeneration)?
        .get(&key)
        .cloned()
    {
        return Ok(descriptor);
    }
    let circuit = empty_mixed_circuit::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| TokenProgramError::KeyGeneration)?;
    let descriptor =
        mixed_descriptor_from_vk::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>(k, &vk);
    cache
        .lock()
        .map_err(|_| TokenProgramError::KeyGeneration)?
        .insert(key, descriptor.clone());
    Ok(descriptor)
}

pub(crate) fn mixed_descriptor_from_vk<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
    k: u32,
    vk: &VerifyingKey<EqAffine>,
) -> Vec<u8> {
    let pinned = format!("{:?}", vk.pinned());
    let mut hash = Sha256::new();
    hash.update(MIXED_VK_DESCRIPTOR_DOMAIN);
    hash.update((DEPTH as u64).to_le_bytes());
    hash.update(k.to_le_bytes());
    hash.update([TOKEN_SPENDS as u8, TOKEN_OUTPUTS as u8, NATIVE_SPENDS as u8]);
    hash.update((pinned.len() as u64).to_le_bytes());
    hash.update(pinned.as_bytes());
    let mut descriptor = Vec::with_capacity(48);
    descriptor.push(1);
    descriptor.extend_from_slice(&k.to_le_bytes());
    descriptor.extend_from_slice(&(DEPTH as u64).to_le_bytes());
    descriptor.extend_from_slice(&[TOKEN_SPENDS as u8, TOKEN_OUTPUTS as u8, NATIVE_SPENDS as u8]);
    descriptor.extend_from_slice(&hash.finalize());
    descriptor
}

pub(crate) fn empty_mixed_circuit<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
) -> Result<MixedTokenCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>, TokenProgramError>
{
    MixedTokenCircuit::new(
        empty_program_circuit::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS>()?,
        empty_native_circuit::<DEPTH, NATIVE_SPENDS, 1>()?,
    )
    .map_err(|_| TokenProgramError::Circuit)
}

fn empty_native_circuit<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize>(
) -> Result<MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>, TokenProgramError> {
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
    MultiTransferCircuit::new(
        &vec![0; SPENDS],
        &vec![0; OUTPUTS],
        spends,
        vec![[Fp::zero(); NOTE_COMMITMENT_INPUTS]; OUTPUTS],
        vec![Fp::one(); OUTPUTS],
        vec![binding_generator(); OUTPUTS],
    )
    .map_err(|_| TokenProgramError::Circuit)
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
        assert_eq!(first.functions.len(), 12);
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

    #[test]
    fn issuance_policy_is_canonical_and_adds_shape_bound_functions() {
        let to_hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let issuer = (crate::spend_auth_circuit::spend_auth_generator() * pallas::Scalar::from(19))
            .to_bytes();
        let policy = TokenIssuancePolicy {
            issuer,
            max_supply: 1_000_000,
            metadata: b"symbol=TEST;decimals=8".to_vec(),
        };
        let encoded = policy.encode().unwrap();
        assert_eq!(
            to_hex(&encoded),
            "4f4e584d0140bc7088034d07f4b45b5ff02dc0098130a44fc5d5fa4560eee0be603d1ef8b0c0843d1673796d626f6c3d544553543b646563696d616c733d38"
        );
        assert_eq!(TokenIssuancePolicy::decode(&encoded).unwrap(), policy);
        let program = standard_token_program::<2>(14, &encoded, 10, Some(20)).unwrap();
        assert_eq!(
            to_hex(&program.id().unwrap()),
            "a7249f5e44ebb1045937aa148bb7c6385f49d9d831f4131e8f5bba431eb501f1"
        );
        assert_eq!(program.functions.len(), 14);
        assert_eq!(
            issuance_policy_from_entry(&program).unwrap(),
            (2, 14, policy)
        );
        assert_eq!(
            program.functions[4].function_id,
            issuance_function_id(1).unwrap()
        );
        assert_eq!(
            program.functions[5].function_id,
            issuance_function_id(2).unwrap()
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(TokenIssuancePolicy::decode(&trailing).is_err());
        assert!(standard_token_program::<2>(14, &trailing, 10, None).is_err());
    }
}
