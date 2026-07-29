//! Proof creation and verification for the current O2 linked transfer circuit.
//!
//! This API is deliberately not exported over the consensus FFI yet. The circuit binds native
//! balance, input/output note commitments, anchor, nullifier, and randomized spend authority. It
//! remains experimental while it supports only one spend/output and lacks consensus FFI wiring.

use group::{Curve, Group, GroupEncoding};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use pasta_curves::{arithmetic::CurveAffine, pallas};

use crate::authorization::{
    verify_authorized_transaction, verify_issuance_binding_authorization,
    verify_spend_authorizations, AuthorizationError,
};
use crate::bridge::{AuthorizedBridge, BridgeError};
use crate::bridge_circuit::BridgeCircuit;
use crate::linked_transfer_circuit::LinkedTransferCircuit;
use crate::membership_circuit::MembershipCircuit;
use crate::mixed_token_circuit::MixedTokenCircuit;
use crate::multi_transfer_circuit::{LinkedSpend, MultiTransferCircuit};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::program::ProgramRegistry;
use crate::spend_auth_circuit::SpendAuthCircuit;
use crate::state::CanonicalField;
use crate::token_issuance_circuit::TokenIssuanceCircuit;
use crate::token_program::{
    descriptor_from_vk, empty_issuance_circuit, empty_mixed_circuit, empty_program_circuit,
    issuance_descriptor_from_vk, issuance_function_id, issuance_public_data_hash,
    issuance_schema_hash, mixed_descriptor_from_vk, mixed_transfer_function_id,
    mixed_transfer_public_data_hash, mixed_transfer_schema_hash, transfer_function_id,
    transfer_public_data_hash, transfer_schema_hash, TOKEN_PROGRAM_BACKEND,
};
use crate::transaction::{
    AuthorizedTransaction, PublicOutput, PublicSpend, TransactionError, MAX_PROOF_BYTES,
};

pub const EXPERIMENTAL_TRANSFER_BACKEND: &str = "halo2-ipa-pasta-onyx-o2-experimental";
pub const BRIDGE_BACKEND: &str = "halo2-ipa-pasta-onyx-bridge-v1";

pub fn multi_transfer_backend_id(spends: usize, outputs: usize) -> String {
    format!("halo2-ipa-pasta-onyx-o2-s{spends}-o{outputs}")
}

pub fn program_transfer_backend_id(spends: usize, outputs: usize) -> String {
    format!("halo2-ipa-pasta-onyx-program-transfer-v1-s{spends}-o{outputs}")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofError {
    InvalidShape,
    InvalidPublicInput,
    ProofTooLarge,
    ProvingFailed,
    VerificationFailed,
    Authorization(AuthorizationError),
    Transaction(TransactionError),
    Bridge(BridgeError),
}

impl From<AuthorizationError> for ProofError {
    fn from(value: AuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

impl From<TransactionError> for ProofError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}

impl From<BridgeError> for ProofError {
    fn from(value: BridgeError) -> Self {
        Self::Bridge(value)
    }
}

#[derive(Clone)]
pub struct BridgeWitness {
    pub output_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub output_value_randomness: Fp,
    pub output_value_commitment: pallas::Affine,
}

fn bridge_public_inputs(bridge: &AuthorizedBridge) -> Result<[Vec<Fp>; 3], ProofError> {
    let preimage = &bridge.preimage;
    if preimage.fee >= preimage.legacy_amount {
        return Err(ProofError::InvalidPublicInput);
    }
    let note_commitment = preimage.output.commitment.field();
    let value_commitment =
        Option::<pallas::Point>::from(pallas::Point::from_bytes(&preimage.output.value_commitment))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
    let coordinates = randomized_key_coordinates(value_commitment)?;
    Ok([
        vec![Fp::from(preimage.fee), Fp::from(preimage.legacy_amount)],
        vec![
            note_commitment,
            crate::types::network_field(&preimage.network_id),
        ],
        coordinates.to_vec(),
    ])
}

pub fn create_bridge_proof(
    k: u32,
    preimage: &crate::bridge::BridgePreimage,
    witness: &BridgeWitness,
) -> Result<Vec<u8>, ProofError> {
    let note_value = preimage
        .legacy_amount
        .checked_sub(preimage.fee)
        .filter(|value| *value != 0)
        .ok_or(ProofError::InvalidPublicInput)?;
    let circuit = BridgeCircuit::new(
        preimage.legacy_amount,
        note_value,
        witness.output_note,
        witness.output_value_randomness,
        witness.output_value_commitment,
    )
    .map_err(|_| ProofError::InvalidShape)?;
    let bridge = AuthorizedBridge {
        preimage: preimage.clone(),
        backend_id: BRIDGE_BACKEND.to_owned(),
        proof: vec![1],
        ownership_signature: [0; 64],
    };
    let public = bridge_public_inputs(&bridge)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public[0], &public[1], &public[2]]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn verify_bridge_proof(k: u32, bridge: &AuthorizedBridge) -> Result<(), ProofError> {
    if bridge.backend_id != BRIDGE_BACKEND {
        return Err(ProofError::InvalidShape);
    }
    let note_value = bridge
        .preimage
        .legacy_amount
        .checked_sub(bridge.preimage.fee)
        .filter(|value| *value != 0)
        .ok_or(ProofError::InvalidPublicInput)?;
    let value_commitment = Option::<pallas::Point>::from(pallas::Point::from_bytes(
        &bridge.preimage.output.value_commitment,
    ))
    .ok_or(ProofError::InvalidPublicInput)?
    .to_affine();
    let mut note = [Fp::zero(); NOTE_COMMITMENT_INPUTS];
    note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(note_value);
    let circuit = BridgeCircuit::new(
        bridge.preimage.legacy_amount,
        note_value,
        note,
        Fp::zero(),
        value_commitment,
    )
    .map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    let public = bridge_public_inputs(bridge)?;
    let strategy = SingleVerifier::new(&params);
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&bridge.proof[..]);
    verify_proof(
        &params,
        &vk,
        strategy,
        &[&[&public[0], &public[1], &public[2]]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

#[derive(Clone)]
pub struct TransferWitness<const DEPTH: usize> {
    pub input_values: Vec<u64>,
    pub output_values: Vec<u64>,
    pub commitment: Fp,
    pub input_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub output_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub authority_key: pallas::Affine,
    pub authorization_randomizer: Fp,
    pub randomized_key: pallas::Affine,
    pub siblings: Vec<Fp>,
    pub position: u64,
    pub nullifier_key: Fp,
    pub rho: Fp,
    pub input_value_randomness: Fp,
    pub input_value_commitment: pallas::Affine,
    pub output_value_randomness: Fp,
    pub output_value_commitment: pallas::Affine,
}

#[derive(Clone)]
pub struct MultiSpendWitness<const DEPTH: usize> {
    pub commitment: Fp,
    pub input_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub authority_key: pallas::Affine,
    pub authorization_randomizer: Fp,
    pub randomized_key: pallas::Affine,
    pub siblings: Vec<Fp>,
    pub position: u64,
    pub nullifier_key: Fp,
    pub rho: Fp,
    pub value_randomness: Fp,
    pub value_commitment: pallas::Affine,
}

#[derive(Clone)]
pub struct MultiTransferWitness<const DEPTH: usize> {
    pub input_values: Vec<u64>,
    pub output_values: Vec<u64>,
    pub spends: Vec<MultiSpendWitness<DEPTH>>,
    pub output_notes: Vec<[Fp; NOTE_COMMITMENT_INPUTS]>,
    pub output_value_randomness: Vec<Fp>,
    pub output_value_commitments: Vec<pallas::Affine>,
}

#[derive(Clone)]
pub struct MixedTokenWitness<const DEPTH: usize> {
    pub token: MultiTransferWitness<DEPTH>,
    pub native: MultiTransferWitness<DEPTH>,
}

impl<const DEPTH: usize> MixedTokenWitness<DEPTH> {
    fn circuit<
        const TOKEN_SPENDS: usize,
        const TOKEN_OUTPUTS: usize,
        const NATIVE_SPENDS: usize,
    >(
        &self,
    ) -> Result<MixedTokenCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>, ProofError>
    {
        MixedTokenCircuit::new(
            self.token
                .program_circuit::<TOKEN_SPENDS, TOKEN_OUTPUTS>()?,
            self.native.circuit::<NATIVE_SPENDS, 1>()?,
        )
        .map_err(|_| ProofError::InvalidShape)
    }
}

#[derive(Clone)]
pub struct TokenIssuanceWitness {
    pub output_values: Vec<u64>,
    pub output_notes: Vec<[Fp; NOTE_COMMITMENT_INPUTS]>,
    pub output_value_randomness: Vec<Fp>,
    pub output_value_commitments: Vec<pallas::Affine>,
}

impl TokenIssuanceWitness {
    fn circuit<const OUTPUTS: usize>(&self) -> Result<TokenIssuanceCircuit<OUTPUTS>, ProofError> {
        TokenIssuanceCircuit::new(
            &self.output_values,
            self.output_notes.clone(),
            self.output_value_randomness.clone(),
            self.output_value_commitments.clone(),
        )
        .map_err(|_| ProofError::InvalidShape)
    }
}

impl<const DEPTH: usize> MultiSpendWitness<DEPTH> {
    fn linked(&self) -> Result<LinkedSpend<DEPTH>, ProofError> {
        Ok(LinkedSpend::new(
            MembershipCircuit::new(
                self.commitment,
                &self.siblings,
                self.position,
                self.nullifier_key,
                self.rho,
            )
            .map_err(|_| ProofError::InvalidShape)?,
            self.input_note,
            SpendAuthCircuit::new(
                self.authority_key,
                self.authorization_randomizer,
                self.randomized_key,
            ),
            self.value_randomness,
            self.value_commitment,
        ))
    }
}

impl<const DEPTH: usize> MultiTransferWitness<DEPTH> {
    pub(crate) fn circuit<const SPENDS: usize, const OUTPUTS: usize>(
        &self,
    ) -> Result<MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>, ProofError> {
        let spends = self
            .spends
            .iter()
            .map(MultiSpendWitness::linked)
            .collect::<Result<Vec<_>, _>>()?;
        MultiTransferCircuit::new(
            &self.input_values,
            &self.output_values,
            spends,
            self.output_notes.clone(),
            self.output_value_randomness.clone(),
            self.output_value_commitments.clone(),
        )
        .map_err(|_| ProofError::InvalidShape)
    }

    pub(crate) fn program_circuit<const SPENDS: usize, const OUTPUTS: usize>(
        &self,
    ) -> Result<MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>, ProofError> {
        let spends = self
            .spends
            .iter()
            .map(MultiSpendWitness::linked)
            .collect::<Result<Vec<_>, _>>()?;
        MultiTransferCircuit::new_program(
            &self.input_values,
            &self.output_values,
            spends,
            self.output_notes.clone(),
            self.output_value_randomness.clone(),
            self.output_value_commitments.clone(),
        )
        .map_err(|_| ProofError::InvalidShape)
    }
}

fn randomized_key_coordinates(key: pallas::Affine) -> Result<[Fp; 2], ProofError> {
    let coordinates = key.coordinates();
    if bool::from(coordinates.is_none()) {
        return Err(ProofError::InvalidPublicInput);
    }
    let coordinates = coordinates.unwrap();
    Ok([*coordinates.x(), *coordinates.y()])
}

fn token_issuance_public_inputs(
    issued_amount: u64,
    network_id: &[u8; 16],
    program_id: &[u8; 32],
    outputs: &[crate::transaction::PublicOutput],
) -> Result<[Vec<Fp>; 3], ProofError> {
    let amount = vec![Fp::from(issued_amount)];
    let mut notes = outputs
        .iter()
        .map(|output| output.commitment.field())
        .collect::<Vec<_>>();
    notes.push(crate::types::network_field(network_id));
    notes.extend(crate::types::pack_32(program_id));
    let mut commitments = Vec::with_capacity(outputs.len() * 2);
    for output in outputs {
        let point =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&output.value_commitment))
                .ok_or(ProofError::InvalidPublicInput)?
                .to_affine();
        commitments.extend(randomized_key_coordinates(point)?);
    }
    Ok([amount, notes, commitments])
}

pub fn create_token_issuance_proof<const OUTPUTS: usize>(
    k: u32,
    witness: &TokenIssuanceWitness,
    issued_amount: u64,
    network_id: [u8; 16],
    program_id: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    if issuance_function_id(OUTPUTS).is_none()
        || witness
            .output_values
            .iter()
            .try_fold(0u64, |sum, value| sum.checked_add(*value))
            != Some(issued_amount)
        || issued_amount == 0
    {
        return Err(ProofError::InvalidShape);
    }
    let circuit = witness.circuit::<OUTPUTS>()?;
    let outputs = witness
        .output_notes
        .iter()
        .zip(&witness.output_value_commitments)
        .map(|(note, commitment)| {
            crate::transaction::PublicOutput {
                    commitment:
                        CanonicalField::from_field(
                            PrimitiveHash::<
                                Fp,
                                P128Pow5T3,
                                ConstantLength<NOTE_COMMITMENT_INPUTS>,
                                3,
                                2,
                            >::init()
                            .hash(*note),
                        ),
                    value_commitment: commitment.to_bytes(),
                    ephemeral_key: [1; 32],
                    ciphertext: vec![],
                    outgoing_ciphertext: vec![],
                }
        })
        .collect::<Vec<_>>();
    let public = token_issuance_public_inputs(issued_amount, &network_id, &program_id, &outputs)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public[0], &public[1], &public[2]]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn verify_authorized_token_issuance<const DEPTH: usize, const OUTPUTS: usize>(
    k: u32,
    transaction: &AuthorizedTransaction,
    issued_amount: u64,
    sequence: u64,
    registry: Option<&ProgramRegistry>,
    block_height: u64,
) -> Result<(), ProofError> {
    let expected_function = issuance_function_id(OUTPUTS).ok_or(ProofError::InvalidShape)?;
    if issued_amount == 0
        || transaction.backend_id != TOKEN_PROGRAM_BACKEND
        || !transaction.preimage.spends.is_empty()
        || transaction.preimage.outputs.len() != OUTPUTS
        || transaction.preimage.fee != 0
        || transaction.preimage.programs.len() != 1
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    let call = &transaction.preimage.programs[0];
    if call.function_id != expected_function
        || call.public_data_hash != issuance_public_data_hash(sequence, issued_amount)
    {
        return Err(ProofError::InvalidShape);
    }
    let registered_function = if let Some(registry) = registry {
        registry
            .validate_calls(std::slice::from_ref(call), block_height, 10_000_000)
            .map_err(|_| ProofError::InvalidShape)?;
        let (entry, function) = registry
            .active_function(&call.program_id, call.function_id, block_height)
            .map_err(|_| ProofError::InvalidShape)?;
        if entry.backend != TOKEN_PROGRAM_BACKEND
            || function.public_input_schema_hash
                != issuance_schema_hash(DEPTH, OUTPUTS).map_err(|_| ProofError::InvalidShape)?
        {
            return Err(ProofError::InvalidShape);
        }
        Some(function)
    } else {
        None
    };
    transaction.preimage.encode()?;
    verify_spend_authorizations(
        &transaction.preimage,
        &transaction.backend_id,
        &transaction.proof,
        &transaction.spend_signatures,
    )?;
    verify_issuance_binding_authorization(
        &transaction.preimage,
        issued_amount,
        &transaction.backend_id,
        &transaction.proof,
        transaction.binding_signature,
    )?;
    let circuit = empty_issuance_circuit::<OUTPUTS>().map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    if let Some(function) = registered_function {
        if function.verifying_key != issuance_descriptor_from_vk(OUTPUTS, k, &vk) {
            return Err(ProofError::InvalidShape);
        }
    }
    let public = token_issuance_public_inputs(
        issued_amount,
        &transaction.preimage.network_id,
        &call.program_id,
        &transaction.preimage.outputs,
    )?;
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&public[0], &public[1], &public[2]]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

pub fn create_multi_transfer_proof<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    witness: &MultiTransferWitness<DEPTH>,
    fee: u64,
    anchor: CanonicalField,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<u8>, ProofError> {
    if nullifiers.len() != SPENDS {
        return Err(ProofError::InvalidShape);
    }
    let circuit = witness.circuit::<SPENDS, OUTPUTS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let public = [Fp::from(fee)];
    let mut membership = Vec::with_capacity(SPENDS + 1);
    membership.push(anchor.field());
    for nullifier in nullifiers {
        membership.push(
            CanonicalField::from_bytes(*nullifier)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = witness
        .output_notes
        .iter()
        .map(|note| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(*note)
        })
        .collect::<Vec<_>>();
    notes.push(witness.spends[0].input_note[1]);
    let mut authorization = witness
        .spends
        .iter()
        .map(|spend| randomized_key_coordinates(spend.randomized_key))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for spend in &witness.spends {
        authorization.extend(randomized_key_coordinates(spend.value_commitment)?);
    }
    for commitment in &witness.output_value_commitments {
        authorization.extend(randomized_key_coordinates(*commitment)?);
    }
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public, &membership, &notes, &authorization]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn create_token_transfer_proof<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    witness: &MultiTransferWitness<DEPTH>,
    anchor: CanonicalField,
    nullifiers: &[[u8; 32]],
    program_id: [u8; 32],
    function_id: u32,
) -> Result<Vec<u8>, ProofError> {
    if nullifiers.len() != SPENDS || transfer_function_id(SPENDS, OUTPUTS) != Some(function_id) {
        return Err(ProofError::InvalidShape);
    }
    let circuit = witness.program_circuit::<SPENDS, OUTPUTS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let public = [Fp::zero()];
    let mut membership = Vec::with_capacity(SPENDS + 1);
    membership.push(anchor.field());
    for nullifier in nullifiers {
        membership.push(
            CanonicalField::from_bytes(*nullifier)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = witness
        .output_notes
        .iter()
        .map(|note| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(*note)
        })
        .collect::<Vec<_>>();
    notes.push(witness.spends[0].input_note[1]);
    notes.extend(crate::types::pack_32(&program_id));
    let mut authorization = witness
        .spends
        .iter()
        .map(|spend| randomized_key_coordinates(spend.randomized_key))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for spend in &witness.spends {
        authorization.extend(randomized_key_coordinates(spend.value_commitment)?);
    }
    for commitment in &witness.output_value_commitments {
        authorization.extend(randomized_key_coordinates(*commitment)?);
    }
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public, &membership, &notes, &authorization]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn verify_authorized_token_transfer<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    transaction: &AuthorizedTransaction,
    registry: Option<&ProgramRegistry>,
    block_height: u64,
) -> Result<(), ProofError> {
    let expected_function =
        transfer_function_id(SPENDS, OUTPUTS).ok_or(ProofError::InvalidShape)?;
    if transaction.backend_id != TOKEN_PROGRAM_BACKEND
        || transaction.preimage.spends.len() != SPENDS
        || transaction.preimage.outputs.len() != OUTPUTS
        || transaction.preimage.fee != 0
        || transaction.preimage.programs.len() != 1
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    let call = &transaction.preimage.programs[0];
    if call.function_id != expected_function || call.public_data_hash != transfer_public_data_hash()
    {
        return Err(ProofError::InvalidShape);
    }
    let registered_function = if let Some(registry) = registry {
        registry
            .validate_calls(std::slice::from_ref(call), block_height, 10_000_000)
            .map_err(|_| ProofError::InvalidShape)?;
        let (entry, function) = registry
            .active_function(&call.program_id, call.function_id, block_height)
            .map_err(|_| ProofError::InvalidShape)?;
        if entry.backend != TOKEN_PROGRAM_BACKEND
            || function.public_input_schema_hash
                != transfer_schema_hash(DEPTH, SPENDS, OUTPUTS)
                    .map_err(|_| ProofError::InvalidShape)?
        {
            return Err(ProofError::InvalidShape);
        }
        Some(function)
    } else {
        None
    };
    transaction.preimage.encode()?;
    verify_authorized_transaction(transaction)?;

    let circuit =
        empty_program_circuit::<DEPTH, SPENDS, OUTPUTS>().map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    if let Some(function) = registered_function {
        if function.verifying_key != descriptor_from_vk::<DEPTH, SPENDS, OUTPUTS>(k, &vk) {
            return Err(ProofError::InvalidShape);
        }
    }
    let public = [Fp::zero()];
    let mut membership = Vec::with_capacity(SPENDS + 1);
    membership.push(transaction.preimage.anchor.field());
    for spend in &transaction.preimage.spends {
        membership.push(
            CanonicalField::from_bytes(spend.nullifier.0)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = transaction
        .preimage
        .outputs
        .iter()
        .map(|output| output.commitment.field())
        .collect::<Vec<_>>();
    notes.push(crate::types::network_field(
        &transaction.preimage.network_id,
    ));
    notes.extend(crate::types::pack_32(&call.program_id));
    let mut authorization = Vec::with_capacity((SPENDS * 2 + SPENDS + OUTPUTS) * 2);
    for spend in &transaction.preimage.spends {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&spend.randomized_key))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    for bytes in transaction
        .preimage
        .spends
        .iter()
        .map(|spend| &spend.value_commitment)
        .chain(
            transaction
                .preimage
                .outputs
                .iter()
                .map(|output| &output.value_commitment),
        )
    {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&public, &membership, &notes, &authorization]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

/// Verifies only the value/membership/note-opening layer for a single program-asset domain.
///
/// This deliberately does not verify transaction authorization or interpret program calls. It is
/// intended for a signed contextual proof bundle whose outer verifier authenticates the complete
/// transaction and separately verifies the registered program predicate.
pub fn verify_program_multi_transfer_proof<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    transaction: &AuthorizedTransaction,
    program_id: &[u8; 32],
) -> Result<(), ProofError> {
    if transaction.backend_id != program_transfer_backend_id(SPENDS, OUTPUTS)
        || transaction.preimage.spends.len() != SPENDS
        || transaction.preimage.outputs.len() != OUTPUTS
        || transaction.preimage.fee != 0
        || !transaction.preimage.programs.is_empty()
        || transaction.proof.is_empty()
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    transaction.preimage.encode()?;
    let circuit =
        empty_program_circuit::<DEPTH, SPENDS, OUTPUTS>().map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    let instances = transaction_lane_public_inputs(
        &transaction.preimage.spends,
        &transaction.preimage.outputs,
        0,
        transaction.preimage.anchor,
        &transaction.preimage.network_id,
        Some(program_id),
    )?;
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&instances[0], &instances[1], &instances[2], &instances[3]]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

fn witness_lane_public_inputs<const DEPTH: usize>(
    witness: &MultiTransferWitness<DEPTH>,
    fee: u64,
    anchor: CanonicalField,
    nullifiers: &[[u8; 32]],
    network_id: &[u8; 16],
    program_id: Option<&[u8; 32]>,
) -> Result<[Vec<Fp>; 4], ProofError> {
    if nullifiers.len() != witness.spends.len() {
        return Err(ProofError::InvalidShape);
    }
    let public = vec![Fp::from(fee)];
    let mut membership = Vec::with_capacity(nullifiers.len() + 1);
    membership.push(anchor.field());
    for nullifier in nullifiers {
        membership.push(
            CanonicalField::from_bytes(*nullifier)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = witness
        .output_notes
        .iter()
        .map(|note| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(*note)
        })
        .collect::<Vec<_>>();
    notes.push(crate::types::network_field(network_id));
    if let Some(program_id) = program_id {
        notes.extend(crate::types::pack_32(program_id));
    }
    let mut authorization = witness
        .spends
        .iter()
        .map(|spend| randomized_key_coordinates(spend.randomized_key))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    for spend in &witness.spends {
        authorization.extend(randomized_key_coordinates(spend.value_commitment)?);
    }
    for commitment in &witness.output_value_commitments {
        authorization.extend(randomized_key_coordinates(*commitment)?);
    }
    Ok([public, membership, notes, authorization])
}

fn transaction_lane_public_inputs(
    spends: &[PublicSpend],
    outputs: &[PublicOutput],
    fee: u64,
    anchor: CanonicalField,
    network_id: &[u8; 16],
    program_id: Option<&[u8; 32]>,
) -> Result<[Vec<Fp>; 4], ProofError> {
    let public = vec![Fp::from(fee)];
    let mut membership = Vec::with_capacity(spends.len() + 1);
    membership.push(anchor.field());
    for spend in spends {
        membership.push(
            CanonicalField::from_bytes(spend.nullifier.0)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = outputs
        .iter()
        .map(|output| output.commitment.field())
        .collect::<Vec<_>>();
    notes.push(crate::types::network_field(network_id));
    if let Some(program_id) = program_id {
        notes.extend(crate::types::pack_32(program_id));
    }
    let mut authorization =
        Vec::with_capacity((spends.len() * 2 + spends.len() + outputs.len()) * 2);
    for spend in spends {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&spend.randomized_key))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    for bytes in spends
        .iter()
        .map(|spend| &spend.value_commitment)
        .chain(outputs.iter().map(|output| &output.value_commitment))
    {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    Ok([public, membership, notes, authorization])
}

pub fn create_mixed_token_transfer_proof<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
    k: u32,
    witness: &MixedTokenWitness<DEPTH>,
    fee: u64,
    anchor: CanonicalField,
    nullifiers: &[[u8; 32]],
    network_id: [u8; 16],
    program_id: [u8; 32],
    function_id: u32,
) -> Result<Vec<u8>, ProofError> {
    if fee == 0
        || nullifiers.len() != TOKEN_SPENDS + NATIVE_SPENDS
        || mixed_transfer_function_id(TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS)
            != Some(function_id)
    {
        return Err(ProofError::InvalidShape);
    }
    let circuit = witness.circuit::<TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let token = witness_lane_public_inputs(
        &witness.token,
        0,
        anchor,
        &nullifiers[..TOKEN_SPENDS],
        &network_id,
        Some(&program_id),
    )?;
    let native = witness_lane_public_inputs(
        &witness.native,
        fee,
        anchor,
        &nullifiers[TOKEN_SPENDS..],
        &network_id,
        None,
    )?;
    let instances: [&[Fp]; 8] = [
        &token[0], &token[1], &token[2], &token[3], &native[0], &native[1], &native[2], &native[3],
    ];
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&instances],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn verify_authorized_mixed_token_transfer<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
>(
    k: u32,
    transaction: &AuthorizedTransaction,
    registry: Option<&ProgramRegistry>,
    block_height: u64,
) -> Result<(), ProofError> {
    let expected_function = mixed_transfer_function_id(TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS)
        .ok_or(ProofError::InvalidShape)?;
    if transaction.backend_id != TOKEN_PROGRAM_BACKEND
        || transaction.preimage.spends.len() != TOKEN_SPENDS + NATIVE_SPENDS
        || transaction.preimage.outputs.len() != TOKEN_OUTPUTS + 1
        || transaction.preimage.fee == 0
        || transaction.preimage.programs.len() != 1
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    let call = &transaction.preimage.programs[0];
    if call.function_id != expected_function
        || call.public_data_hash != mixed_transfer_public_data_hash()
    {
        return Err(ProofError::InvalidShape);
    }
    let registered_function = if let Some(registry) = registry {
        registry
            .validate_calls(std::slice::from_ref(call), block_height, 10_000_000)
            .map_err(|_| ProofError::InvalidShape)?;
        let (entry, function) = registry
            .active_function(&call.program_id, call.function_id, block_height)
            .map_err(|_| ProofError::InvalidShape)?;
        if entry.backend != TOKEN_PROGRAM_BACKEND
            || function.public_input_schema_hash
                != mixed_transfer_schema_hash(DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS)
                    .map_err(|_| ProofError::InvalidShape)?
        {
            return Err(ProofError::InvalidShape);
        }
        Some(function)
    } else {
        None
    };
    transaction.preimage.encode()?;
    verify_authorized_transaction(transaction)?;
    let circuit = empty_mixed_circuit::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>()
        .map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    if let Some(function) = registered_function {
        if function.verifying_key
            != mixed_descriptor_from_vk::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>(k, &vk)
        {
            return Err(ProofError::InvalidShape);
        }
    }
    let token = transaction_lane_public_inputs(
        &transaction.preimage.spends[..TOKEN_SPENDS],
        &transaction.preimage.outputs[..TOKEN_OUTPUTS],
        0,
        transaction.preimage.anchor,
        &transaction.preimage.network_id,
        Some(&call.program_id),
    )?;
    let native = transaction_lane_public_inputs(
        &transaction.preimage.spends[TOKEN_SPENDS..],
        &transaction.preimage.outputs[TOKEN_OUTPUTS..],
        transaction.preimage.fee,
        transaction.preimage.anchor,
        &transaction.preimage.network_id,
        None,
    )?;
    let instances: [&[Fp]; 8] = [
        &token[0], &token[1], &token[2], &token[3], &native[0], &native[1], &native[2], &native[3],
    ];
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&instances],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

pub fn verify_multi_transfer_proof<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    transaction: &AuthorizedTransaction,
) -> Result<(), ProofError> {
    if transaction.backend_id != multi_transfer_backend_id(SPENDS, OUTPUTS)
        || transaction.preimage.spends.len() != SPENDS
        || transaction.preimage.outputs.len() != OUTPUTS
        || !transaction.preimage.programs.is_empty()
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    transaction.preimage.encode()?;
    let siblings = vec![Fp::zero(); DEPTH];
    let generator = pallas::Point::generator().to_affine();
    let dummy_spends = (0..SPENDS)
        .map(|_| {
            Ok(LinkedSpend::new(
                MembershipCircuit::new(Fp::zero(), &siblings, 0, Fp::zero(), Fp::zero())
                    .map_err(|_| ProofError::InvalidShape)?,
                [Fp::zero(); NOTE_COMMITMENT_INPUTS],
                SpendAuthCircuit::new(generator, Fp::zero(), generator),
                Fp::one(),
                crate::spend_auth_circuit::binding_generator(),
            ))
        })
        .collect::<Result<Vec<_>, ProofError>>()?;
    let circuit = MultiTransferCircuit::<DEPTH, SPENDS, OUTPUTS>::new(
        &vec![0; SPENDS],
        &vec![0; OUTPUTS],
        dummy_spends,
        vec![[Fp::zero(); NOTE_COMMITMENT_INPUTS]; OUTPUTS],
        vec![Fp::one(); OUTPUTS],
        vec![crate::spend_auth_circuit::binding_generator(); OUTPUTS],
    )
    .map_err(|_| ProofError::InvalidShape)?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    let public = [Fp::from(transaction.preimage.fee)];
    let mut membership = Vec::with_capacity(SPENDS + 1);
    membership.push(transaction.preimage.anchor.field());
    for spend in &transaction.preimage.spends {
        membership.push(
            CanonicalField::from_bytes(spend.nullifier.0)
                .ok_or(ProofError::InvalidPublicInput)?
                .field(),
        );
    }
    let mut notes = transaction
        .preimage
        .outputs
        .iter()
        .map(|output| output.commitment.field())
        .collect::<Vec<_>>();
    notes.push(crate::types::network_field(
        &transaction.preimage.network_id,
    ));
    let mut authorization = Vec::with_capacity(SPENDS * 2);
    for spend in &transaction.preimage.spends {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&spend.randomized_key))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    for bytes in transaction
        .preimage
        .spends
        .iter()
        .map(|spend| &spend.value_commitment)
        .chain(
            transaction
                .preimage
                .outputs
                .iter()
                .map(|output| &output.value_commitment),
        )
    {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&public, &membership, &notes, &authorization]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

pub fn verify_authorized_multi_transfer<
    const DEPTH: usize,
    const SPENDS: usize,
    const OUTPUTS: usize,
>(
    k: u32,
    transaction: &AuthorizedTransaction,
) -> Result<(), ProofError> {
    if !transaction.preimage.programs.is_empty() {
        return Err(ProofError::InvalidShape);
    }
    verify_authorized_transaction(transaction)?;
    verify_multi_transfer_proof::<DEPTH, SPENDS, OUTPUTS>(k, transaction)
}

impl<const DEPTH: usize> TransferWitness<DEPTH> {
    fn circuit(&self) -> Result<LinkedTransferCircuit<DEPTH>, ProofError> {
        if self.input_values.len() != 1 || self.output_values.len() != 1 {
            return Err(ProofError::InvalidShape);
        }
        Ok(LinkedTransferCircuit::new(
            self.input_values[0],
            self.output_values[0],
            MembershipCircuit::new(
                self.commitment,
                &self.siblings,
                self.position,
                self.nullifier_key,
                self.rho,
            )
            .map_err(|_| ProofError::InvalidShape)?,
            self.input_note,
            self.output_note,
            SpendAuthCircuit::new(
                self.authority_key,
                self.authorization_randomizer,
                self.randomized_key,
            ),
            self.input_value_randomness,
            self.input_value_commitment,
            self.output_value_randomness,
            self.output_value_commitment,
        ))
    }
}

pub fn create_transfer_proof<const DEPTH: usize>(
    k: u32,
    witness: &TransferWitness<DEPTH>,
    fee: u64,
    anchor: CanonicalField,
    nullifier: [u8; 32],
) -> Result<Vec<u8>, ProofError> {
    let nullifier = CanonicalField::from_bytes(nullifier).ok_or(ProofError::InvalidPublicInput)?;
    let circuit = witness.circuit()?;
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let pk = keygen_pk(&params, vk, &circuit).map_err(|_| ProofError::ProvingFailed)?;
    let public = [Fp::from(fee)];
    let membership = [anchor.field(), nullifier.field()];
    let notes = vec![
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
            .hash(witness.output_note),
        witness.input_note[1],
    ];
    let randomized_coordinates = witness.randomized_key.coordinates();
    if bool::from(randomized_coordinates.is_none()) {
        return Err(ProofError::InvalidPublicInput);
    }
    let randomized_coordinates = randomized_coordinates.unwrap();
    let mut authorization = vec![*randomized_coordinates.x(), *randomized_coordinates.y()];
    authorization.extend(randomized_key_coordinates(witness.input_value_commitment)?);
    authorization.extend(randomized_key_coordinates(witness.output_value_commitment)?);
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public, &membership, &notes, &authorization]],
        rand::rngs::OsRng,
        &mut transcript,
    )
    .map_err(|_| ProofError::ProvingFailed)?;
    let proof = transcript.finalize();
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ProofError::ProofTooLarge);
    }
    Ok(proof)
}

pub fn verify_transfer_proof<const DEPTH: usize>(
    k: u32,
    transaction: &AuthorizedTransaction,
) -> Result<(), ProofError> {
    if !transaction.preimage.programs.is_empty() {
        return Err(ProofError::InvalidShape);
    }
    if transaction.backend_id != EXPERIMENTAL_TRANSFER_BACKEND
        || transaction.preimage.spends.len() != 1
        || transaction.preimage.outputs.len() != 1
        || transaction.proof.len() > MAX_PROOF_BYTES
    {
        return Err(ProofError::InvalidShape);
    }
    transaction.preimage.encode()?;
    let nullifier = CanonicalField::from_bytes(transaction.preimage.spends[0].nullifier.0)
        .ok_or(ProofError::InvalidPublicInput)?;
    let empty_siblings = vec![Fp::zero(); DEPTH];
    let circuit: LinkedTransferCircuit<DEPTH> = LinkedTransferCircuit::new(
        0,
        0,
        MembershipCircuit::new(Fp::zero(), &empty_siblings, 0, Fp::zero(), Fp::zero())
            .map_err(|_| ProofError::InvalidShape)?,
        [Fp::zero(); NOTE_COMMITMENT_INPUTS],
        [Fp::zero(); NOTE_COMMITMENT_INPUTS],
        SpendAuthCircuit::new(
            pallas::Point::generator().to_affine(),
            Fp::zero(),
            pallas::Point::generator().to_affine(),
        ),
        Fp::one(),
        crate::spend_auth_circuit::binding_generator(),
        Fp::one(),
        crate::spend_auth_circuit::binding_generator(),
    );
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    let public = [Fp::from(transaction.preimage.fee)];
    let membership = [transaction.preimage.anchor.field(), nullifier.field()];
    let notes = vec![
        transaction.preimage.outputs[0].commitment.field(),
        crate::types::network_field(&transaction.preimage.network_id),
    ];
    let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
        &transaction.preimage.spends[0].randomized_key,
    ))
    .ok_or(ProofError::InvalidPublicInput)?
    .to_affine();
    let randomized_coordinates = randomized_key.coordinates();
    if bool::from(randomized_coordinates.is_none()) {
        return Err(ProofError::InvalidPublicInput);
    }
    let randomized_coordinates = randomized_coordinates.unwrap();
    let mut authorization = vec![*randomized_coordinates.x(), *randomized_coordinates.y()];
    for bytes in [
        &transaction.preimage.spends[0].value_commitment,
        &transaction.preimage.outputs[0].value_commitment,
    ] {
        let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
            .ok_or(ProofError::InvalidPublicInput)?
            .to_affine();
        authorization.extend(randomized_key_coordinates(point)?);
    }
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&public, &membership, &notes, &authorization]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

pub fn verify_authorized_transfer<const DEPTH: usize>(
    k: u32,
    transaction: &AuthorizedTransaction,
) -> Result<(), ProofError> {
    if !transaction.preimage.programs.is_empty() {
        return Err(ProofError::InvalidShape);
    }
    verify_authorized_transaction(transaction)?;
    verify_transfer_proof::<DEPTH>(k, transaction)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;

    use crate::authorization::{prepare_same_owner_spends, sign_prepared_spends};
    use crate::keys::MasterSeed;
    use crate::state::Nullifier;
    use crate::transaction::{PublicOutput, PublicSpend, TransactionPreimage};
    use crate::types::NETWORK_ID_BYTES;

    use super::*;

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    fn value_commitment(value: u64, randomness: Fp) -> pallas::Affine {
        Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &crate::value_commitment_circuit::value_commitment_bytes(value, randomness),
        ))
        .unwrap()
        .to_affine()
    }

    #[test]
    fn experimental_transfer_backend_proves_then_authenticates() {
        const DEPTH: usize = 4;
        const K: u32 = 14;
        let keys = MasterSeed::new([9; 32])
            .derive([1; NETWORK_ID_BYTES])
            .unwrap();
        let address = keys.address(0).unwrap();
        let authority_key =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&address.spend_authority_key))
                .unwrap()
                .to_affine();
        let authority_coordinates = authority_key.coordinates().unwrap();
        let mut input_note = std::array::from_fn(|index| Fp::from(index as u64 + 40));
        input_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(30);
        input_note[1] = crate::types::network_field(&[1; NETWORK_ID_BYTES]);
        input_note[2] = Fp::zero();
        input_note[3] = Fp::zero();
        input_note[4] = crate::types::native_asset_fields()[0];
        input_note[5] = crate::types::native_asset_fields()[1];
        input_note[10] = *authority_coordinates.x();
        input_note[11] = *authority_coordinates.y();
        input_note[13] = Fp::from(101);
        let commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(input_note);
        let mut output_note = std::array::from_fn(|index| Fp::from(index as u64 + 80));
        output_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(25);
        output_note[1] = crate::types::network_field(&[1; NETWORK_ID_BYTES]);
        output_note[2] = Fp::zero();
        output_note[3] = Fp::zero();
        output_note[4] = crate::types::native_asset_fields()[0];
        output_note[5] = crate::types::native_asset_fields()[1];
        output_note[13] = Fp::from(102);
        let output_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(output_note);
        // Anchor this proof at the canonical empty tree so the consensus snapshot FFI can apply
        // the exact same authorized envelope as its first state transition.
        let mut empty = hash2(Fp::from(1), Fp::zero());
        let mut siblings = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            siblings.push(empty);
            empty = hash2(Fp::from(2), hash2(empty, empty));
        }
        let position = 0u64;
        let mut root = hash2(Fp::from(1), commitment);
        for (level, sibling) in siblings.iter().enumerate() {
            let pair = if ((position >> level) & 1) == 0 {
                hash2(root, *sibling)
            } else {
                hash2(*sibling, root)
            };
            root = hash2(Fp::from(2), pair);
        }
        let nullifier_key = Fp::from(21);
        let rho = Fp::from(22);
        let nullifier = hash2(
            Fp::from(3),
            hash2(hash2(nullifier_key, rho), Fp::from(position)),
        )
        .to_repr();
        let anchor = CanonicalField::from_field(root);
        let mut preimage = TransactionPreimage {
            network_id: [1; NETWORK_ID_BYTES],
            anchor,
            expiry_height: 100,
            fee: 5,
            spends: vec![PublicSpend {
                nullifier: Nullifier(nullifier),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    30,
                    Fp::from(101),
                ),
                randomized_key: [0; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(output_commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    25,
                    Fp::from(102),
                ),
                ephemeral_key: [32; 32],
                ciphertext: vec![33; 48],
                outgoing_ciphertext: vec![34; 32],
            }],
            programs: vec![],
        };
        let prepared = prepare_same_owner_spends(&keys, &mut preimage).unwrap();
        let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &preimage.spends[0].randomized_key,
        ))
        .unwrap()
        .to_affine();
        let witness: TransferWitness<DEPTH> = TransferWitness {
            input_values: vec![30],
            output_values: vec![25],
            commitment,
            input_note,
            output_note,
            authority_key,
            authorization_randomizer: prepared.randomizers()[0],
            randomized_key,
            siblings,
            position,
            nullifier_key,
            rho,
            input_value_randomness: Fp::from(101),
            input_value_commitment: value_commitment(30, Fp::from(101)),
            output_value_randomness: Fp::from(102),
            output_value_commitment: value_commitment(25, Fp::from(102)),
        };
        let proof = create_transfer_proof(K, &witness, 5, anchor, nullifier).unwrap();
        let mut mismatched_opening = witness.clone();
        mismatched_opening.input_note[0] += Fp::one();
        let mismatched_proof =
            create_transfer_proof(K, &mismatched_opening, 5, anchor, nullifier).unwrap();
        let spend_signatures =
            sign_prepared_spends(&prepared, &preimage, EXPERIMENTAL_TRANSFER_BACKEND, &proof)
                .unwrap();
        let binding_signature = crate::authorization::sign_binding_authorization(
            &preimage,
            EXPERIMENTAL_TRANSFER_BACKEND,
            &proof,
            &[Fp::from(101)],
            &[Fp::from(102)],
        )
        .unwrap();
        let transaction = AuthorizedTransaction {
            preimage,
            backend_id: EXPERIMENTAL_TRANSFER_BACKEND.to_owned(),
            proof,
            spend_signatures,
            binding_signature,
        };
        let mut unsupported_program = transaction.clone();
        unsupported_program
            .preimage
            .programs
            .push(crate::transaction::ProgramCall {
                program_id: [9; 32],
                function_id: 1,
                public_data_hash: [8; 32],
            });
        assert!(matches!(
            verify_authorized_multi_transfer::<DEPTH, 1, 1>(K, &unsupported_program),
            Err(ProofError::InvalidShape)
        ));
        let encoded = transaction.encode().unwrap();
        let mut extracted_network = [0u8; NETWORK_ID_BYTES];
        let mut extracted_anchor = [0u8; 32];
        let mut extracted_expiry = 0u64;
        let mut extracted_fee = 0u64;
        let mut extracted_nullifiers = [0u8; 32];
        let mut extracted_nullifier_count = 0usize;
        let mut extracted_commitments = [0u8; 32];
        let mut extracted_commitment_count = 0usize;
        assert_eq!(
            crate::onyx_verify_and_extract_transfer(
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                extracted_network.as_mut_ptr(),
                extracted_anchor.as_mut_ptr(),
                &mut extracted_expiry,
                &mut extracted_fee,
                extracted_nullifiers.as_mut_ptr(),
                1,
                &mut extracted_nullifier_count,
                extracted_commitments.as_mut_ptr(),
                1,
                &mut extracted_commitment_count,
            ),
            1
        );
        assert_eq!(extracted_network, [1; NETWORK_ID_BYTES]);
        assert_eq!(extracted_anchor, anchor.bytes());
        assert_eq!(extracted_expiry, 100);
        assert_eq!(extracted_fee, 5);
        assert_eq!(extracted_nullifier_count, 1);
        assert_eq!(extracted_nullifiers, nullifier);
        assert_eq!(extracted_commitment_count, 1);
        assert_eq!(
            extracted_commitments,
            CanonicalField::from_field(output_commitment).bytes()
        );

        // Seed the state with the note being spent. This models its creation in a prior block and
        // gives the verifier an authentic canonical snapshot whose root is the proof anchor.
        let mut prestate = crate::state::ShieldedState::<DEPTH>::new(10);
        let mut funding = transaction.preimage.clone();
        funding.anchor = prestate.root();
        funding.spends[0].nullifier = Nullifier([9; 32]);
        funding.outputs[0].commitment = CanonicalField::from_field(commitment);
        prestate.apply_bridge(&funding, [1; 32], 30, 0, 0).unwrap();
        assert_eq!(prestate.root(), anchor);
        let previous_snapshot = prestate.encode_snapshot();

        let mut snapshot_ptr = std::ptr::null_mut();
        let mut snapshot_len = 0usize;
        let mut applied_fee = 0u64;
        assert_eq!(
            crate::onyx_verify_apply_transfer(
                previous_snapshot.as_ptr(),
                previous_snapshot.len(),
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                [1u8; NETWORK_ID_BYTES].as_ptr(),
                1,
                &mut snapshot_ptr,
                &mut snapshot_len,
                &mut applied_fee,
            ),
            1
        );
        assert!(!snapshot_ptr.is_null());
        assert!(snapshot_len > 0);
        assert_eq!(applied_fee, 5);
        let snapshot = unsafe { std::slice::from_raw_parts(snapshot_ptr, snapshot_len) }.to_vec();
        crate::onyx_free(snapshot_ptr, snapshot_len);
        let restored = crate::state::ShieldedState::<DEPTH>::decode_snapshot(&snapshot).unwrap();
        assert!(restored.is_spent(&Nullifier(nullifier)));
        assert_eq!(restored.leaf_count(), 2);
        assert_ne!(restored.root(), anchor);
        assert_eq!(
            (
                restored.total_bridged(),
                restored.total_fees(),
                restored.circulating_supply()
            ),
            (30, 5, 25)
        );

        let mut rejected_ptr = std::ptr::null_mut();
        let mut rejected_len = 0usize;
        let mut rejected_fee = 0u64;
        assert_eq!(
            crate::onyx_verify_apply_transfer(
                std::ptr::null(),
                0,
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                [2u8; NETWORK_ID_BYTES].as_ptr(),
                1,
                &mut rejected_ptr,
                &mut rejected_len,
                &mut rejected_fee,
            ),
            -5
        );
        assert!(rejected_ptr.is_null());
        assert_eq!(rejected_len, 0);
        assert_eq!(
            crate::onyx_verify_apply_transfer(
                std::ptr::null(),
                0,
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                [1u8; NETWORK_ID_BYTES].as_ptr(),
                101,
                &mut rejected_ptr,
                &mut rejected_len,
                &mut rejected_fee,
            ),
            -5
        );

        let mut mismatched_transaction = transaction.clone();
        mismatched_transaction.proof = mismatched_proof;
        assert_eq!(
            verify_transfer_proof::<DEPTH>(K, &mismatched_transaction),
            Err(ProofError::VerificationFailed)
        );

        let mut wrong_randomized_key = transaction.clone();
        wrong_randomized_key.preimage.spends[0].randomized_key =
            pallas::Point::generator().to_bytes();
        assert_eq!(
            verify_transfer_proof::<DEPTH>(K, &wrong_randomized_key),
            Err(ProofError::VerificationFailed)
        );

        let mut substituted_commitment = transaction.clone();
        substituted_commitment.preimage.outputs[0].value_commitment =
            crate::value_commitment_circuit::value_commitment_bytes(25, Fp::from(103));
        assert_eq!(
            verify_transfer_proof::<DEPTH>(K, &substituted_commitment),
            Err(ProofError::VerificationFailed)
        );

        let mut cross_network = transaction.clone();
        cross_network.preimage.network_id = [2; NETWORK_ID_BYTES];
        assert_eq!(
            verify_transfer_proof::<DEPTH>(K, &cross_network),
            Err(ProofError::VerificationFailed)
        );

        let mut changed = transaction;
        changed.preimage.fee = 4;
        assert!(verify_authorized_transfer::<DEPTH>(K, &changed).is_err());
    }

    #[test]
    fn registered_private_token_transfer_proves_verifies_and_applies() {
        const DEPTH: usize = 2;
        const K: u32 = 14;
        const VALUE: u64 = 30;
        let keys = MasterSeed::new([19; 32])
            .derive([3; NETWORK_ID_BYTES])
            .unwrap();
        let address = keys.address(0).unwrap();
        let authority_key =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&address.spend_authority_key))
                .unwrap()
                .to_affine();
        let authority_coordinates = authority_key.coordinates().unwrap();

        let program = crate::token_program::standard_token_program::<DEPTH>(
            K,
            b"private-test-token/USD",
            1,
            Some(100),
        )
        .unwrap();
        let program_id = program.id().unwrap();
        let mut other_program = program.clone();
        other_program.manifest.extend_from_slice(b"/other");
        let other_program_id = other_program.id().unwrap();
        let program_fields = crate::types::pack_32(&program_id);
        let function_id = crate::token_program::transfer_function_id(1, 1).unwrap();

        let mut input_note = std::array::from_fn(|index| Fp::from(index as u64 + 140));
        input_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(VALUE);
        input_note[1] = crate::types::network_field(&[3; NETWORK_ID_BYTES]);
        input_note[2] = program_fields[0];
        input_note[3] = program_fields[1];
        input_note[4] = program_fields[0];
        input_note[5] = program_fields[1];
        input_note[10] = *authority_coordinates.x();
        input_note[11] = *authority_coordinates.y();
        input_note[13] = Fp::from(201);
        let commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(input_note);

        let mut output_note = std::array::from_fn(|index| Fp::from(index as u64 + 180));
        output_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(VALUE);
        output_note[1] = crate::types::network_field(&[3; NETWORK_ID_BYTES]);
        output_note[2] = program_fields[0];
        output_note[3] = program_fields[1];
        output_note[4] = program_fields[0];
        output_note[5] = program_fields[1];
        output_note[13] = Fp::from(202);
        let output_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(output_note);

        let mut empty = hash2(Fp::from(1), Fp::zero());
        let mut siblings = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            siblings.push(empty);
            empty = hash2(Fp::from(2), hash2(empty, empty));
        }
        let position = 0u64;
        let mut root = hash2(Fp::from(1), commitment);
        for sibling in &siblings {
            root = hash2(Fp::from(2), hash2(root, *sibling));
        }
        let nullifier_key = Fp::from(221);
        let rho = Fp::from(222);
        let nullifier = hash2(
            Fp::from(3),
            hash2(hash2(nullifier_key, rho), Fp::from(position)),
        )
        .to_repr();
        let anchor = CanonicalField::from_field(root);
        let mut preimage = TransactionPreimage {
            network_id: [3; NETWORK_ID_BYTES],
            anchor,
            expiry_height: 50,
            fee: 0,
            spends: vec![PublicSpend {
                nullifier: Nullifier(nullifier),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    VALUE,
                    Fp::from(201),
                ),
                randomized_key: [0; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(output_commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    VALUE,
                    Fp::from(202),
                ),
                ephemeral_key: [42; 32],
                ciphertext: vec![43; 48],
                outgoing_ciphertext: vec![44; 32],
            }],
            programs: vec![crate::transaction::ProgramCall {
                program_id,
                function_id,
                public_data_hash: crate::token_program::transfer_public_data_hash(),
            }],
        };
        let prepared = prepare_same_owner_spends(&keys, &mut preimage).unwrap();
        let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &preimage.spends[0].randomized_key,
        ))
        .unwrap()
        .to_affine();
        let witness = MultiTransferWitness::<DEPTH> {
            input_values: vec![VALUE],
            output_values: vec![VALUE],
            spends: vec![MultiSpendWitness {
                commitment,
                input_note,
                authority_key,
                authorization_randomizer: prepared.randomizers()[0],
                randomized_key,
                siblings,
                position,
                nullifier_key,
                rho,
                value_randomness: Fp::from(201),
                value_commitment: value_commitment(VALUE, Fp::from(201)),
            }],
            output_notes: vec![output_note],
            output_value_randomness: vec![Fp::from(202)],
            output_value_commitments: vec![value_commitment(VALUE, Fp::from(202))],
        };
        let mut wrong_asset_witness = witness.clone();
        wrong_asset_witness.output_notes[0][4] += Fp::one();
        let wrong_asset_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(wrong_asset_witness.output_notes[0]);
        let mut wrong_asset_authorization =
            randomized_key_coordinates(randomized_key).unwrap().to_vec();
        wrong_asset_authorization
            .extend(randomized_key_coordinates(value_commitment(VALUE, Fp::from(201))).unwrap());
        wrong_asset_authorization
            .extend(randomized_key_coordinates(value_commitment(VALUE, Fp::from(202))).unwrap());
        assert!(MockProver::run(
            K,
            &wrong_asset_witness.program_circuit::<1, 1>().unwrap(),
            vec![
                vec![Fp::zero()],
                vec![
                    anchor.field(),
                    CanonicalField::from_bytes(nullifier).unwrap().field()
                ],
                vec![
                    wrong_asset_commitment,
                    crate::types::network_field(&[3; NETWORK_ID_BYTES]),
                    program_fields[0],
                    program_fields[1],
                ],
                wrong_asset_authorization,
            ],
        )
        .unwrap()
        .verify()
        .is_err());
        let proof = create_token_transfer_proof::<DEPTH, 1, 1>(
            K,
            &witness,
            anchor,
            &[nullifier],
            program_id,
            function_id,
        )
        .unwrap();
        let base_transaction = AuthorizedTransaction {
            preimage: TransactionPreimage {
                programs: Vec::new(),
                ..preimage.clone()
            },
            backend_id: program_transfer_backend_id(1, 1),
            proof: proof.clone(),
            spend_signatures: Vec::new(),
            binding_signature: [0; 64],
        };
        verify_program_multi_transfer_proof::<DEPTH, 1, 1>(K, &base_transaction, &program_id)
            .unwrap();
        assert!(verify_program_multi_transfer_proof::<DEPTH, 1, 1>(
            K,
            &base_transaction,
            &other_program_id,
        )
        .is_err());
        let spend_signatures = sign_prepared_spends(
            &prepared,
            &preimage,
            crate::token_program::TOKEN_PROGRAM_BACKEND,
            &proof,
        )
        .unwrap();
        let binding_signature = crate::authorization::sign_binding_authorization(
            &preimage,
            crate::token_program::TOKEN_PROGRAM_BACKEND,
            &proof,
            &[Fp::from(201)],
            &[Fp::from(202)],
        )
        .unwrap();
        let transaction = AuthorizedTransaction {
            preimage: preimage.clone(),
            backend_id: crate::token_program::TOKEN_PROGRAM_BACKEND.to_owned(),
            proof,
            spend_signatures,
            binding_signature,
        };

        let encoded = transaction.encode().unwrap();
        assert_eq!(
            crate::onyx_verify_authorized_transfer(
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
            ),
            1
        );
        let mut state = crate::state::ShieldedState::<DEPTH>::new(10);
        state.register_program(program).unwrap();
        state.register_program(other_program).unwrap();
        assert!(matches!(
            verify_authorized_token_transfer::<DEPTH, 1, 1>(
                K,
                &transaction,
                Some(state.program_registry()),
                0,
            ),
            Err(ProofError::InvalidShape)
        ));
        assert!(verify_authorized_token_transfer::<DEPTH, 1, 1>(
            K,
            &transaction,
            Some(state.program_registry()),
            2,
        )
        .is_ok());

        let mut wrong_program = transaction.clone();
        wrong_program.preimage.programs[0].program_id = other_program_id;
        wrong_program.spend_signatures = sign_prepared_spends(
            &prepared,
            &wrong_program.preimage,
            crate::token_program::TOKEN_PROGRAM_BACKEND,
            &wrong_program.proof,
        )
        .unwrap();
        wrong_program.binding_signature = crate::authorization::sign_binding_authorization(
            &wrong_program.preimage,
            crate::token_program::TOKEN_PROGRAM_BACKEND,
            &wrong_program.proof,
            &[Fp::from(201)],
            &[Fp::from(202)],
        )
        .unwrap();
        assert!(matches!(
            verify_authorized_token_transfer::<DEPTH, 1, 1>(
                K,
                &wrong_program,
                Some(state.program_registry()),
                2,
            ),
            Err(ProofError::VerificationFailed)
        ));

        let mut wrong_fee = transaction.clone();
        wrong_fee.preimage.fee = 1;
        assert!(matches!(
            verify_authorized_token_transfer::<DEPTH, 1, 1>(
                K,
                &wrong_fee,
                Some(state.program_registry()),
                2,
            ),
            Err(ProofError::InvalidShape)
        ));

        let funding = TransactionPreimage {
            network_id: [3; NETWORK_ID_BYTES],
            anchor: state.root(),
            expiry_height: 50,
            fee: 0,
            spends: vec![],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    VALUE,
                    Fp::from(201),
                ),
                ephemeral_key: [52; 32],
                ciphertext: vec![53; 48],
                outgoing_ciphertext: vec![54; 32],
            }],
            programs: vec![],
        };
        state.apply_bridge(&funding, [1; 32], VALUE, 0, 1).unwrap();
        assert_eq!(state.root(), anchor);
        let previous_snapshot = state.encode_snapshot();
        let mut snapshot_ptr = std::ptr::null_mut();
        let mut snapshot_len = 0usize;
        let mut applied_fee = 99u64;
        assert_eq!(
            crate::onyx_verify_apply_transfer(
                previous_snapshot.as_ptr(),
                previous_snapshot.len(),
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                [3u8; NETWORK_ID_BYTES].as_ptr(),
                2,
                &mut snapshot_ptr,
                &mut snapshot_len,
                &mut applied_fee,
            ),
            1
        );
        assert_eq!(applied_fee, 0);
        let snapshot = unsafe { std::slice::from_raw_parts(snapshot_ptr, snapshot_len) }.to_vec();
        crate::onyx_free(snapshot_ptr, snapshot_len);
        let applied = crate::state::ShieldedState::<DEPTH>::decode_snapshot(&snapshot).unwrap();
        assert!(applied.is_spent(&Nullifier(nullifier)));
        assert_eq!(applied.leaf_count(), 2);
        assert_eq!(applied.program_count(), 2);
        assert_eq!(applied.total_fees(), 0);
        assert_eq!(applied.circulating_supply(), VALUE);
    }

    #[test]
    fn two_by_two_shape_proves_and_rejects_wrong_family() {
        const DEPTH: usize = 2;
        const K: u32 = 16;
        let keys = MasterSeed::new([19; 32])
            .derive([1; NETWORK_ID_BYTES])
            .unwrap();
        let address = keys.address(0).unwrap();
        let authority =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&address.spend_authority_key))
                .unwrap()
                .to_affine();
        let authority_coordinates = authority.coordinates().unwrap();
        let mut input_notes = [
            std::array::from_fn(|i| Fp::from(10 + i as u64)),
            std::array::from_fn(|i| Fp::from(40 + i as u64)),
        ];
        for (index, (note, value)) in input_notes.iter_mut().zip([30u64, 20]).enumerate() {
            note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(value);
            note[1] = crate::types::network_field(&[1; NETWORK_ID_BYTES]);
            note[2] = Fp::zero();
            note[3] = Fp::zero();
            note[4] = crate::types::native_asset_fields()[0];
            note[5] = crate::types::native_asset_fields()[1];
            note[10] = *authority_coordinates.x();
            note[11] = *authority_coordinates.y();
            note[13] = Fp::from(110 + index as u64);
        }
        let commitment = |note: [Fp; NOTE_COMMITMENT_INPUTS]| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(note)
        };
        let commitments = input_notes.map(commitment);
        let leaves = commitments.map(|cm| hash2(Fp::from(1), cm));
        let other = Fp::from(91);
        let parent = hash2(Fp::from(2), hash2(leaves[0], leaves[1]));
        let root = hash2(Fp::from(2), hash2(parent, other));
        let anchor = CanonicalField::from_field(root);
        let nullifier_keys = [Fp::from(61), Fp::from(62)];
        let rhos = [Fp::from(71), Fp::from(72)];
        let nullifiers: [[u8; 32]; 2] = std::array::from_fn(|index| {
            hash2(
                Fp::from(3),
                hash2(
                    hash2(nullifier_keys[index], rhos[index]),
                    Fp::from(index as u64),
                ),
            )
            .to_repr()
        });
        let mut output_notes = vec![
            std::array::from_fn(|i| Fp::from(100 + i as u64)),
            std::array::from_fn(|i| Fp::from(130 + i as u64)),
        ];
        output_notes[0][crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(25);
        output_notes[1][crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(20);
        output_notes[0][13] = Fp::from(120);
        output_notes[1][13] = Fp::from(121);
        for note in &mut output_notes {
            note[1] = crate::types::network_field(&[1; NETWORK_ID_BYTES]);
            note[2] = Fp::zero();
            note[3] = Fp::zero();
            note[4] = crate::types::native_asset_fields()[0];
            note[5] = crate::types::native_asset_fields()[1];
        }
        let outputs = output_notes
            .iter()
            .enumerate()
            .map(|(index, note)| PublicOutput {
                commitment: CanonicalField::from_field(commitment(*note)),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    [25, 20][index],
                    Fp::from(120 + index as u64),
                ),
                ephemeral_key: [32; 32],
                ciphertext: vec![33; 48],
                outgoing_ciphertext: vec![34; 32],
            })
            .collect();
        let mut preimage = TransactionPreimage {
            network_id: [1; NETWORK_ID_BYTES],
            anchor,
            expiry_height: 100,
            fee: 5,
            spends: nullifiers
                .iter()
                .enumerate()
                .map(|(index, nf)| PublicSpend {
                    nullifier: Nullifier(*nf),
                    value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                        [30, 20][index],
                        Fp::from(110 + index as u64),
                    ),
                    randomized_key: [0; 32],
                })
                .collect(),
            outputs,
            programs: vec![],
        };
        let prepared = prepare_same_owner_spends(&keys, &mut preimage).unwrap();
        let spends = (0..2)
            .map(|index| {
                let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                    &preimage.spends[index].randomized_key,
                ))
                .unwrap()
                .to_affine();
                MultiSpendWitness {
                    commitment: commitments[index],
                    input_note: input_notes[index],
                    authority_key: authority,
                    authorization_randomizer: prepared.randomizers()[index],
                    randomized_key,
                    siblings: vec![leaves[1 - index], other],
                    position: index as u64,
                    nullifier_key: nullifier_keys[index],
                    rho: rhos[index],
                    value_randomness: Fp::from(110 + index as u64),
                    value_commitment: value_commitment(
                        [30, 20][index],
                        Fp::from(110 + index as u64),
                    ),
                }
            })
            .collect();
        let witness = MultiTransferWitness {
            input_values: vec![30, 20],
            output_values: vec![25, 20],
            spends,
            output_notes,
            output_value_randomness: vec![Fp::from(120), Fp::from(121)],
            output_value_commitments: vec![
                value_commitment(25, Fp::from(120)),
                value_commitment(20, Fp::from(121)),
            ],
        };
        let proof = create_multi_transfer_proof::<DEPTH, 2, 2>(K, &witness, 5, anchor, &nullifiers)
            .unwrap();
        let backend_id = multi_transfer_backend_id(2, 2);
        let spend_signatures =
            sign_prepared_spends(&prepared, &preimage, &backend_id, &proof).unwrap();
        let binding_signature = crate::authorization::sign_binding_authorization(
            &preimage,
            &backend_id,
            &proof,
            &[Fp::from(110), Fp::from(111)],
            &[Fp::from(120), Fp::from(121)],
        )
        .unwrap();
        let transaction = AuthorizedTransaction {
            preimage,
            backend_id,
            proof,
            spend_signatures,
            binding_signature,
        };
        assert!(verify_authorized_multi_transfer::<DEPTH, 2, 2>(K, &transaction).is_ok());
        assert_eq!(
            verify_multi_transfer_proof::<DEPTH, 1, 2>(K, &transaction),
            Err(ProofError::InvalidShape)
        );
    }
}
