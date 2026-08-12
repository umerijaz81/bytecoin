//! Deterministic Onyx wallet scanning and witness state.

use std::collections::BTreeMap;

use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use halo2_proofs::pasta::Fp;
use pasta_curves::pallas;
use rand::RngCore;

use crate::authorization::{
    prepare_same_owner_spends, sign_binding_authorization, sign_prepared_spends,
};
use crate::bridge::{AuthorizedBridge, BridgePreimage};
use crate::compiler_backend::{create_compiler_proof_for_export, CompilerWitness};
use crate::keys::{EncryptedNote, FullViewingKey, KeyBundle, RecipientAddress};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::program::{ProgramEntry, ProgramRegistry};
use crate::program_context::{
    ContextualAuthorizedTransaction, ContextualProofBundle, ProgramContext, ProgramStateTransition,
    CONTEXTUAL_PROGRAM_BACKEND,
};
use crate::program_deployment::{
    deployment_hash, AuthorizedProgramDeployment, MAX_PROGRAM_ACTIVATION_DELAY,
    PROGRAM_DEPLOYMENT_FUNCTION_ID,
};
use crate::proof::{
    create_bridge_proof, create_mixed_token_transfer_proof, create_multi_transfer_proof,
    create_token_issuance_proof, multi_transfer_backend_id, BridgeWitness, MixedTokenWitness,
    MultiSpendWitness, MultiTransferWitness, TokenIssuanceWitness, BRIDGE_BACKEND,
};
use crate::standard_programs::{
    contextual_public_inputs, kind_for_schema, standard_artifact, standard_program_entry,
    StandardApplication, StandardProgramKind, STANDARD_CIRCUIT_K, STANDARD_FUNCTION_ID,
};
use crate::state::{CanonicalField, MerklePath, WitnessError, WitnessTree, ONYX_MERKLE_DEPTH};
use crate::token_issuance::{sign_issuer_authorization, AuthorizedTokenIssuance};
use crate::token_program::{
    issuance_function_id, issuance_policy_from_entry, issuance_public_data_hash,
    mixed_transfer_function_id, mixed_transfer_public_data_hash, standard_token_program,
    TOKEN_PROGRAM_BACKEND,
};
use crate::transaction::{
    AuthorizedTransaction, ProgramCall, PublicOutput, PublicSpend, TransactionPreimage,
};
use crate::types::NATIVE_ASSET_ID;
use crate::types::{write_varint, DecodeError, NotePlaintext, Reader};
use crate::value_commitment_circuit::value_commitment_bytes;

const WALLET_SNAPSHOT_VERSION: u8 = 2;
const LEGACY_WALLET_SNAPSHOT_VERSION: u8 = 1;
const MAX_WALLET_LEAVES: usize = 1_000_000;
const MAX_WALLET_NOTES: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletNote {
    pub commitment: CanonicalField,
    pub position: u64,
    pub plaintext: NotePlaintext,
    pub spent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletError {
    WrongNetwork,
    Transaction,
    Tree(WitnessError),
    Note(DecodeError),
    Snapshot,
}

#[derive(Debug)]
pub enum WalletBuildError {
    InvalidValue,
    InvalidRecipient,
    Crypto,
    InsufficientFunds,
}

struct StandardCallBuild {
    valid_from_height: u64,
    state: ProgramStateTransition,
    application: StandardApplication,
    witness: Vec<CanonicalField>,
}

struct BuiltNativeTransfer {
    transaction: AuthorizedTransaction,
    context: Option<ProgramContext>,
}

#[cfg(test)]
fn select_note_indices(
    notes: &[WalletNote],
    required: u64,
) -> Result<Vec<usize>, WalletBuildError> {
    select_matching_note_indices(notes, required, |_| true)
}

fn select_matching_note_indices(
    notes: &[WalletNote],
    required: u64,
    matches: impl Fn(&WalletNote) -> bool,
) -> Result<Vec<usize>, WalletBuildError> {
    let unspent = notes
        .iter()
        .enumerate()
        .filter(|(_, note)| !note.spent && matches(note))
        .collect::<Vec<_>>();
    if let Some((index, _)) = unspent
        .iter()
        .copied()
        .find(|(_, note)| note.plaintext.value >= required)
    {
        return Ok(vec![index]);
    }
    for first in 0..unspent.len() {
        for second in (first + 1)..unspent.len() {
            let value = unspent[first]
                .1
                .plaintext
                .value
                .checked_add(unspent[second].1.plaintext.value)
                .ok_or(WalletBuildError::InvalidValue)?;
            if value >= required {
                return Ok(vec![unspent[first].0, unspent[second].0]);
            }
        }
    }
    Err(WalletBuildError::InsufficientFunds)
}

fn select_asset_note_indices(
    notes: &[WalletNote],
    required: u64,
    program_id: &[u8; 32],
    asset_id: &[u8; 32],
) -> Result<Vec<usize>, WalletBuildError> {
    select_matching_note_indices(notes, required, |note| {
        note.plaintext.program_id == *program_id && note.plaintext.asset_id == *asset_id
    })
}

pub fn build_bridge(
    sender: &KeyBundle,
    recipient: &RecipientAddress,
    expiry_height: u64,
    fee: u64,
    legacy_amount: u64,
    legacy_stack_index: u64,
    legacy_key_image: [u8; 32],
    memo: Vec<u8>,
    circuit_k: u32,
) -> Result<AuthorizedBridge, WalletBuildError> {
    let note_value = legacy_amount
        .checked_sub(fee)
        .filter(|value| *value != 0)
        .ok_or(WalletBuildError::InvalidValue)?;
    if recipient.network_id
        != sender
            .full_viewing_key()
            .map_err(|_| WalletBuildError::Crypto)?
            .network_id()
    {
        return Err(WalletBuildError::InvalidRecipient);
    }
    let mut rho_wide = [0u8; 64];
    let mut randomness_wide = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut rho_wide);
    rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
    let rho = CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide));
    let randomness = CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide));
    // Reuse the note randomness as the value-commitment trapdoor. Recipients recover it through
    // authenticated note encryption and therefore retain the opening required for a later spend.
    let value_randomness = randomness.field();
    let note = NotePlaintext {
        network_id: recipient.network_id,
        program_id: [0; 32],
        asset_id: NATIVE_ASSET_ID,
        value: note_value,
        diversifier: recipient.diversifier,
        transmission_key: recipient.transmission_key,
        spend_authority_key: recipient.spend_authority_key,
        rho,
        randomness,
        memo,
    };
    let commitment = note
        .commitment()
        .map_err(|_| WalletBuildError::InvalidRecipient)?;
    let value_commitment_bytes = value_commitment_bytes(note_value, value_randomness);
    let value_commitment =
        Option::<pallas::Point>::from(pallas::Point::from_bytes(&value_commitment_bytes))
            .ok_or(WalletBuildError::Crypto)?
            .to_affine();
    let mut preimage = BridgePreimage {
        network_id: recipient.network_id,
        expiry_height,
        fee,
        legacy_amount,
        legacy_stack_index,
        legacy_key_image,
        output: PublicOutput {
            commitment,
            value_commitment: value_commitment_bytes,
            ephemeral_key: [0; 32],
            ciphertext: vec![],
            outgoing_ciphertext: vec![],
        },
    };
    let binding = preimage
        .encryption_binding()
        .map_err(|_| WalletBuildError::Crypto)?;
    let encrypted = sender
        .encrypt_note(&note, recipient, binding, 0)
        .map_err(|_| WalletBuildError::Crypto)?;
    preimage.output.ephemeral_key = encrypted.ephemeral_key;
    preimage.output.ciphertext = encrypted.ciphertext;
    preimage.output.outgoing_ciphertext = encrypted.outgoing_ciphertext;
    let note_inputs: [Fp; NOTE_COMMITMENT_INPUTS] = note
        .commitment_inputs()
        .map_err(|_| WalletBuildError::Crypto)?;
    let proof = create_bridge_proof(
        circuit_k,
        &preimage,
        &BridgeWitness {
            output_note: note_inputs,
            output_value_randomness: value_randomness,
            output_value_commitment: value_commitment,
        },
    )
    .map_err(|_| WalletBuildError::Crypto)?;
    Ok(AuthorizedBridge {
        preimage,
        backend_id: BRIDGE_BACKEND.to_owned(),
        proof,
        ownership_signature: [0; 64],
    })
}

pub fn build_token_issuance(
    issuer: &KeyBundle,
    recipient: &RecipientAddress,
    anchor: CanonicalField,
    program_id: [u8; 32],
    sequence: u64,
    issued_amount: u64,
    expiry_height: u64,
    memo: Vec<u8>,
    circuit_k: u32,
) -> Result<AuthorizedTokenIssuance, WalletBuildError> {
    if issued_amount == 0
        || recipient.network_id
            != issuer
                .full_viewing_key()
                .map_err(|_| WalletBuildError::Crypto)?
                .network_id()
    {
        return Err(WalletBuildError::InvalidRecipient);
    }
    let mut rho_wide = [0u8; 64];
    let mut randomness_wide = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut rho_wide);
    rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
    let note = NotePlaintext {
        network_id: recipient.network_id,
        program_id,
        asset_id: program_id,
        value: issued_amount,
        diversifier: recipient.diversifier,
        transmission_key: recipient.transmission_key,
        spend_authority_key: recipient.spend_authority_key,
        rho: CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide)),
        randomness: CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide)),
        memo,
    };
    let value_randomness = note.randomness.field();
    let commitment = note.commitment().map_err(|_| WalletBuildError::Crypto)?;
    let value_commitment_bytes = value_commitment_bytes(issued_amount, value_randomness);
    let value_commitment =
        Option::<pallas::Point>::from(pallas::Point::from_bytes(&value_commitment_bytes))
            .ok_or(WalletBuildError::Crypto)?
            .to_affine();
    let mut preimage = TransactionPreimage {
        network_id: recipient.network_id,
        anchor,
        expiry_height,
        fee: 0,
        spends: vec![],
        outputs: vec![PublicOutput {
            commitment,
            value_commitment: value_commitment_bytes,
            ephemeral_key: [0; 32],
            ciphertext: vec![],
            outgoing_ciphertext: vec![],
        }],
        programs: vec![ProgramCall {
            program_id,
            function_id: issuance_function_id(1).expect("one-output issuance is supported"),
            public_data_hash: issuance_public_data_hash(sequence, issued_amount),
        }],
    };
    let binding = preimage
        .encryption_binding()
        .map_err(|_| WalletBuildError::Crypto)?;
    let encrypted = issuer
        .encrypt_note(&note, recipient, binding, 0)
        .map_err(|_| WalletBuildError::Crypto)?;
    preimage.outputs[0].ephemeral_key = encrypted.ephemeral_key;
    preimage.outputs[0].ciphertext = encrypted.ciphertext;
    preimage.outputs[0].outgoing_ciphertext = encrypted.outgoing_ciphertext;
    let witness = TokenIssuanceWitness {
        output_values: vec![issued_amount],
        output_notes: vec![note
            .commitment_inputs()
            .map_err(|_| WalletBuildError::Crypto)?],
        output_value_randomness: vec![value_randomness],
        output_value_commitments: vec![value_commitment],
    };
    let proof = create_token_issuance_proof::<1>(
        circuit_k,
        &witness,
        issued_amount,
        recipient.network_id,
        program_id,
    )
    .map_err(|_| WalletBuildError::Crypto)?;
    let binding_signature = sign_binding_authorization(
        &preimage,
        TOKEN_PROGRAM_BACKEND,
        &proof,
        &[],
        &[value_randomness],
    )
    .map_err(|_| WalletBuildError::Crypto)?;
    let mut issuance = AuthorizedTokenIssuance {
        sequence,
        issued_amount,
        transaction: AuthorizedTransaction {
            preimage,
            backend_id: TOKEN_PROGRAM_BACKEND.to_owned(),
            proof,
            spend_signatures: vec![],
            binding_signature,
        },
        issuer_signature: [0; 64],
    };
    issuance.issuer_signature =
        sign_issuer_authorization(issuer, &issuance).map_err(|_| WalletBuildError::Crypto)?;
    Ok(issuance)
}

impl From<WitnessError> for WalletError {
    fn from(value: WitnessError) -> Self {
        Self::Tree(value)
    }
}

#[derive(Clone)]
pub struct WalletState<const DEPTH: usize = ONYX_MERKLE_DEPTH> {
    network_id: [u8; 16],
    tree: WitnessTree<DEPTH>,
    notes: Vec<WalletNote>,
    programs: ProgramRegistry,
    issuance: BTreeMap<[u8; 32], WalletTokenIssuanceState>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WalletTokenIssuanceState {
    issued_supply: u64,
    next_sequence: u64,
}

impl<const DEPTH: usize> WalletState<DEPTH> {
    pub fn new(network_id: [u8; 16]) -> Self {
        Self {
            network_id,
            tree: WitnessTree::default(),
            notes: Vec::new(),
            programs: ProgramRegistry::default(),
            issuance: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    pub fn network_id(&self) -> [u8; 16] {
        self.network_id
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn notes(&self) -> &[WalletNote] {
        &self.notes
    }

    pub fn program_registry(&self) -> &ProgramRegistry {
        &self.programs
    }

    pub fn token_issued_supply(&self, program_id: &[u8; 32]) -> u64 {
        self.issuance
            .get(program_id)
            .map(|state| state.issued_supply)
            .unwrap_or(0)
    }

    pub fn token_next_issuance_sequence(&self, program_id: &[u8; 32]) -> u64 {
        self.issuance
            .get(program_id)
            .map(|state| state.next_sequence)
            .unwrap_or(0)
    }

    pub fn register_program(&mut self, entry: ProgramEntry) -> Result<(), WalletError> {
        self.programs
            .register(entry)
            .map(|_| ())
            .map_err(|_| WalletError::Transaction)
    }

    pub fn record_program_deployment(
        &mut self,
        deployment: &AuthorizedProgramDeployment,
        block_height: u64,
        circuit_k: u32,
    ) -> Result<(), WalletError> {
        let maximum_activation = block_height
            .checked_add(MAX_PROGRAM_ACTIVATION_DELAY)
            .ok_or(WalletError::Transaction)?;
        if deployment.activation_height <= block_height
            || deployment.activation_height > maximum_activation
        {
            return Err(WalletError::Transaction);
        }
        let entry = deployment
            .program_entry::<DEPTH>(circuit_k)
            .map_err(|_| WalletError::Transaction)?;
        let program_id = entry.id().map_err(|_| WalletError::Transaction)?;
        if deployment.funding.preimage.programs.len() != 1
            || deployment.funding.preimage.programs[0].program_id != program_id
        {
            return Err(WalletError::Transaction);
        }
        self.register_program(entry)
    }

    pub fn record_token_issuance_envelope(
        &mut self,
        issuance: &AuthorizedTokenIssuance,
        block_height: u64,
    ) -> Result<(), WalletError> {
        let transaction = &issuance.transaction.preimage;
        if transaction.programs.len() != 1
            || transaction.spends.len() != 0
            || !(1..=2).contains(&transaction.outputs.len())
            || transaction.fee != 0
        {
            return Err(WalletError::Transaction);
        }
        let call = &transaction.programs[0];
        if call.function_id
            != issuance_function_id(transaction.outputs.len()).ok_or(WalletError::Transaction)?
            || call.public_data_hash
                != issuance_public_data_hash(issuance.sequence, issuance.issued_amount)
            || self
                .programs
                .active_function(&call.program_id, call.function_id, block_height)
                .is_err()
        {
            return Err(WalletError::Transaction);
        }
        self.record_token_issuance(call.program_id, issuance.sequence, issuance.issued_amount)
    }

    pub fn record_token_issuance(
        &mut self,
        program_id: [u8; 32],
        sequence: u64,
        issued_amount: u64,
    ) -> Result<(), WalletError> {
        let entry = self
            .programs
            .get(&program_id)
            .ok_or(WalletError::Transaction)?;
        let (_, _, policy) =
            issuance_policy_from_entry(entry).map_err(|_| WalletError::Transaction)?;
        let current = self.issuance.get(&program_id).copied().unwrap_or_default();
        if sequence != current.next_sequence || issued_amount == 0 {
            return Err(WalletError::Transaction);
        }
        let issued_supply = current
            .issued_supply
            .checked_add(issued_amount)
            .filter(|supply| *supply <= policy.max_supply)
            .ok_or(WalletError::Transaction)?;
        let next_sequence = sequence.checked_add(1).ok_or(WalletError::Transaction)?;
        self.issuance.insert(
            program_id,
            WalletTokenIssuanceState {
                issued_supply,
                next_sequence,
            },
        );
        Ok(())
    }

    pub fn unspent_balance(&self) -> Result<u64, WalletError> {
        self.unspent_asset_balance(&[0; 32], &NATIVE_ASSET_ID)
    }

    pub fn unspent_asset_balance(
        &self,
        program_id: &[u8; 32],
        asset_id: &[u8; 32],
    ) -> Result<u64, WalletError> {
        self.notes
            .iter()
            .filter(|note| {
                !note.spent
                    && &note.plaintext.program_id == program_id
                    && &note.plaintext.asset_id == asset_id
            })
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.plaintext.value)
                    .ok_or(WalletError::Snapshot)
            })
    }

    pub fn unspent_asset_note_count(&self, program_id: &[u8; 32], asset_id: &[u8; 32]) -> usize {
        self.notes
            .iter()
            .filter(|note| {
                !note.spent
                    && &note.plaintext.program_id == program_id
                    && &note.plaintext.asset_id == asset_id
            })
            .count()
    }

    pub fn witness(&self, note_index: usize) -> Result<MerklePath, WalletError> {
        let note = self.notes.get(note_index).ok_or(WalletError::Transaction)?;
        Ok(self.tree.witness(note.position)?)
    }

    pub fn build_transfer(
        &self,
        keys: &KeyBundle,
        recipient: &RecipientAddress,
        amount: u64,
        fee: u64,
        expiry_height: u64,
        memo: Vec<u8>,
        circuit_k: u32,
    ) -> Result<AuthorizedTransaction, WalletBuildError> {
        self.build_native_transfer(
            keys,
            recipient,
            amount,
            fee,
            expiry_height,
            memo,
            circuit_k,
            vec![],
            None,
            false,
        )
        .map(|built| built.transaction)
    }

    #[cfg(feature = "qualification-fixtures")]
    pub fn build_authenticated_invalid_proof_transfer(
        &self,
        keys: &KeyBundle,
        recipient: &RecipientAddress,
        amount: u64,
        fee: u64,
        expiry_height: u64,
        memo: Vec<u8>,
        circuit_k: u32,
    ) -> Result<AuthorizedTransaction, WalletBuildError> {
        self.build_native_transfer(
            keys,
            recipient,
            amount,
            fee,
            expiry_height,
            memo,
            circuit_k,
            vec![],
            None,
            true,
        )
        .map(|built| built.transaction)
    }

    pub fn build_program_deployment(
        &self,
        keys: &KeyBundle,
        token_manifest: Vec<u8>,
        activation_height: u64,
        deactivation_height: Option<u64>,
        expiry_height: u64,
        fee: u64,
        program_k: u32,
        funding_k: u32,
    ) -> Result<AuthorizedProgramDeployment, WalletBuildError> {
        // Reject an unavailable funding spend before constructing the comparatively expensive token
        // artifact. In particular, a wallet-side pending reservation must fail in bounded time rather
        // than rebuilding proving/verifying keys only to discover the same insufficient balance in
        // build_native_transfer below.
        let required = fee.checked_add(1).ok_or(WalletBuildError::InvalidValue)?;
        select_asset_note_indices(&self.notes, required, &[0; 32], &NATIVE_ASSET_ID)?;
        let entry = standard_token_program::<DEPTH>(
            program_k,
            &token_manifest,
            activation_height,
            deactivation_height,
        )
        .map_err(|_| WalletBuildError::InvalidValue)?;
        self.build_program_deployment_entry(keys, entry, expiry_height, fee, funding_k)
    }

    pub fn build_standard_program_deployment(
        &self,
        keys: &KeyBundle,
        kind: StandardProgramKind,
        activation_height: u64,
        deactivation_height: Option<u64>,
        expiry_height: u64,
        fee: u64,
        circuit_k: u32,
    ) -> Result<AuthorizedProgramDeployment, WalletBuildError> {
        let entry = standard_program_entry(kind, activation_height, deactivation_height)
            .map_err(|_| WalletBuildError::InvalidValue)?;
        self.build_program_deployment_entry(keys, entry, expiry_height, fee, circuit_k)
    }

    fn build_program_deployment_entry(
        &self,
        keys: &KeyBundle,
        entry: crate::program::ProgramEntry,
        expiry_height: u64,
        fee: u64,
        circuit_k: u32,
    ) -> Result<AuthorizedProgramDeployment, WalletBuildError> {
        let program_id = entry.id().map_err(|_| WalletBuildError::Crypto)?;
        let activation_height = entry.activation_height;
        let deactivation_height = entry.deactivation_height;
        let manifest = entry.manifest;
        let call = ProgramCall {
            program_id,
            function_id: PROGRAM_DEPLOYMENT_FUNCTION_ID,
            public_data_hash: deployment_hash(
                self.network_id,
                &manifest,
                activation_height,
                deactivation_height,
            ),
        };
        // A one-unit self-payment gives the generic native builder a canonical non-zero output;
        // every remaining selected unit returns as shielded change and only `fee` is destroyed.
        let self_address = keys.address(0).map_err(|_| WalletBuildError::Crypto)?;
        let funding = self
            .build_native_transfer(
                keys,
                &self_address,
                1,
                fee,
                expiry_height,
                vec![],
                circuit_k,
                vec![call],
                None,
                false,
            )?
            .transaction;
        Ok(AuthorizedProgramDeployment {
            token_manifest: manifest,
            activation_height,
            deactivation_height,
            funding,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_standard_program_call(
        &self,
        keys: &KeyBundle,
        program_id: [u8; 32],
        valid_from_height: u64,
        expiry_height: u64,
        application: StandardApplication,
        prior_state: CanonicalField,
        next_state: CanonicalField,
        witness: Vec<CanonicalField>,
        circuit_k: u32,
    ) -> Result<ContextualAuthorizedTransaction, WalletBuildError> {
        if !(10..=20).contains(&circuit_k)
            || valid_from_height > expiry_height
            || prior_state == next_state
            || witness.is_empty()
        {
            return Err(WalletBuildError::InvalidValue);
        }
        let (entry, function) = self
            .programs
            .active_function(&program_id, STANDARD_FUNCTION_ID, valid_from_height)
            .map_err(|_| WalletBuildError::InvalidValue)?;
        let kind = kind_for_schema(&function.public_input_schema_hash)
            .ok_or(WalletBuildError::InvalidValue)?;
        let artifact = standard_artifact(kind);
        if application.kind() != kind
            || entry.backend != crate::compiler_backend::COMPILER_PROGRAM_BACKEND
            || function.verifying_key != artifact.verifying_key
        {
            return Err(WalletBuildError::InvalidValue);
        }
        let expected_witness = match kind {
            StandardProgramKind::Multisig => 48,
            StandardProgramKind::Nft | StandardProgramKind::Vesting | StandardProgramKind::Swap => {
                1
            }
        };
        if witness.len() != expected_witness {
            return Err(WalletBuildError::InvalidValue);
        }
        let call = ProgramCall {
            program_id,
            function_id: STANDARD_FUNCTION_ID,
            public_data_hash: [0; 32],
        };
        let self_address = keys.address(0).map_err(|_| WalletBuildError::Crypto)?;
        let built = self.build_native_transfer(
            keys,
            &self_address,
            1,
            0,
            expiry_height,
            vec![],
            circuit_k,
            vec![call],
            Some(StandardCallBuild {
                valid_from_height,
                state: ProgramStateTransition {
                    prior: prior_state.bytes(),
                    next: next_state.bytes(),
                },
                application,
                witness,
            }),
            false,
        )?;
        Ok(ContextualAuthorizedTransaction {
            transaction: built.transaction,
            contexts: vec![built.context.ok_or(WalletBuildError::Crypto)?],
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_native_transfer(
        &self,
        keys: &KeyBundle,
        recipient: &RecipientAddress,
        amount: u64,
        fee: u64,
        expiry_height: u64,
        memo: Vec<u8>,
        circuit_k: u32,
        programs: Vec<ProgramCall>,
        standard_call: Option<StandardCallBuild>,
        invalidate_proof: bool,
    ) -> Result<BuiltNativeTransfer, WalletBuildError> {
        let required = amount
            .checked_add(fee)
            .filter(|value| amount != 0 && *value != 0)
            .ok_or(WalletBuildError::InvalidValue)?;
        let selected_indices =
            select_asset_note_indices(&self.notes, required, &[0; 32], &NATIVE_ASSET_ID)?;
        let selected = selected_indices
            .iter()
            .map(|index| &self.notes[*index])
            .collect::<Vec<_>>();
        if recipient.network_id != self.network_id
            || selected
                .iter()
                .any(|note| note.plaintext.network_id != recipient.network_id)
        {
            return Err(WalletBuildError::InvalidRecipient);
        }
        let input_value = selected.iter().try_fold(0u64, |sum, note| {
            sum.checked_add(note.plaintext.value)
                .ok_or(WalletBuildError::InvalidValue)
        })?;
        let change = input_value - required;
        let mut recipients = vec![(recipient.clone(), amount, memo)];
        if change != 0 {
            recipients.push((
                keys.address(0).map_err(|_| WalletBuildError::Crypto)?,
                change,
                vec![],
            ));
        }

        let mut output_notes = Vec::with_capacity(recipients.len());
        let mut output_randomness = Vec::with_capacity(recipients.len());
        let mut output_commitments = Vec::with_capacity(recipients.len());
        let mut outputs = Vec::with_capacity(recipients.len());
        for (recipient, value, memo) in &recipients {
            let mut rho_wide = [0u8; 64];
            let mut randomness_wide = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut rho_wide);
            rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
            let note = NotePlaintext {
                network_id: self.network_id,
                program_id: [0; 32],
                asset_id: NATIVE_ASSET_ID,
                value: *value,
                diversifier: recipient.diversifier,
                transmission_key: recipient.transmission_key,
                spend_authority_key: recipient.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide)),
                randomness: CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide)),
                memo: memo.clone(),
            };
            let randomness = note.randomness.field();
            let commitment = note.commitment().map_err(|_| WalletBuildError::Crypto)?;
            let commitment_bytes = value_commitment_bytes(*value, randomness);
            let commitment_point =
                Option::<pallas::Point>::from(pallas::Point::from_bytes(&commitment_bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
            output_notes.push(note);
            output_randomness.push(randomness);
            output_commitments.push(commitment_point);
            outputs.push(PublicOutput {
                commitment,
                value_commitment: commitment_bytes,
                ephemeral_key: [0; 32],
                ciphertext: vec![],
                outgoing_ciphertext: vec![],
            });
        }

        let input_randomness = selected
            .iter()
            .map(|note| note.plaintext.randomness.field())
            .collect::<Vec<_>>();
        let input_commitments = selected
            .iter()
            .zip(&input_randomness)
            .map(|(note, randomness)| {
                let bytes = value_commitment_bytes(note.plaintext.value, *randomness);
                let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                Ok((bytes, point))
            })
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let nullifiers = selected
            .iter()
            .map(|note| {
                note.plaintext
                    .nullifier(keys.nullifier_key(), note.position)
            })
            .collect::<Vec<_>>();
        let mut preimage = TransactionPreimage {
            network_id: self.network_id,
            anchor: self.root(),
            expiry_height,
            fee,
            spends: nullifiers
                .iter()
                .zip(&input_commitments)
                .map(|(nullifier, (value_commitment, _))| PublicSpend {
                    nullifier: *nullifier,
                    value_commitment: *value_commitment,
                    randomized_key: [0; 32],
                })
                .collect(),
            outputs,
            programs,
        };
        let prepared =
            prepare_same_owner_spends(keys, &mut preimage).map_err(|_| WalletBuildError::Crypto)?;
        let binding = preimage
            .encryption_binding()
            .map_err(|_| WalletBuildError::Crypto)?;
        for (index, (note, recipient)) in output_notes.iter().zip(&recipients).enumerate() {
            let encrypted = keys
                .encrypt_note(note, &recipient.0, binding, index as u32)
                .map_err(|_| WalletBuildError::Crypto)?;
            preimage.outputs[index].ephemeral_key = encrypted.ephemeral_key;
            preimage.outputs[index].ciphertext = encrypted.ciphertext;
            preimage.outputs[index].outgoing_ciphertext = encrypted.outgoing_ciphertext;
        }

        let spends = selected
            .iter()
            .zip(&selected_indices)
            .zip(&input_randomness)
            .zip(&input_commitments)
            .enumerate()
            .map(
                |(spend_index, (((input, note_index), randomness), (_, commitment)))| {
                    let path = self
                        .witness(*note_index)
                        .map_err(|_| WalletBuildError::Crypto)?;
                    let authority = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &input.plaintext.spend_authority_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &preimage.spends[spend_index].randomized_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    Ok(MultiSpendWitness {
                        commitment: input.commitment.field(),
                        input_note: input
                            .plaintext
                            .commitment_inputs()
                            .map_err(|_| WalletBuildError::Crypto)?,
                        authority_key: authority,
                        authorization_randomizer: prepared.randomizers()[spend_index],
                        randomized_key,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|sibling| sibling.field())
                            .collect(),
                        position: path.position,
                        nullifier_key: keys.nullifier_key().field(),
                        rho: input.plaintext.rho.field(),
                        value_randomness: *randomness,
                        value_commitment: *commitment,
                    })
                },
            )
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let witness = MultiTransferWitness::<DEPTH> {
            input_values: selected.iter().map(|note| note.plaintext.value).collect(),
            output_values: recipients.iter().map(|recipient| recipient.1).collect(),
            spends,
            output_notes: output_notes
                .iter()
                .map(|note| {
                    note.commitment_inputs()
                        .map_err(|_| WalletBuildError::Crypto)
                })
                .collect::<Result<Vec<_>, _>>()?,
            output_value_randomness: output_randomness.clone(),
            output_value_commitments: output_commitments,
        };
        let base_backend_id = multi_transfer_backend_id(selected.len(), recipients.len());
        let nullifier_bytes = nullifiers
            .iter()
            .map(|nullifier| nullifier.0)
            .collect::<Vec<_>>();
        let base_proof = match (selected.len(), recipients.len()) {
            (1, 1) => create_multi_transfer_proof::<DEPTH, 1, 1>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (1, 2) => create_multi_transfer_proof::<DEPTH, 1, 2>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (2, 1) => create_multi_transfer_proof::<DEPTH, 2, 1>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (2, 2) => create_multi_transfer_proof::<DEPTH, 2, 2>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            _ => return Err(WalletBuildError::Crypto),
        }
        .map_err(|_| WalletBuildError::Crypto)?;
        let (backend_id, proof, context) = match standard_call {
            Some(call) => {
                if preimage.programs.len() != 1 || fee != 0 {
                    return Err(WalletBuildError::InvalidValue);
                }
                let context = ProgramContext::from_transaction(
                    &preimage,
                    0,
                    call.valid_from_height,
                    Some(call.state),
                    call.application
                        .encode()
                        .map_err(|_| WalletBuildError::InvalidValue)?,
                )
                .map_err(|_| WalletBuildError::InvalidValue)?;
                preimage.programs[0].public_data_hash =
                    context.hash().map_err(|_| WalletBuildError::Crypto)?;
                let kind = call.application.kind();
                let artifact = standard_artifact(kind);
                let public_inputs = contextual_public_inputs(&context, kind)
                    .map_err(|_| WalletBuildError::InvalidValue)?;
                let private_witness = call
                    .witness
                    .iter()
                    .map(|value| value.field())
                    .collect::<Vec<_>>();
                let mut parameters = public_inputs[..public_inputs.len() - 1].to_vec();
                parameters.extend(private_witness);
                let program_proof = create_compiler_proof_for_export(
                    artifact.ir,
                    STANDARD_CIRCUIT_K,
                    artifact.export,
                    CompilerWitness { parameters },
                    &public_inputs,
                )
                .map_err(|_| WalletBuildError::Crypto)?;
                let proof = ContextualProofBundle {
                    base_backend_id,
                    base_proof,
                    program_proofs: vec![program_proof],
                }
                .encode()
                .map_err(|_| WalletBuildError::Crypto)?;
                (CONTEXTUAL_PROGRAM_BACKEND.to_owned(), proof, Some(context))
            }
            None => (base_backend_id, base_proof, None),
        };
        #[cfg(feature = "qualification-fixtures")]
        let mut proof = proof;
        #[cfg(feature = "qualification-fixtures")]
        if invalidate_proof {
            // Preserve the canonical proof length and all public transaction metadata, but alter the
            // completed Halo2 transcript before signing it. The signatures below therefore remain
            // authentic for these exact invalid proof bytes and cheap authorization prechecks pass.
            let last = proof.last_mut().ok_or(WalletBuildError::Crypto)?;
            *last ^= 0x01;
        }
        #[cfg(not(feature = "qualification-fixtures"))]
        let _ = invalidate_proof;
        let spend_signatures = sign_prepared_spends(&prepared, &preimage, &backend_id, &proof)
            .map_err(|_| WalletBuildError::Crypto)?;
        let binding_signature = sign_binding_authorization(
            &preimage,
            &backend_id,
            &proof,
            &input_randomness,
            &output_randomness,
        )
        .map_err(|_| WalletBuildError::Crypto)?;
        Ok(BuiltNativeTransfer {
            transaction: AuthorizedTransaction {
                preimage,
                backend_id,
                proof,
                spend_signatures,
                binding_signature,
            },
            context,
        })
    }

    pub fn build_mixed_token_transfer(
        &self,
        keys: &KeyBundle,
        recipient: &RecipientAddress,
        program_id: [u8; 32],
        token_amount: u64,
        fee: u64,
        expiry_height: u64,
        memo: Vec<u8>,
        circuit_k: u32,
    ) -> Result<AuthorizedTransaction, WalletBuildError> {
        if recipient.network_id != self.network_id
            || program_id == [0; 32]
            || token_amount == 0
            || fee == 0
        {
            return Err(WalletBuildError::InvalidValue);
        }
        let token_indices =
            select_asset_note_indices(&self.notes, token_amount, &program_id, &program_id)?;
        let native_indices =
            select_asset_note_indices(&self.notes, fee, &[0; 32], &NATIVE_ASSET_ID)?;
        let token_inputs = token_indices
            .iter()
            .map(|index| &self.notes[*index])
            .collect::<Vec<_>>();
        let native_inputs = native_indices
            .iter()
            .map(|index| &self.notes[*index])
            .collect::<Vec<_>>();
        let sum = |notes: &[&WalletNote]| {
            notes.iter().try_fold(0u64, |sum, note| {
                sum.checked_add(note.plaintext.value)
                    .ok_or(WalletBuildError::InvalidValue)
            })
        };
        let token_change = sum(&token_inputs)? - token_amount;
        let native_change = sum(&native_inputs)? - fee;
        let change_address = keys.address(0).map_err(|_| WalletBuildError::Crypto)?;
        let mut output_specs = vec![(
            recipient.clone(),
            token_amount,
            memo,
            program_id,
            program_id,
        )];
        if token_change != 0 {
            output_specs.push((
                change_address.clone(),
                token_change,
                vec![],
                program_id,
                program_id,
            ));
        }
        let token_output_count = output_specs.len();
        output_specs.push((
            change_address,
            native_change,
            vec![],
            [0; 32],
            NATIVE_ASSET_ID,
        ));

        let mut output_notes = Vec::with_capacity(output_specs.len());
        let mut output_randomness = Vec::with_capacity(output_specs.len());
        let mut output_commitments = Vec::with_capacity(output_specs.len());
        let mut outputs = Vec::with_capacity(output_specs.len());
        for (recipient, value, memo, note_program, asset_id) in &output_specs {
            let mut rho_wide = [0u8; 64];
            let mut randomness_wide = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut rho_wide);
            rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
            let note = NotePlaintext {
                network_id: self.network_id,
                program_id: *note_program,
                asset_id: *asset_id,
                value: *value,
                diversifier: recipient.diversifier,
                transmission_key: recipient.transmission_key,
                spend_authority_key: recipient.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide)),
                randomness: CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide)),
                memo: memo.clone(),
            };
            let randomness = note.randomness.field();
            let commitment = note.commitment().map_err(|_| WalletBuildError::Crypto)?;
            let commitment_bytes = value_commitment_bytes(*value, randomness);
            let commitment_point =
                Option::<pallas::Point>::from(pallas::Point::from_bytes(&commitment_bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
            output_notes.push(note);
            output_randomness.push(randomness);
            output_commitments.push(commitment_point);
            outputs.push(PublicOutput {
                commitment,
                value_commitment: commitment_bytes,
                ephemeral_key: [0; 32],
                ciphertext: vec![],
                outgoing_ciphertext: vec![],
            });
        }

        let mut selected_indices = token_indices.clone();
        selected_indices.extend(&native_indices);
        let mut selected = token_inputs.clone();
        selected.extend(&native_inputs);
        if selected
            .iter()
            .any(|note| note.plaintext.network_id != self.network_id)
        {
            return Err(WalletBuildError::InvalidRecipient);
        }
        let input_randomness = selected
            .iter()
            .map(|note| note.plaintext.randomness.field())
            .collect::<Vec<_>>();
        let input_commitments = selected
            .iter()
            .zip(&input_randomness)
            .map(|(note, randomness)| {
                let bytes = value_commitment_bytes(note.plaintext.value, *randomness);
                let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                Ok((bytes, point))
            })
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let nullifiers = selected
            .iter()
            .map(|note| {
                note.plaintext
                    .nullifier(keys.nullifier_key(), note.position)
            })
            .collect::<Vec<_>>();
        let function_id =
            mixed_transfer_function_id(token_inputs.len(), token_output_count, native_inputs.len())
                .ok_or(WalletBuildError::Crypto)?;
        let mut preimage = TransactionPreimage {
            network_id: self.network_id,
            anchor: self.root(),
            expiry_height,
            fee,
            spends: nullifiers
                .iter()
                .zip(&input_commitments)
                .map(|(nullifier, (value_commitment, _))| PublicSpend {
                    nullifier: *nullifier,
                    value_commitment: *value_commitment,
                    randomized_key: [0; 32],
                })
                .collect(),
            outputs,
            programs: vec![ProgramCall {
                program_id,
                function_id,
                public_data_hash: mixed_transfer_public_data_hash(),
            }],
        };
        let prepared =
            prepare_same_owner_spends(keys, &mut preimage).map_err(|_| WalletBuildError::Crypto)?;
        let binding = preimage
            .encryption_binding()
            .map_err(|_| WalletBuildError::Crypto)?;
        for (index, (note, spec)) in output_notes.iter().zip(&output_specs).enumerate() {
            let encrypted = keys
                .encrypt_note(note, &spec.0, binding, index as u32)
                .map_err(|_| WalletBuildError::Crypto)?;
            preimage.outputs[index].ephemeral_key = encrypted.ephemeral_key;
            preimage.outputs[index].ciphertext = encrypted.ciphertext;
            preimage.outputs[index].outgoing_ciphertext = encrypted.outgoing_ciphertext;
        }
        let spends = selected
            .iter()
            .zip(&selected_indices)
            .zip(&input_randomness)
            .zip(&input_commitments)
            .enumerate()
            .map(
                |(spend_index, (((input, note_index), randomness), (_, commitment)))| {
                    let path = self
                        .witness(*note_index)
                        .map_err(|_| WalletBuildError::Crypto)?;
                    let authority = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &input.plaintext.spend_authority_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &preimage.spends[spend_index].randomized_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    Ok(MultiSpendWitness {
                        commitment: input.commitment.field(),
                        input_note: input
                            .plaintext
                            .commitment_inputs()
                            .map_err(|_| WalletBuildError::Crypto)?,
                        authority_key: authority,
                        authorization_randomizer: prepared.randomizers()[spend_index],
                        randomized_key,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|sibling| sibling.field())
                            .collect(),
                        position: path.position,
                        nullifier_key: keys.nullifier_key().field(),
                        rho: input.plaintext.rho.field(),
                        value_randomness: *randomness,
                        value_commitment: *commitment,
                    })
                },
            )
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let token_spend_count = token_inputs.len();
        let witness = MixedTokenWitness {
            token: MultiTransferWitness::<DEPTH> {
                input_values: token_inputs
                    .iter()
                    .map(|note| note.plaintext.value)
                    .collect(),
                output_values: output_specs[..token_output_count]
                    .iter()
                    .map(|spec| spec.1)
                    .collect(),
                spends: spends[..token_spend_count].to_vec(),
                output_notes: output_notes[..token_output_count]
                    .iter()
                    .map(|note| {
                        note.commitment_inputs()
                            .map_err(|_| WalletBuildError::Crypto)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                output_value_randomness: output_randomness[..token_output_count].to_vec(),
                output_value_commitments: output_commitments[..token_output_count].to_vec(),
            },
            native: MultiTransferWitness::<DEPTH> {
                input_values: native_inputs
                    .iter()
                    .map(|note| note.plaintext.value)
                    .collect(),
                output_values: vec![native_change],
                spends: spends[token_spend_count..].to_vec(),
                output_notes: vec![output_notes[token_output_count]
                    .commitment_inputs()
                    .map_err(|_| WalletBuildError::Crypto)?],
                output_value_randomness: vec![output_randomness[token_output_count]],
                output_value_commitments: vec![output_commitments[token_output_count]],
            },
        };
        let nullifier_bytes = nullifiers
            .iter()
            .map(|nullifier| nullifier.0)
            .collect::<Vec<_>>();
        macro_rules! prove {
            ($ts:literal, $to:literal, $ns:literal) => {
                create_mixed_token_transfer_proof::<DEPTH, $ts, $to, $ns>(
                    circuit_k,
                    &witness,
                    fee,
                    self.root(),
                    &nullifier_bytes,
                    self.network_id,
                    program_id,
                    function_id,
                )
            };
        }
        let proof = match (token_spend_count, token_output_count, native_inputs.len()) {
            (1, 1, 1) => prove!(1, 1, 1),
            (1, 1, 2) => prove!(1, 1, 2),
            (1, 2, 1) => prove!(1, 2, 1),
            (1, 2, 2) => prove!(1, 2, 2),
            (2, 1, 1) => prove!(2, 1, 1),
            (2, 1, 2) => prove!(2, 1, 2),
            (2, 2, 1) => prove!(2, 2, 1),
            (2, 2, 2) => prove!(2, 2, 2),
            _ => return Err(WalletBuildError::Crypto),
        }
        .map_err(|_| WalletBuildError::Crypto)?;
        let spend_signatures =
            sign_prepared_spends(&prepared, &preimage, TOKEN_PROGRAM_BACKEND, &proof)
                .map_err(|_| WalletBuildError::Crypto)?;
        let binding_signature = sign_binding_authorization(
            &preimage,
            TOKEN_PROGRAM_BACKEND,
            &proof,
            &input_randomness,
            &output_randomness,
        )
        .map_err(|_| WalletBuildError::Crypto)?;
        Ok(AuthorizedTransaction {
            preimage,
            backend_id: TOKEN_PROGRAM_BACKEND.to_owned(),
            proof,
            spend_signatures,
            binding_signature,
        })
    }

    pub fn encode_snapshot(&self) -> Result<Vec<u8>, WalletError> {
        let mut out = Vec::new();
        out.push(WALLET_SNAPSHOT_VERSION);
        out.push(DEPTH as u8);
        out.extend_from_slice(&self.network_id);
        write_varint(self.tree.leaf_count(), &mut out);
        for commitment in self.tree.commitments() {
            out.extend_from_slice(&commitment.bytes());
        }
        write_varint(self.notes.len() as u64, &mut out);
        for note in &self.notes {
            out.extend_from_slice(&note.commitment.bytes());
            write_varint(note.position, &mut out);
            out.push(u8::from(note.spent));
            let plaintext = note.plaintext.encode().map_err(WalletError::Note)?;
            write_varint(plaintext.len() as u64, &mut out);
            out.extend_from_slice(&plaintext);
        }
        let programs = self.programs.encode();
        write_varint(programs.len() as u64, &mut out);
        out.extend_from_slice(&programs);
        write_varint(self.issuance.len() as u64, &mut out);
        for (program_id, issuance) in &self.issuance {
            out.extend_from_slice(program_id);
            write_varint(issuance.issued_supply, &mut out);
            write_varint(issuance.next_sequence, &mut out);
        }
        Ok(out)
    }

    pub fn decode_snapshot(input: &[u8]) -> Result<Self, WalletError> {
        let mut reader = Reader::new(input);
        let version = reader.byte().map_err(WalletError::Note)?;
        if (version != WALLET_SNAPSHOT_VERSION && version != LEGACY_WALLET_SNAPSHOT_VERSION)
            || usize::from(reader.byte().map_err(WalletError::Note)?) != DEPTH
        {
            return Err(WalletError::Snapshot);
        }
        let network_id = reader.array().map_err(WalletError::Note)?;
        let leaf_count = bounded_count(
            reader.varint().map_err(WalletError::Note)?,
            MAX_WALLET_LEAVES,
        )?;
        let mut tree = WitnessTree::<DEPTH>::default();
        for _ in 0..leaf_count {
            tree.append(reader.field().map_err(WalletError::Note)?)?;
        }
        let note_count = bounded_count(
            reader.varint().map_err(WalletError::Note)?,
            MAX_WALLET_NOTES,
        )?;
        let mut notes = Vec::with_capacity(note_count);
        let mut positions = std::collections::HashSet::with_capacity(note_count);
        for _ in 0..note_count {
            let commitment = reader.field().map_err(WalletError::Note)?;
            let position = reader.varint().map_err(WalletError::Note)?;
            let spent = match reader.byte().map_err(WalletError::Note)? {
                0 => false,
                1 => true,
                _ => return Err(WalletError::Snapshot),
            };
            let plaintext_len = bounded_count(
                reader.varint().map_err(WalletError::Note)?,
                crate::types::MAX_MEMO_BYTES + 256,
            )?;
            let plaintext =
                NotePlaintext::decode(reader.take(plaintext_len).map_err(WalletError::Note)?)
                    .map_err(WalletError::Note)?;
            if position >= tree.leaf_count()
                || !positions.insert(position)
                || tree.commitments()[position as usize] != commitment
                || plaintext.network_id != network_id
                || plaintext.commitment().map_err(WalletError::Note)? != commitment
            {
                return Err(WalletError::Snapshot);
            }
            notes.push(WalletNote {
                commitment,
                position,
                plaintext,
                spent,
            });
        }
        let (programs, issuance) = if version == WALLET_SNAPSHOT_VERSION {
            let registry_len = bounded_count(
                reader.varint().map_err(WalletError::Note)?,
                crate::program::MAX_REGISTRY_BYTES,
            )?;
            let programs =
                ProgramRegistry::decode(reader.take(registry_len).map_err(WalletError::Note)?)
                    .map_err(|_| WalletError::Snapshot)?;
            let issuance_count = bounded_count(
                reader.varint().map_err(WalletError::Note)?,
                crate::program::MAX_REGISTERED_PROGRAMS,
            )?;
            let mut issuance = BTreeMap::new();
            let mut previous = None;
            for _ in 0..issuance_count {
                let program_id: [u8; 32] = reader.array().map_err(WalletError::Note)?;
                if previous.is_some_and(|id| id >= program_id) {
                    return Err(WalletError::Snapshot);
                }
                previous = Some(program_id);
                let issued_supply = reader.varint().map_err(WalletError::Note)?;
                let next_sequence = reader.varint().map_err(WalletError::Note)?;
                let entry = programs.get(&program_id).ok_or(WalletError::Snapshot)?;
                let (_, _, policy) =
                    issuance_policy_from_entry(entry).map_err(|_| WalletError::Snapshot)?;
                if issued_supply == 0 || issued_supply > policy.max_supply || next_sequence == 0 {
                    return Err(WalletError::Snapshot);
                }
                issuance.insert(
                    program_id,
                    WalletTokenIssuanceState {
                        issued_supply,
                        next_sequence,
                    },
                );
            }
            (programs, issuance)
        } else {
            (ProgramRegistry::default(), BTreeMap::new())
        };
        if !reader.is_empty() {
            return Err(WalletError::Snapshot);
        }
        Ok(Self {
            network_id,
            tree,
            notes,
            programs,
            issuance,
        })
    }

    pub fn scan_transfer(
        &mut self,
        keys: &FullViewingKey,
        transaction: &AuthorizedTransaction,
    ) -> Result<(), WalletError> {
        if transaction.preimage.network_id != self.network_id {
            return Err(WalletError::WrongNetwork);
        }
        let binding = transaction
            .preimage
            .encryption_binding()
            .map_err(|_| WalletError::Transaction)?;
        self.scan_outputs(keys, &transaction.preimage.outputs, binding)?;
        self.reserve_transfer_spends(keys, transaction)
    }

    pub fn reserve_transfer_spends(
        &mut self,
        keys: &FullViewingKey,
        transaction: &AuthorizedTransaction,
    ) -> Result<(), WalletError> {
        if transaction.preimage.network_id != self.network_id {
            return Err(WalletError::WrongNetwork);
        }
        for note in &mut self.notes {
            if note.spent {
                continue;
            }
            let nullifier = note
                .plaintext
                .nullifier(keys.nullifier_key(), note.position);
            if transaction
                .preimage
                .spends
                .iter()
                .any(|spend| spend.nullifier == nullifier)
            {
                note.spent = true;
            }
        }
        Ok(())
    }

    pub fn scan_bridge(
        &mut self,
        keys: &FullViewingKey,
        bridge: &AuthorizedBridge,
    ) -> Result<(), WalletError> {
        if bridge.preimage.network_id != self.network_id {
            return Err(WalletError::WrongNetwork);
        }
        let binding = bridge
            .preimage
            .encryption_binding()
            .map_err(|_| WalletError::Transaction)?;
        self.scan_outputs(keys, std::slice::from_ref(&bridge.preimage.output), binding)
    }

    fn scan_outputs(
        &mut self,
        keys: &FullViewingKey,
        outputs: &[PublicOutput],
        binding: [u8; 32],
    ) -> Result<(), WalletError> {
        for (index, output) in outputs.iter().enumerate() {
            let position = self.tree.append(output.commitment)?;
            let encrypted = EncryptedNote {
                ephemeral_key: output.ephemeral_key,
                ciphertext: output.ciphertext.clone(),
                outgoing_ciphertext: output.outgoing_ciphertext.clone(),
            };
            if let Ok(plaintext) =
                keys.decrypt_received_note(&encrypted, output.commitment, binding, index as u32)
            {
                self.notes.push(WalletNote {
                    commitment: output.commitment,
                    position,
                    plaintext,
                    spent: false,
                });
            }
        }
        Ok(())
    }
}

fn bounded_count(value: u64, maximum: usize) -> Result<usize, WalletError> {
    if value > maximum as u64 {
        Err(WalletError::Snapshot)
    } else {
        Ok(value as usize)
    }
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::pasta::Fp;

    use crate::keys::{encrypt_note_with_ephemeral, MasterSeed};
    use crate::state::Nullifier;
    use crate::transaction::{PublicSpend, TransactionPreimage};
    use crate::types::{NotePlaintext, NATIVE_ASSET_ID, NETWORK_ID_BYTES};
    use crate::value_commitment_circuit::value_commitment_bytes;

    use super::*;

    fn funded_wallet<const DEPTH: usize>(
        keys: &KeyBundle,
        network: [u8; NETWORK_ID_BYTES],
        values: &[u64],
    ) -> WalletState<DEPTH> {
        let address = keys.address(0).unwrap();
        let mut wallet = WalletState::<DEPTH>::new(network);
        for (index, value) in values.iter().enumerate() {
            let note = NotePlaintext {
                network_id: network,
                program_id: [0; 32],
                asset_id: NATIVE_ASSET_ID,
                value: *value,
                diversifier: address.diversifier,
                transmission_key: address.transmission_key,
                spend_authority_key: address.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from(100 + index as u64)),
                randomness: CanonicalField::from_field(Fp::from(200 + index as u64)),
                memo: vec![],
            };
            let commitment = note.commitment().unwrap();
            let position = wallet.tree.append(commitment).unwrap();
            wallet.notes.push(WalletNote {
                commitment,
                position,
                plaintext: note,
                spent: false,
            });
        }
        wallet
    }

    fn funded_mixed_wallet<const DEPTH: usize>(
        keys: &KeyBundle,
        network: [u8; NETWORK_ID_BYTES],
        program_id: [u8; 32],
        native_values: &[u64],
        token_values: &[u64],
    ) -> WalletState<DEPTH> {
        let address = keys.address(0).unwrap();
        let mut wallet = WalletState::<DEPTH>::new(network);
        for (index, (program, asset, value)) in native_values
            .iter()
            .map(|value| ([0; 32], NATIVE_ASSET_ID, *value))
            .chain(
                token_values
                    .iter()
                    .map(|value| (program_id, program_id, *value)),
            )
            .enumerate()
        {
            let note = NotePlaintext {
                network_id: network,
                program_id: program,
                asset_id: asset,
                value,
                diversifier: address.diversifier,
                transmission_key: address.transmission_key,
                spend_authority_key: address.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from(500 + index as u64)),
                randomness: CanonicalField::from_field(Fp::from(600 + index as u64)),
                memo: vec![],
            };
            let commitment = note.commitment().unwrap();
            let position = wallet.tree.append(commitment).unwrap();
            wallet.notes.push(WalletNote {
                commitment,
                position,
                plaintext: note,
                spent: false,
            });
        }
        wallet
    }

    #[test]
    fn cpp_standard_program_wallet_fixture_stays_stable() {
        const DEPTH: usize = 32;
        let network = [17; NETWORK_ID_BYTES];
        let keys = MasterSeed::new([44; 32]).derive(network).unwrap();
        let mut wallet = funded_wallet::<DEPTH>(
            &keys,
            network,
            &[1, crate::program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE + 1],
        );
        let entry = standard_program_entry(StandardProgramKind::Nft, 10, None).unwrap();
        wallet.register_program(entry).unwrap();
        let snapshot = wallet.encode_snapshot().unwrap();
        let encoded = snapshot
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            encoded,
            include_str!("../../../tests/zk/standard_program_wallet_fixture.inc")
                .trim()
                .trim_matches('"'),
            "update the C++ fixture only after reviewing wallet snapshot format drift"
        );
        let poseidon = |left, right| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
        };
        let identity = poseidon(
            poseidon(Fp::from(21), Fp::zero()),
            poseidon(Fp::from(22), Fp::zero()),
        );
        let instance = poseidon(identity, Fp::from(33));
        assert_eq!(
            poseidon(Fp::from(34), instance)
                .to_repr()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "dea354729d447a92315a7730a8ffa9c2621f025a2e73cf2c794b7923939f1a00",
            "update the C++ NFT witness fixture only after reviewing primitive drift"
        );
    }

    #[test]
    fn builder_combines_two_notes_for_exact_and_change_payments() {
        const DEPTH: usize = 2;
        const K: u32 = 16;
        let network = [8; NETWORK_ID_BYTES];
        let sender = MasterSeed::new([21; 32]).derive(network).unwrap();
        let recipient_keys = MasterSeed::new([22; 32]).derive(network).unwrap();
        let recipient = recipient_keys.address(0).unwrap();

        let exact_wallet = funded_wallet::<DEPTH>(&sender, network, &[10, 12]);
        let exact = exact_wallet
            .build_transfer(&sender, &recipient, 20, 2, 50, vec![], K)
            .unwrap();
        assert_eq!(
            (exact.preimage.spends.len(), exact.preimage.outputs.len()),
            (2, 1)
        );
        crate::proof::verify_authorized_multi_transfer::<DEPTH, 2, 1>(K, &exact).unwrap();

        let change_wallet = funded_wallet::<DEPTH>(&sender, network, &[10, 15]);
        let change = change_wallet
            .build_transfer(&sender, &recipient, 20, 2, 50, vec![], K)
            .unwrap();
        assert_eq!(
            (change.preimage.spends.len(), change.preimage.outputs.len()),
            (2, 2)
        );
        crate::proof::verify_authorized_multi_transfer::<DEPTH, 2, 2>(K, &change).unwrap();

        let mut recipient_wallet = WalletState::<DEPTH>::new(network);
        recipient_wallet
            .scan_transfer(&recipient_keys.full_viewing_key().unwrap(), &change)
            .unwrap();
        assert_eq!(recipient_wallet.unspent_balance().unwrap(), 20);
        let mut sender_wallet = WalletState::<DEPTH>::new(network);
        sender_wallet
            .scan_transfer(&sender.full_viewing_key().unwrap(), &change)
            .unwrap();
        assert_eq!(sender_wallet.unspent_balance().unwrap(), 3);
    }

    #[cfg(feature = "qualification-fixtures")]
    #[test]
    fn invalid_proof_fixture_preserves_authorization_but_fails_halo2() {
        const DEPTH: usize = 2;
        const K: u32 = 16;
        let network = [31; NETWORK_ID_BYTES];
        let sender = MasterSeed::new([71; 32]).derive(network).unwrap();
        let recipient = MasterSeed::new([72; 32])
            .derive(network)
            .unwrap()
            .address(0)
            .unwrap();
        let wallet = funded_wallet::<DEPTH>(&sender, network, &[25]);
        let transaction = wallet
            .build_authenticated_invalid_proof_transfer(
                &sender,
                &recipient,
                20,
                2,
                50,
                b"qualification only".to_vec(),
                K,
            )
            .unwrap();

        crate::authorization::verify_authorized_transaction(&transaction).unwrap();
        assert!(
            crate::proof::verify_authorized_multi_transfer::<DEPTH, 1, 2>(K, &transaction).is_err()
        );
    }

    #[test]
    fn program_deployment_builder_binds_manifest_call_and_fee() {
        const DEPTH: usize = 2;
        const FUNDING_K: u32 = 10;
        const PROGRAM_K: u32 = 14;
        let network = [19; NETWORK_ID_BYTES];
        let sender = MasterSeed::new([41; 32]).derive(network).unwrap();
        let wallet = funded_wallet::<DEPTH>(
            &sender,
            network,
            &[crate::program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE + 1],
        );
        let deployment = wallet
            .build_program_deployment(
                &sender,
                b"onyx.standard.private-fungible-token/v1".to_vec(),
                10,
                Some(100),
                20,
                crate::program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE,
                PROGRAM_K,
                FUNDING_K,
            )
            .unwrap();
        assert_eq!(deployment.funding.preimage.programs.len(), 1);
        assert_eq!(
            deployment.funding.preimage.programs[0].public_data_hash,
            deployment.deployment_hash()
        );
        let entry = crate::program_deployment::verify_standard_deployment::<DEPTH, 1, 1>(
            FUNDING_K,
            PROGRAM_K,
            &deployment,
            9,
        )
        .unwrap();
        assert!(
            crate::program_deployment::verify_standard_deployment::<DEPTH, 1, 1>(
                FUNDING_K,
                FUNDING_K,
                &deployment,
                9,
            )
            .is_err()
        );
        assert_eq!(
            entry.id().unwrap(),
            deployment.funding.preimage.programs[0].program_id
        );
        let mut reserved = wallet.clone();
        let sender_view = sender.full_viewing_key().unwrap();
        reserved
            .reserve_transfer_spends(&sender_view, &deployment.funding)
            .unwrap();
        assert!(matches!(
            reserved.build_program_deployment(
                &sender,
                b"onyx.standard.private-fungible-token/v1".to_vec(),
                10,
                Some(100),
                20,
                crate::program_deployment::MIN_PROGRAM_DEPLOYMENT_FEE,
                PROGRAM_K,
                FUNDING_K,
            ),
            Err(WalletBuildError::InsufficientFunds)
        ));
        let mut tracked = wallet.clone();
        tracked
            .record_program_deployment(&deployment, 9, PROGRAM_K)
            .unwrap();
        let restored =
            WalletState::<DEPTH>::decode_snapshot(&tracked.encode_snapshot().unwrap()).unwrap();
        assert!(restored
            .program_registry()
            .get(&deployment.funding.preimage.programs[0].program_id)
            .is_some());
        assert_eq!(
            AuthorizedProgramDeployment::decode(&deployment.encode().unwrap()).unwrap(),
            deployment
        );
    }

    #[test]
    fn standard_program_call_builder_composes_base_and_nft_proofs() {
        const DEPTH: usize = 2;
        let network = [17; NETWORK_ID_BYTES];
        let keys = MasterSeed::new([44; 32]).derive(network).unwrap();
        let mut wallet = funded_wallet::<DEPTH>(&keys, network, &[1]);
        let entry = standard_program_entry(StandardProgramKind::Nft, 10, None).unwrap();
        let program_id = entry.id().unwrap();
        wallet.register_program(entry.clone()).unwrap();

        let collection_id = Fp::from(21).to_repr();
        let token_id = Fp::from(22).to_repr();
        let serial = Fp::from(33);
        let owner_secret = Fp::from(34);
        let poseidon = |left, right| {
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([left, right])
        };
        let collection = poseidon(Fp::from(21), Fp::zero());
        let token = poseidon(Fp::from(22), Fp::zero());
        let identity = poseidon(collection, token);
        let instance = poseidon(identity, serial);
        let prior = CanonicalField::from_field(poseidon(owner_secret, instance));
        let next = CanonicalField::from_field(Fp::from(901));
        let application = StandardApplication::Nft {
            collection_id,
            token_id,
            serial: 33,
            transfer_nonce: 1,
        };
        assert!(wallet
            .build_standard_program_call(
                &keys,
                program_id,
                10,
                20,
                application.clone(),
                prior,
                next,
                vec![],
                STANDARD_CIRCUIT_K,
            )
            .is_err());
        let envelope = wallet
            .build_standard_program_call(
                &keys,
                program_id,
                10,
                20,
                application,
                prior,
                next,
                vec![CanonicalField::from_field(owner_secret)],
                STANDARD_CIRCUIT_K,
            )
            .unwrap();
        envelope
            .verify_standard(
                wallet.program_registry(),
                10,
                DEPTH as u32,
                STANDARD_CIRCUIT_K,
            )
            .unwrap();
        assert_eq!(
            envelope.contexts[0].state.as_ref().unwrap().prior,
            prior.bytes()
        );
        assert_eq!(
            ContextualAuthorizedTransaction::decode(&envelope.encode().unwrap()).unwrap(),
            envelope
        );

        // The admission precheck authenticates and inspects state without verifying either Halo2
        // proof. A fresh transaction is eligible, while replaying it after state application is a
        // cheap conflict. Full proof verification above remains the acceptance gate.
        let public_output = |note: &WalletNote| crate::transaction::PublicOutput {
            commitment: note.commitment,
            value_commitment: value_commitment_bytes(
                note.plaintext.value,
                note.plaintext.randomness.field(),
            ),
            ephemeral_key: [1; 32],
            ciphertext: vec![2],
            outgoing_ciphertext: vec![3],
        };
        let mut consensus = crate::state::ShieldedState::<DEPTH>::new(10);
        consensus.register_program(entry).unwrap();
        let setup = TransactionPreimage {
            network_id: network,
            anchor: consensus.root(),
            expiry_height: 50,
            fee: 0,
            spends: vec![],
            outputs: vec![public_output(&wallet.notes()[0])],
            programs: vec![],
        };
        consensus.apply_bridge(&setup, [1; 32], 1, 0, 0).unwrap();
        assert_eq!(consensus.root(), wallet.root());

        let encoded = envelope.encode().unwrap();
        let fresh_snapshot = consensus.encode_snapshot();
        assert_eq!(
            crate::precheck_authenticated_standard_program_state::<DEPTH>(
                &fresh_snapshot,
                &envelope
            ),
            Ok(true)
        );
        assert_eq!(
            crate::onyx_precheck_authenticated_standard_program_state(
                fresh_snapshot.as_ptr(),
                fresh_snapshot.len(),
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
            ),
            1
        );
        assert_eq!(
            crate::onyx_precheck_authenticated_standard_program_state(
                fresh_snapshot.as_ptr(),
                fresh_snapshot.len(),
                encoded.as_ptr(),
                encoded.len(),
                3,
            ),
            -3
        );

        consensus
            .apply_contextual_transaction(&envelope.transaction.preimage, 10, &envelope.contexts)
            .unwrap();
        let applied_snapshot = consensus.encode_snapshot();
        assert_eq!(
            crate::precheck_authenticated_standard_program_state::<DEPTH>(
                &applied_snapshot,
                &envelope
            ),
            Ok(false)
        );
        assert_eq!(
            crate::onyx_precheck_authenticated_standard_program_state(
                applied_snapshot.as_ptr(),
                applied_snapshot.len(),
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
            ),
            0
        );
    }

    #[test]
    fn mixed_token_builder_conserves_each_asset_and_pays_native_fee() {
        const DEPTH: usize = 4;
        const K: u32 = 14;
        const NATIVE_K: u32 = 13;
        let network = [18; NETWORK_ID_BYTES];
        let sender = MasterSeed::new([31; 32]).derive(network).unwrap();
        let recipient_keys = MasterSeed::new([32; 32]).derive(network).unwrap();
        let recipient = recipient_keys.address(0).unwrap();
        let entry =
            crate::token_program::standard_token_program::<DEPTH>(K, b"MIXED/TEST", 1, None)
                .unwrap();
        let program_id = entry.id().unwrap();
        let mut registry = crate::program::ProgramRegistry::default();
        registry.register(entry.clone()).unwrap();
        let wallet = funded_mixed_wallet::<DEPTH>(&sender, network, program_id, &[5], &[30]);
        assert_eq!(wallet.unspent_balance().unwrap(), 5);
        assert_eq!(
            wallet
                .unspent_asset_balance(&program_id, &program_id)
                .unwrap(),
            30
        );
        let transaction = wallet
            .build_mixed_token_transfer(
                &sender,
                &recipient,
                program_id,
                20,
                2,
                50,
                b"mixed payment".to_vec(),
                K,
            )
            .unwrap();
        assert_eq!(
            (
                transaction.preimage.spends.len(),
                transaction.preimage.outputs.len(),
                transaction.preimage.fee,
            ),
            (2, 3, 2)
        );
        crate::proof::verify_authorized_mixed_token_transfer::<DEPTH, 1, 2, 1>(
            K,
            &transaction,
            Some(&registry),
            1,
        )
        .unwrap();
        let public_output = |note: &WalletNote| PublicOutput {
            commitment: note.commitment,
            value_commitment: value_commitment_bytes(
                note.plaintext.value,
                note.plaintext.randomness.field(),
            ),
            ephemeral_key: [1; 32],
            ciphertext: vec![2],
            outgoing_ciphertext: vec![3],
        };
        let mut consensus = crate::state::ShieldedState::<DEPTH>::new(10);
        consensus.register_program(entry).unwrap();
        let native_setup = TransactionPreimage {
            network_id: network,
            anchor: consensus.root(),
            expiry_height: 50,
            fee: 0,
            spends: vec![],
            outputs: vec![public_output(&wallet.notes()[0])],
            programs: vec![],
        };
        consensus
            .apply_bridge(&native_setup, [1; 32], 5, 0, 0)
            .unwrap();
        let token_setup = TransactionPreimage {
            network_id: network,
            anchor: consensus.root(),
            expiry_height: 50,
            fee: 0,
            spends: vec![],
            outputs: vec![public_output(&wallet.notes()[1])],
            programs: vec![],
        };
        consensus.apply_transaction(&token_setup, 0).unwrap();
        assert_eq!(consensus.root(), wallet.root());
        let snapshot = consensus.encode_snapshot();
        let mut direct = crate::state::ShieldedState::<DEPTH>::decode_snapshot(&snapshot).unwrap();
        assert!(direct.knows_anchor(transaction.preimage.anchor));
        direct.apply_transfer(&transaction.preimage, 1).unwrap();
        let encoded = transaction.encode().unwrap();
        let mut next_ptr = std::ptr::null_mut();
        let mut next_len = 0usize;
        let mut extracted_fee = 0u64;
        assert_eq!(
            crate::onyx_verify_apply_transfer(
                snapshot.as_ptr(),
                snapshot.len(),
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                NATIVE_K,
                K,
                network.as_ptr(),
                1,
                &mut next_ptr,
                &mut next_len,
                &mut extracted_fee,
            ),
            1
        );
        let next_snapshot = unsafe { std::slice::from_raw_parts(next_ptr, next_len) }.to_vec();
        crate::onyx_free(next_ptr, next_len);
        let applied =
            crate::state::ShieldedState::<DEPTH>::decode_snapshot(&next_snapshot).unwrap();
        assert_eq!(extracted_fee, 2);
        assert_eq!((applied.total_fees(), applied.circulating_supply()), (2, 3));
        assert!(transaction
            .preimage
            .spends
            .iter()
            .all(|spend| applied.is_spent(&spend.nullifier)));
        let mut wrong_fee = transaction.clone();
        wrong_fee.preimage.fee = 1;
        assert!(
            crate::proof::verify_authorized_mixed_token_transfer::<DEPTH, 1, 2, 1>(
                K, &wrong_fee, None, 0,
            )
            .is_err()
        );

        let mut recipient_wallet = WalletState::<DEPTH>::new(network);
        recipient_wallet
            .scan_transfer(&recipient_keys.full_viewing_key().unwrap(), &transaction)
            .unwrap();
        assert_eq!(recipient_wallet.unspent_balance().unwrap(), 0);
        assert_eq!(
            recipient_wallet
                .unspent_asset_balance(&program_id, &program_id)
                .unwrap(),
            20
        );
        let mut sender_wallet = WalletState::<DEPTH>::new(network);
        sender_wallet
            .scan_transfer(&sender.full_viewing_key().unwrap(), &transaction)
            .unwrap();
        assert_eq!(sender_wallet.unspent_balance().unwrap(), 3);
        assert_eq!(
            sender_wallet
                .unspent_asset_balance(&program_id, &program_id)
                .unwrap(),
            10
        );
    }

    #[test]
    fn selector_prefers_one_note_then_first_sufficient_pair() {
        let network = [7; NETWORK_ID_BYTES];
        let keys = MasterSeed::new([23; 32]).derive(network).unwrap();
        let wallet = funded_wallet::<2>(&keys, network, &[4, 4, 6, 12]);
        assert_eq!(select_note_indices(wallet.notes(), 10).unwrap(), vec![3]);
        assert_eq!(select_note_indices(wallet.notes(), 13).unwrap(), vec![0, 3]);

        let pair_wallet = funded_wallet::<2>(&keys, network, &[4, 4, 6]);
        assert_eq!(
            select_note_indices(pair_wallet.notes(), 10).unwrap(),
            vec![0, 2]
        );
        assert!(matches!(
            select_note_indices(pair_wallet.notes(), 11),
            Err(WalletBuildError::InsufficientFunds)
        ));
    }

    #[test]
    fn scanner_tracks_all_leaves_recovers_notes_witnesses_and_spends() {
        let network = [9; NETWORK_ID_BYTES];
        let receiver = MasterSeed::new([2; 32]).derive(network).unwrap();
        let sender = MasterSeed::new([3; 32]).derive(network).unwrap();
        let receiver_view = receiver.full_viewing_key().unwrap();
        let sender_view = sender.full_viewing_key().unwrap();
        let address = receiver.address(0).unwrap();
        let note = NotePlaintext {
            network_id: network,
            program_id: [0; 32],
            asset_id: NATIVE_ASSET_ID,
            value: 25,
            diversifier: address.diversifier,
            transmission_key: address.transmission_key,
            spend_authority_key: address.spend_authority_key,
            rho: CanonicalField::from_field(Fp::from(6)),
            randomness: CanonicalField::from_field(Fp::from(7)),
            memo: b"wallet scan".to_vec(),
        };
        let commitment = note.commitment().unwrap();
        let mut output = PublicOutput {
            commitment,
            value_commitment: value_commitment_bytes(25, Fp::from(11)),
            ephemeral_key: [0; 32],
            ciphertext: vec![],
            outgoing_ciphertext: vec![],
        };
        let preimage = TransactionPreimage {
            network_id: network,
            anchor: CanonicalField::from_field(Fp::from(12)),
            expiry_height: 100,
            fee: 5,
            spends: vec![],
            outputs: vec![output.clone()],
            programs: vec![],
        };
        let binding = preimage.encryption_binding().unwrap();
        let encrypted = encrypt_note_with_ephemeral(
            &note,
            &address,
            &sender.outgoing_viewing_key(),
            [4; 32],
            binding,
            0,
        )
        .unwrap();
        output.ephemeral_key = encrypted.ephemeral_key;
        output.ciphertext = encrypted.ciphertext;
        output.outgoing_ciphertext = encrypted.outgoing_ciphertext;
        let transaction = AuthorizedTransaction {
            preimage: TransactionPreimage {
                outputs: vec![output],
                ..preimage
            },
            backend_id: "test".to_owned(),
            proof: vec![],
            spend_signatures: vec![],
            binding_signature: [0; 64],
        };

        let mut wallet = WalletState::<8>::new(network);
        wallet.scan_transfer(&receiver_view, &transaction).unwrap();
        assert_eq!(wallet.leaf_count(), 1);
        assert_eq!(wallet.notes().len(), 1);
        assert_eq!(wallet.notes()[0].plaintext, note);
        assert!(wallet
            .witness(0)
            .unwrap()
            .verify::<8>(commitment, wallet.root())
            .unwrap());
        let snapshot = wallet.encode_snapshot().unwrap();
        let restored = WalletState::<8>::decode_snapshot(&snapshot).unwrap();
        assert_eq!(restored.root(), wallet.root());
        assert_eq!(restored.notes(), wallet.notes());
        let mut trailing = snapshot.clone();
        trailing.push(0);
        assert_eq!(
            WalletState::<8>::decode_snapshot(&trailing).err(),
            Some(WalletError::Snapshot)
        );

        let mut address_bytes = [0u8; 91];
        assert_eq!(
            crate::onyx_wallet_address(
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                address_bytes.as_mut_ptr(),
            ),
            0
        );
        assert_eq!(&address_bytes[..16], &network);
        let encoded_transaction = transaction.encode().unwrap();
        let mut ffi_snapshot_ptr = std::ptr::null_mut();
        let mut ffi_snapshot_len = 0usize;
        let mut ffi_balance = 0u64;
        let mut ffi_note_count = 0usize;
        let mut ffi_root = [0u8; 32];
        assert_eq!(
            crate::onyx_wallet_scan(
                std::ptr::null(),
                0,
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                1,
                20,
                20,
                encoded_transaction.as_ptr(),
                encoded_transaction.len(),
                &mut ffi_snapshot_ptr,
                &mut ffi_snapshot_len,
                &mut ffi_balance,
                &mut ffi_note_count,
                ffi_root.as_mut_ptr(),
            ),
            1
        );
        assert_eq!((ffi_balance, ffi_note_count), (25, 1));
        assert!(!ffi_snapshot_ptr.is_null());
        crate::onyx_free(ffi_snapshot_ptr, ffi_snapshot_len);

        let mut viewing_bytes = [0u8; crate::keys::FULL_VIEWING_KEY_BYTES];
        assert_eq!(
            crate::onyx_full_viewing_key(
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                viewing_bytes.as_mut_ptr(),
            ),
            0
        );
        ffi_snapshot_ptr = std::ptr::null_mut();
        ffi_snapshot_len = 0;
        ffi_balance = 0;
        ffi_note_count = 0;
        assert_eq!(
            crate::onyx_wallet_scan_viewing(
                std::ptr::null(),
                0,
                viewing_bytes.as_ptr(),
                viewing_bytes.len(),
                0,
                1,
                20,
                20,
                encoded_transaction.as_ptr(),
                encoded_transaction.len(),
                &mut ffi_snapshot_ptr,
                &mut ffi_snapshot_len,
                &mut ffi_balance,
                &mut ffi_note_count,
                ffi_root.as_mut_ptr(),
            ),
            1
        );
        assert_eq!((ffi_balance, ffi_note_count), (25, 1));
        crate::onyx_free(ffi_snapshot_ptr, ffi_snapshot_len);

        let mut unsigned_bridge_ptr = std::ptr::null_mut();
        let mut unsigned_bridge_len = 0usize;
        let mut ownership_sighash = [0u8; 32];
        assert_eq!(
            crate::onyx_wallet_create_bridge(
                [3u8; 32].as_ptr(),
                address_bytes.as_ptr(),
                100,
                5,
                30,
                42,
                [7u8; 32].as_ptr(),
                b"bridge memo".as_ptr(),
                b"bridge memo".len(),
                13,
                &mut unsigned_bridge_ptr,
                &mut unsigned_bridge_len,
                ownership_sighash.as_mut_ptr(),
            ),
            1
        );
        let unsigned_bridge =
            unsafe { std::slice::from_raw_parts(unsigned_bridge_ptr, unsigned_bridge_len) }
                .to_vec();
        crate::onyx_free(unsigned_bridge_ptr, unsigned_bridge_len);
        let bridge = AuthorizedBridge::decode(&unsigned_bridge).unwrap();
        crate::proof::verify_bridge_proof(13, &bridge).unwrap();
        assert_eq!(ownership_sighash, bridge.ownership_sighash().unwrap());
        let mut finalized_ptr = std::ptr::null_mut();
        let mut finalized_len = 0usize;
        assert_eq!(
            crate::onyx_wallet_finalize_bridge(
                unsigned_bridge.as_ptr(),
                unsigned_bridge.len(),
                [9u8; 64].as_ptr(),
                &mut finalized_ptr,
                &mut finalized_len,
            ),
            1
        );
        let finalized =
            unsafe { std::slice::from_raw_parts(finalized_ptr, finalized_len) }.to_vec();
        crate::onyx_free(finalized_ptr, finalized_len);
        assert_eq!(
            AuthorizedBridge::decode(&finalized)
                .unwrap()
                .ownership_signature,
            [9; 64]
        );

        // The public wallet FFI is fixed to the consensus tree depth. Build the
        // transfer snapshot at that depth rather than reusing the compact
        // depth-8 unit-test wallet above.
        let mut transfer_wallet = WalletState::<32>::new(network);
        transfer_wallet
            .scan_transfer(&receiver_view, &transaction)
            .unwrap();
        let wallet_snapshot = transfer_wallet.encode_snapshot().unwrap();
        let mut recipient_bytes = [0u8; 91];
        assert_eq!(
            crate::onyx_wallet_address(
                [3u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                recipient_bytes.as_mut_ptr(),
            ),
            0
        );
        let mut payment_ptr = std::ptr::null_mut();
        let mut payment_len = 0usize;
        assert_eq!(
            crate::onyx_wallet_create_transfer(
                wallet_snapshot.as_ptr(),
                wallet_snapshot.len(),
                [2u8; 32].as_ptr(),
                recipient_bytes.as_ptr(),
                20,
                2,
                101,
                b"shielded payment".as_ptr(),
                b"shielded payment".len(),
                16,
                &mut payment_ptr,
                &mut payment_len,
            ),
            1
        );
        let payment_encoded =
            unsafe { std::slice::from_raw_parts(payment_ptr, payment_len) }.to_vec();
        crate::onyx_free(payment_ptr, payment_len);
        let payment = AuthorizedTransaction::decode(&payment_encoded).unwrap();
        assert_eq!(payment.preimage.outputs.len(), 2);
        crate::proof::verify_authorized_multi_transfer::<32, 1, 2>(16, &payment).unwrap();
        let mut reserved_ptr = std::ptr::null_mut();
        let mut reserved_len = 0usize;
        assert_eq!(
            crate::onyx_wallet_reserve_spends(
                wallet_snapshot.as_ptr(),
                wallet_snapshot.len(),
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                payment_encoded.as_ptr(),
                payment_encoded.len(),
                &mut reserved_ptr,
                &mut reserved_len,
            ),
            1
        );
        let reserved_snapshot =
            unsafe { std::slice::from_raw_parts(reserved_ptr, reserved_len) }.to_vec();
        crate::onyx_free(reserved_ptr, reserved_len);
        let reserved = WalletState::<32>::decode_snapshot(&reserved_snapshot).unwrap();
        assert_eq!(reserved.unspent_balance().unwrap(), 0);
        assert_eq!(reserved.leaf_count(), transfer_wallet.leaf_count());
        assert_eq!(reserved.root(), transfer_wallet.root());
        let mut recipient_wallet = WalletState::<8>::new(network);
        recipient_wallet
            .scan_transfer(&sender_view, &payment)
            .unwrap();
        assert_eq!(recipient_wallet.unspent_balance().unwrap(), 20);

        let mut foreign = WalletState::<8>::new(network);
        foreign.scan_transfer(&sender_view, &transaction).unwrap();
        assert_eq!(foreign.leaf_count(), 1);
        assert!(foreign.notes().is_empty());

        let nullifier = note.nullifier(receiver.nullifier_key(), 0);
        let spend = AuthorizedTransaction {
            preimage: TransactionPreimage {
                network_id: network,
                anchor: wallet.root(),
                expiry_height: 101,
                fee: 1,
                spends: vec![PublicSpend {
                    nullifier,
                    value_commitment: value_commitment_bytes(25, Fp::from(11)),
                    randomized_key: [0; 32],
                }],
                outputs: vec![],
                programs: vec![],
            },
            backend_id: "test".to_owned(),
            proof: vec![],
            spend_signatures: vec![[0; 64]],
            binding_signature: [0; 64],
        };
        wallet.scan_transfer(&receiver_view, &spend).unwrap();
        assert!(wallet.notes()[0].spent);
        assert_ne!(nullifier, Nullifier([0; 32]));
        let rolled_back = WalletState::<8>::decode_snapshot(&snapshot).unwrap();
        assert!(!rolled_back.notes()[0].spent);
        assert_eq!(rolled_back.root(), restored.root());
    }
}
