//! Canonical, fee-funded deployment envelope for audited standard Onyx programs.

use sha2::{Digest, Sha256};

use crate::authorization::{verify_authorized_transaction, AuthorizationError};
use crate::program::{ProgramEntry, ProgramError, MAX_MANIFEST_BYTES};
use crate::proof::{multi_transfer_backend_id, verify_multi_transfer_proof, ProofError};
use crate::standard_programs::{standard_artifact, standard_program_entry, StandardProgramKind};
use crate::token_program::{standard_token_program, TokenProgramError};
use crate::transaction::{read_bytes, write_bytes, AuthorizedTransaction, TransactionError};
use crate::types::{write_varint, DecodeError, Reader};

pub const PROGRAM_DEPLOYMENT_VERSION: u8 = 1;
pub const PROGRAM_DEPLOYMENT_FUNCTION_ID: u32 = u32::MAX;
pub const MIN_PROGRAM_DEPLOYMENT_FEE: u64 = 100_000;
pub const PROGRAM_DEPLOYMENT_COST: u64 = 5_000_000;
pub const MAX_PROGRAM_ACTIVATION_DELAY: u64 = 100_000;
// Must remain aligned with CryptoNoteConfig::ONYX_MAX_ENVELOPE_SIZE: the outer
// transaction rejects larger opaque envelopes before the Rust decoder runs.
pub const MAX_PROGRAM_DEPLOYMENT_BYTES: usize = 384 * 1024;
const DEPLOYMENT_HASH_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-deployment";
const DEPLOYMENT_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-deployment-id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedProgramDeployment {
    pub token_manifest: Vec<u8>,
    pub activation_height: u64,
    pub deactivation_height: Option<u64>,
    pub funding: AuthorizedTransaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramDeploymentError {
    Decode(DecodeError),
    Transaction(TransactionError),
    Authorization(AuthorizationError),
    Proof(ProofError),
    Program(TokenProgramError),
    Registry(ProgramError),
    InvalidManifest,
    InvalidActivation,
    InsufficientFee,
    InvalidCall,
    Oversized,
}

impl From<DecodeError> for ProgramDeploymentError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<TransactionError> for ProgramDeploymentError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}

impl From<AuthorizationError> for ProgramDeploymentError {
    fn from(value: AuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

impl From<ProofError> for ProgramDeploymentError {
    fn from(value: ProofError) -> Self {
        Self::Proof(value)
    }
}

impl From<TokenProgramError> for ProgramDeploymentError {
    fn from(value: TokenProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<ProgramError> for ProgramDeploymentError {
    fn from(value: ProgramError) -> Self {
        Self::Registry(value)
    }
}

impl AuthorizedProgramDeployment {
    fn validate_structure(&self) -> Result<(), ProgramDeploymentError> {
        if self.token_manifest.is_empty() || self.token_manifest.len() > MAX_MANIFEST_BYTES {
            return Err(ProgramDeploymentError::InvalidManifest);
        }
        if self
            .deactivation_height
            .is_some_and(|height| height <= self.activation_height || height == u64::MAX)
        {
            return Err(ProgramDeploymentError::InvalidActivation);
        }
        if self.funding.preimage.fee < MIN_PROGRAM_DEPLOYMENT_FEE {
            return Err(ProgramDeploymentError::InsufficientFee);
        }
        if self.funding.preimage.programs.len() != 1
            || self.funding.preimage.programs[0].function_id != PROGRAM_DEPLOYMENT_FUNCTION_ID
            || self.funding.preimage.programs[0].public_data_hash != self.deployment_hash()
        {
            return Err(ProgramDeploymentError::InvalidCall);
        }
        self.funding.encode()?;
        Ok(())
    }

    pub fn deployment_hash(&self) -> [u8; 32] {
        deployment_hash(
            self.funding.preimage.network_id,
            &self.token_manifest,
            self.activation_height,
            self.deactivation_height,
        )
    }

    pub fn id(&self) -> Result<[u8; 32], ProgramDeploymentError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(DEPLOYMENT_ID_DOMAIN);
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

pub fn deployment_hash(
    network_id: [u8; 16],
    token_manifest: &[u8],
    activation_height: u64,
    deactivation_height: Option<u64>,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DEPLOYMENT_HASH_DOMAIN);
    hash.update([PROGRAM_DEPLOYMENT_VERSION]);
    hash.update(network_id);
    hash.update(activation_height.to_le_bytes());
    hash.update(deactivation_height.unwrap_or(u64::MAX).to_le_bytes());
    hash.update((token_manifest.len() as u64).to_le_bytes());
    hash.update(token_manifest);
    hash.finalize().into()
}

impl AuthorizedProgramDeployment {
    pub fn program_entry<const DEPTH: usize>(
        &self,
        k: u32,
    ) -> Result<ProgramEntry, ProgramDeploymentError> {
        for kind in [
            StandardProgramKind::Nft,
            StandardProgramKind::Vesting,
            StandardProgramKind::Multisig,
            StandardProgramKind::Swap,
        ] {
            if self.token_manifest == standard_artifact(kind).package_manifest {
                return Ok(standard_program_entry(
                    kind,
                    self.activation_height,
                    self.deactivation_height,
                )?);
            }
        }
        standard_token_program::<DEPTH>(
            k,
            &self.token_manifest,
            self.activation_height,
            self.deactivation_height,
        )
        .map_err(|_| ProgramDeploymentError::InvalidManifest)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProgramDeploymentError> {
        self.validate_structure()?;
        let mut out = vec![PROGRAM_DEPLOYMENT_VERSION];
        write_bytes(&self.token_manifest, &mut out);
        write_varint(self.activation_height, &mut out);
        write_varint(self.deactivation_height.unwrap_or(u64::MAX), &mut out);
        write_bytes(&self.funding.encode()?, &mut out);
        if out.len() > MAX_PROGRAM_DEPLOYMENT_BYTES {
            return Err(ProgramDeploymentError::Oversized);
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProgramDeploymentError> {
        if input.is_empty() || input.len() > MAX_PROGRAM_DEPLOYMENT_BYTES {
            return Err(ProgramDeploymentError::Oversized);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != PROGRAM_DEPLOYMENT_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let token_manifest = read_bytes(&mut reader, MAX_MANIFEST_BYTES)?;
        let activation_height = reader.varint()?;
        let deactivation = reader.varint()?;
        let funding = AuthorizedTransaction::decode(&read_bytes(
            &mut reader,
            crate::MAX_AUTHORIZED_TRANSACTION_BYTES,
        )?)?;
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let deployment = Self {
            token_manifest,
            activation_height,
            deactivation_height: (deactivation != u64::MAX).then_some(deactivation),
            funding,
        };
        deployment.validate_structure()?;
        Ok(deployment)
    }
}

pub fn verify_standard_deployment<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize>(
    k: u32,
    deployment: &AuthorizedProgramDeployment,
    block_height: u64,
) -> Result<ProgramEntry, ProgramDeploymentError> {
    deployment.validate_structure()?;
    let minimum_activation = block_height
        .checked_add(1)
        .ok_or(ProgramDeploymentError::InvalidActivation)?;
    let maximum_activation = block_height
        .checked_add(MAX_PROGRAM_ACTIVATION_DELAY)
        .ok_or(ProgramDeploymentError::InvalidActivation)?;
    if deployment.activation_height < minimum_activation
        || deployment.activation_height > maximum_activation
    {
        return Err(ProgramDeploymentError::InvalidActivation);
    }
    if deployment.funding.backend_id != multi_transfer_backend_id(SPENDS, OUTPUTS)
        || deployment.funding.preimage.spends.len() != SPENDS
        || deployment.funding.preimage.outputs.len() != OUTPUTS
    {
        return Err(ProgramDeploymentError::InvalidCall);
    }
    let entry = deployment.program_entry::<DEPTH>(k)?;
    let program_id = entry
        .id()
        .map_err(|_| ProgramDeploymentError::InvalidCall)?;
    if deployment.funding.preimage.programs[0].program_id != program_id {
        return Err(ProgramDeploymentError::InvalidCall);
    }
    verify_authorized_transaction(&deployment.funding)?;
    let mut proof_statement = deployment.funding.clone();
    proof_statement.preimage.programs.clear();
    verify_multi_transfer_proof::<DEPTH, SPENDS, OUTPUTS>(k, &proof_statement)?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use group::{Curve, GroupEncoding};
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::pasta::Fp;
    use pasta_curves::{arithmetic::CurveAffine, pallas};

    use crate::authorization::{
        prepare_same_owner_spends, sign_binding_authorization, sign_prepared_spends,
    };
    use crate::keys::MasterSeed;
    use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
    use crate::proof::{create_multi_transfer_proof, MultiSpendWitness, MultiTransferWitness};
    use crate::state::{CanonicalField, Nullifier};
    use crate::token_program::standard_token_program;
    use crate::transaction::{ProgramCall, PublicOutput, PublicSpend, TransactionPreimage};
    use crate::types::NETWORK_ID_BYTES;

    use super::*;

    fn field(value: u64) -> CanonicalField {
        CanonicalField::from_field(Fp::from(value))
    }

    fn deployment_skeleton(manifest: Vec<u8>) -> AuthorizedProgramDeployment {
        let mut result = AuthorizedProgramDeployment {
            token_manifest: manifest,
            activation_height: 11,
            deactivation_height: Some(100),
            funding: AuthorizedTransaction {
                preimage: TransactionPreimage {
                    network_id: [1; NETWORK_ID_BYTES],
                    anchor: field(2),
                    expiry_height: 20,
                    fee: MIN_PROGRAM_DEPLOYMENT_FEE,
                    spends: vec![PublicSpend {
                        nullifier: Nullifier([3; 32]),
                        value_commitment: [4; 32],
                        randomized_key: [5; 32],
                    }],
                    outputs: vec![PublicOutput {
                        commitment: field(6),
                        value_commitment: [7; 32],
                        ephemeral_key: [8; 32],
                        ciphertext: vec![],
                        outgoing_ciphertext: vec![],
                    }],
                    programs: vec![],
                },
                backend_id: multi_transfer_backend_id(1, 1),
                proof: vec![9],
                spend_signatures: vec![[10; 64]],
                binding_signature: [11; 64],
            },
        };
        result.funding.preimage.programs.push(ProgramCall {
            program_id: [0; 32],
            function_id: PROGRAM_DEPLOYMENT_FUNCTION_ID,
            public_data_hash: result.deployment_hash(),
        });
        result
    }

    fn deployment() -> AuthorizedProgramDeployment {
        let manifest = b"TEST/DEPLOY".to_vec();
        let entry = standard_token_program::<2>(14, &manifest, 11, Some(100)).unwrap();
        let mut result = deployment_skeleton(manifest);
        result.funding.preimage.spends[0].value_commitment =
            crate::value_commitment_circuit::value_commitment_bytes(
                MIN_PROGRAM_DEPLOYMENT_FEE + 1,
                Fp::from(4),
            );
        result.funding.preimage.outputs[0].value_commitment =
            crate::value_commitment_circuit::value_commitment_bytes(1, Fp::from(7));
        result.funding.preimage.programs[0].program_id = entry.id().unwrap();
        result
    }

    fn rebind_call(deployment: &mut AuthorizedProgramDeployment) {
        deployment.funding.preimage.programs[0].public_data_hash = deployment.deployment_hash();
    }

    #[test]
    fn deployment_encoding_binds_manifest_call_and_activation() {
        let deployment = deployment();
        let encoded = deployment.encode().unwrap();
        assert_eq!(
            AuthorizedProgramDeployment::decode(&encoded).unwrap(),
            deployment
        );
        let mut changed = deployment.clone();
        changed.activation_height += 1;
        assert_eq!(
            changed.encode().err(),
            Some(ProgramDeploymentError::InvalidCall)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(AuthorizedProgramDeployment::decode(&trailing).is_err());
    }

    #[test]
    fn deployment_resolves_only_pinned_standard_program_manifests() {
        for kind in [
            StandardProgramKind::Nft,
            StandardProgramKind::Vesting,
            StandardProgramKind::Multisig,
            StandardProgramKind::Swap,
        ] {
            let mut deployment =
                deployment_skeleton(standard_artifact(kind).package_manifest.to_vec());
            let expected = standard_program_entry(
                kind,
                deployment.activation_height,
                deployment.deactivation_height,
            )
            .unwrap();
            deployment.funding.preimage.programs[0].program_id = expected.id().unwrap();
            rebind_call(&mut deployment);

            // An invalid k makes the generic token fallback fail immediately; pinned
            // standard artifacts remain resolvable because their k is immutable.
            let resolved = deployment.program_entry::<2>(9).unwrap();
            assert_eq!(resolved, expected);

            deployment.token_manifest.push(b'\n');
            rebind_call(&mut deployment);
            assert_eq!(
                deployment.program_entry::<2>(9).err(),
                Some(ProgramDeploymentError::InvalidManifest)
            );
        }
    }

    #[test]
    fn deployment_policy_rejects_unsafe_windows_fees_and_heights() {
        let mut low_fee = deployment();
        low_fee.funding.preimage.fee = MIN_PROGRAM_DEPLOYMENT_FEE - 1;
        assert_eq!(
            low_fee.validate_structure().err(),
            Some(ProgramDeploymentError::InsufficientFee)
        );

        let mut noncanonical_window = deployment();
        noncanonical_window.deactivation_height = Some(u64::MAX);
        assert_eq!(
            noncanonical_window.validate_structure().err(),
            Some(ProgramDeploymentError::InvalidActivation)
        );

        let mut current_height = deployment();
        current_height.activation_height = 10;
        rebind_call(&mut current_height);
        assert_eq!(
            verify_standard_deployment::<2, 1, 1>(14, &current_height, 10).err(),
            Some(ProgramDeploymentError::InvalidActivation)
        );

        let mut too_far = deployment();
        too_far.activation_height = MAX_PROGRAM_ACTIVATION_DELAY + 2;
        too_far.deactivation_height = None;
        rebind_call(&mut too_far);
        assert_eq!(
            verify_standard_deployment::<2, 1, 1>(14, &too_far, 1).err(),
            Some(ProgramDeploymentError::InvalidActivation)
        );

        let mut tampered_manifest = deployment();
        tampered_manifest.token_manifest.push(b'!');
        assert_eq!(
            tampered_manifest.validate_structure().err(),
            Some(ProgramDeploymentError::InvalidCall)
        );
    }

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    fn point(value: u64, randomness: Fp) -> pallas::Affine {
        Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &crate::value_commitment_circuit::value_commitment_bytes(value, randomness),
        ))
        .unwrap()
        .to_affine()
    }

    #[test]
    fn authorized_deployment_verifies_applies_and_rejects_replay() {
        const DEPTH: usize = 2;
        const K: u32 = 14;
        const CHANGE: u64 = 25;
        let input_value = MIN_PROGRAM_DEPLOYMENT_FEE + CHANGE;
        let network = [7; NETWORK_ID_BYTES];
        let keys = MasterSeed::new([71; 32]).derive(network).unwrap();
        let address = keys.address(0).unwrap();
        let authority_key =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&address.spend_authority_key))
                .unwrap()
                .to_affine();
        let authority = authority_key.coordinates().unwrap();

        let manifest = b"private-deployed-token/TEST".to_vec();
        let activation_height = 3;
        let entry =
            standard_token_program::<DEPTH>(K, &manifest, activation_height, Some(100)).unwrap();
        let program_id = entry.id().unwrap();
        let mut input_note = std::array::from_fn(|index| Fp::from(index as u64 + 300));
        input_note[1] = crate::types::network_field(&network);
        input_note[2] = Fp::zero();
        input_note[3] = Fp::zero();
        input_note[4] = crate::types::native_asset_fields()[0];
        input_note[5] = crate::types::native_asset_fields()[1];
        input_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(input_value);
        input_note[10] = *authority.x();
        input_note[11] = *authority.y();
        input_note[13] = Fp::from(401);
        let input_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(input_note);
        let mut output_note = std::array::from_fn(|index| Fp::from(index as u64 + 350));
        output_note[1] = crate::types::network_field(&network);
        output_note[2] = Fp::zero();
        output_note[3] = Fp::zero();
        output_note[4] = crate::types::native_asset_fields()[0];
        output_note[5] = crate::types::native_asset_fields()[1];
        output_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(CHANGE);
        output_note[13] = Fp::from(402);
        let output_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(output_note);

        let mut empty = hash2(Fp::from(1), Fp::zero());
        let mut siblings = Vec::with_capacity(DEPTH);
        for _ in 0..DEPTH {
            siblings.push(empty);
            empty = hash2(Fp::from(2), hash2(empty, empty));
        }
        let mut root = hash2(Fp::from(1), input_commitment);
        for sibling in &siblings {
            root = hash2(Fp::from(2), hash2(root, *sibling));
        }
        let anchor = CanonicalField::from_field(root);
        let nullifier_key = Fp::from(421);
        let rho = Fp::from(422);
        let nullifier = hash2(Fp::from(3), hash2(hash2(nullifier_key, rho), Fp::zero())).to_repr();
        let mut funding = TransactionPreimage {
            network_id: network,
            anchor,
            expiry_height: 20,
            fee: MIN_PROGRAM_DEPLOYMENT_FEE,
            spends: vec![PublicSpend {
                nullifier: Nullifier(nullifier),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    input_value,
                    Fp::from(401),
                ),
                randomized_key: [0; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(output_commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    CHANGE,
                    Fp::from(402),
                ),
                ephemeral_key: [8; 32],
                ciphertext: vec![9; 48],
                outgoing_ciphertext: vec![10; 32],
            }],
            programs: vec![],
        };
        let mut deployment = AuthorizedProgramDeployment {
            token_manifest: manifest,
            activation_height,
            deactivation_height: Some(100),
            funding: AuthorizedTransaction {
                preimage: funding.clone(),
                backend_id: multi_transfer_backend_id(1, 1),
                proof: vec![],
                spend_signatures: vec![[0; 64]],
                binding_signature: [0; 64],
            },
        };
        funding.programs.push(ProgramCall {
            program_id,
            function_id: PROGRAM_DEPLOYMENT_FUNCTION_ID,
            public_data_hash: deployment.deployment_hash(),
        });
        let prepared = prepare_same_owner_spends(&keys, &mut funding).unwrap();
        let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &funding.spends[0].randomized_key,
        ))
        .unwrap()
        .to_affine();
        let witness = MultiTransferWitness::<DEPTH> {
            input_values: vec![input_value],
            output_values: vec![CHANGE],
            spends: vec![MultiSpendWitness {
                commitment: input_commitment,
                input_note,
                authority_key,
                authorization_randomizer: prepared.randomizers()[0],
                randomized_key,
                siblings,
                position: 0,
                nullifier_key,
                rho,
                value_randomness: Fp::from(401),
                value_commitment: point(input_value, Fp::from(401)),
            }],
            output_notes: vec![output_note],
            output_value_randomness: vec![Fp::from(402)],
            output_value_commitments: vec![point(CHANGE, Fp::from(402))],
        };
        let proof = create_multi_transfer_proof::<DEPTH, 1, 1>(
            K,
            &witness,
            MIN_PROGRAM_DEPLOYMENT_FEE,
            anchor,
            &[nullifier],
        )
        .unwrap();
        let backend = multi_transfer_backend_id(1, 1);
        let spend_signatures = sign_prepared_spends(&prepared, &funding, &backend, &proof).unwrap();
        let binding_signature = sign_binding_authorization(
            &funding,
            &backend,
            &proof,
            &[Fp::from(401)],
            &[Fp::from(402)],
        )
        .unwrap();
        deployment.funding = AuthorizedTransaction {
            preimage: funding,
            backend_id: backend,
            proof,
            spend_signatures,
            binding_signature,
        };
        let encoded = deployment.encode().unwrap();

        let mut extracted_network = [0u8; NETWORK_ID_BYTES];
        let mut extracted_anchor = [0u8; 32];
        let mut extracted_expiry = 0u64;
        let mut extracted_fee = 0u64;
        let mut extracted_program = [0u8; 32];
        let mut extracted_nullifier = [0u8; 32];
        let mut extracted_nullifier_count = 0usize;
        let mut extracted_commitment = [0u8; 32];
        let mut extracted_commitment_count = 0usize;
        assert_eq!(
            crate::onyx_verify_program_deployment(
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                extracted_network.as_mut_ptr(),
                extracted_anchor.as_mut_ptr(),
                &mut extracted_expiry,
                &mut extracted_fee,
                extracted_program.as_mut_ptr(),
                extracted_nullifier.as_mut_ptr(),
                1,
                &mut extracted_nullifier_count,
                extracted_commitment.as_mut_ptr(),
                1,
                &mut extracted_commitment_count,
            ),
            1
        );
        assert_eq!(extracted_program, program_id);
        assert_eq!(extracted_fee, MIN_PROGRAM_DEPLOYMENT_FEE);
        assert_eq!(extracted_nullifier, nullifier);

        let mut state = crate::state::ShieldedState::<DEPTH>::new(10);
        let seed = TransactionPreimage {
            network_id: network,
            anchor: state.root(),
            expiry_height: 20,
            fee: 0,
            spends: vec![],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(input_commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    input_value,
                    Fp::from(401),
                ),
                ephemeral_key: [12; 32],
                ciphertext: vec![13; 48],
                outgoing_ciphertext: vec![14; 32],
            }],
            programs: vec![],
        };
        state.apply_bridge(&seed, input_value, 0, 1).unwrap();
        assert_eq!(state.root(), anchor);
        let previous_snapshot = state.encode_snapshot();
        let mut snapshot_ptr = std::ptr::null_mut();
        let mut snapshot_len = 0usize;
        let mut applied_fee = 0u64;
        let mut applied_program = [0u8; 32];
        assert_eq!(
            crate::onyx_verify_apply_program_deployment(
                previous_snapshot.as_ptr(),
                previous_snapshot.len(),
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                network.as_ptr(),
                2,
                &mut snapshot_ptr,
                &mut snapshot_len,
                &mut applied_fee,
                applied_program.as_mut_ptr(),
            ),
            1
        );
        assert_eq!(applied_program, program_id);
        let snapshot = unsafe { std::slice::from_raw_parts(snapshot_ptr, snapshot_len) }.to_vec();
        crate::onyx_free(snapshot_ptr, snapshot_len);
        let applied = crate::state::ShieldedState::<DEPTH>::decode_snapshot(&snapshot).unwrap();
        assert_eq!(applied.program_count(), 1);
        assert_eq!(
            applied.current_block_program_cost(),
            PROGRAM_DEPLOYMENT_COST
        );
        assert_eq!(applied.total_fees(), MIN_PROGRAM_DEPLOYMENT_FEE);
        assert_eq!(applied.circulating_supply(), CHANGE);
        assert!(applied.is_spent(&Nullifier(nullifier)));

        let mut replay_ptr = std::ptr::null_mut();
        let mut replay_len = 0usize;
        assert_eq!(
            crate::onyx_verify_apply_program_deployment(
                snapshot.as_ptr(),
                snapshot.len(),
                10,
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                network.as_ptr(),
                2,
                &mut replay_ptr,
                &mut replay_len,
                &mut applied_fee,
                applied_program.as_mut_ptr(),
            ),
            -5
        );
        assert!(replay_ptr.is_null());
        assert_eq!(replay_len, 0);
    }
}
