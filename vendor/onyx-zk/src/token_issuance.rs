//! Canonical issuer-authorized private fungible-token issuance envelope.

use rand::rngs::OsRng;
use reddsa::orchard::SpendAuth;
use reddsa::{Signature, SigningKey, VerificationKey};
use sha2::{Digest, Sha256};

use crate::authorization::{authorization_digest, AuthorizationError};
use crate::keys::KeyBundle;
use crate::program::ProgramRegistry;
use crate::proof::{verify_authorized_token_issuance, ProofError};
use crate::token_program::{
    issuance_function_id, issuance_policy_from_entry, issuance_public_data_hash, TokenProgramError,
    TOKEN_PROGRAM_BACKEND,
};
use crate::transaction::{read_bytes, write_bytes, AuthorizedTransaction, TransactionError};
use crate::types::{write_varint, DecodeError, Reader};

pub const TOKEN_ISSUANCE_VERSION: u8 = 1;
pub const MAX_TOKEN_ISSUANCE_BYTES: usize = 384 * 1024;
const ISSUER_AUTHORIZATION_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-issuer-authorization";
const ISSUANCE_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.token-issuance-id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTokenIssuance {
    pub sequence: u64,
    pub issued_amount: u64,
    pub transaction: AuthorizedTransaction,
    pub issuer_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenIssuanceError {
    Decode(DecodeError),
    Transaction(TransactionError),
    Authorization(AuthorizationError),
    Proof(ProofError),
    Program(TokenProgramError),
    InvalidShape,
    InvalidIssuer,
    SupplyCap,
    Oversized,
}

impl From<DecodeError> for TokenIssuanceError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}
impl From<TransactionError> for TokenIssuanceError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}
impl From<AuthorizationError> for TokenIssuanceError {
    fn from(value: AuthorizationError) -> Self {
        Self::Authorization(value)
    }
}
impl From<ProofError> for TokenIssuanceError {
    fn from(value: ProofError) -> Self {
        Self::Proof(value)
    }
}
impl From<TokenProgramError> for TokenIssuanceError {
    fn from(value: TokenProgramError) -> Self {
        Self::Program(value)
    }
}

impl AuthorizedTokenIssuance {
    pub fn validate_structure(&self) -> Result<(), TokenIssuanceError> {
        let preimage = &self.transaction.preimage;
        if self.issued_amount == 0
            || self.transaction.backend_id != TOKEN_PROGRAM_BACKEND
            || !preimage.spends.is_empty()
            || !(1..=2).contains(&preimage.outputs.len())
            || preimage.fee != 0
            || preimage.programs.len() != 1
            || preimage.programs[0].function_id
                != issuance_function_id(preimage.outputs.len()).unwrap()
            || preimage.programs[0].public_data_hash
                != issuance_public_data_hash(self.sequence, self.issued_amount)
        {
            return Err(TokenIssuanceError::InvalidShape);
        }
        self.transaction.encode()?;
        Ok(())
    }

    pub fn issuer_digest(&self) -> Result<[u8; 32], TokenIssuanceError> {
        self.validate_structure()?;
        let authorization = authorization_digest(
            &self.transaction.preimage,
            &self.transaction.backend_id,
            &self.transaction.proof,
        )?;
        let mut hash = Sha256::new();
        hash.update(ISSUER_AUTHORIZATION_DOMAIN);
        hash.update([TOKEN_ISSUANCE_VERSION]);
        hash.update(self.sequence.to_le_bytes());
        hash.update(self.issued_amount.to_le_bytes());
        hash.update(authorization);
        Ok(hash.finalize().into())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TokenIssuanceError> {
        self.validate_structure()?;
        let mut out = vec![TOKEN_ISSUANCE_VERSION];
        write_varint(self.sequence, &mut out);
        write_varint(self.issued_amount, &mut out);
        write_bytes(&self.transaction.encode()?, &mut out);
        out.extend_from_slice(&self.issuer_signature);
        if out.len() > MAX_TOKEN_ISSUANCE_BYTES {
            return Err(TokenIssuanceError::Oversized);
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TokenIssuanceError> {
        if input.is_empty() || input.len() > MAX_TOKEN_ISSUANCE_BYTES {
            return Err(TokenIssuanceError::Oversized);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != TOKEN_ISSUANCE_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let issuance = Self {
            sequence: reader.varint()?,
            issued_amount: reader.varint()?,
            transaction: AuthorizedTransaction::decode(&read_bytes(
                &mut reader,
                crate::MAX_AUTHORIZED_TRANSACTION_BYTES,
            )?)?,
            issuer_signature: reader.array()?,
        };
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        issuance.validate_structure()?;
        Ok(issuance)
    }

    pub fn id(&self) -> Result<[u8; 32], TokenIssuanceError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(ISSUANCE_ID_DOMAIN);
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

pub fn sign_issuer_authorization(
    keys: &KeyBundle,
    issuance: &AuthorizedTokenIssuance,
) -> Result<[u8; 64], TokenIssuanceError> {
    let signing = SigningKey::<SpendAuth>::try_from(keys.spend_key_bytes())
        .map_err(|_| TokenIssuanceError::InvalidIssuer)?;
    Ok(signing.sign(&mut OsRng, &issuance.issuer_digest()?).into())
}

pub fn verify_token_issuance<const DEPTH: usize, const OUTPUTS: usize>(
    k: u32,
    issuance: &AuthorizedTokenIssuance,
    registry: &ProgramRegistry,
    block_height: u64,
) -> Result<(), TokenIssuanceError> {
    issuance.validate_structure()?;
    let call = &issuance.transaction.preimage.programs[0];
    let entry = registry
        .get(&call.program_id)
        .ok_or(TokenIssuanceError::InvalidShape)?;
    if entry.id().map_err(|_| TokenIssuanceError::InvalidShape)? != call.program_id {
        return Err(TokenIssuanceError::InvalidShape);
    }
    let (depth, manifest_k, policy) = issuance_policy_from_entry(entry)?;
    if depth != DEPTH || manifest_k != k || issuance.issued_amount > policy.max_supply {
        return Err(TokenIssuanceError::SupplyCap);
    }
    let verification = VerificationKey::<SpendAuth>::try_from(policy.issuer)
        .map_err(|_| TokenIssuanceError::InvalidIssuer)?;
    verification
        .verify(
            &issuance.issuer_digest()?,
            &Signature::<SpendAuth>::from(issuance.issuer_signature),
        )
        .map_err(|_| TokenIssuanceError::InvalidIssuer)?;
    verify_authorized_token_issuance::<DEPTH, OUTPUTS>(
        k,
        &issuance.transaction,
        issuance.issued_amount,
        issuance.sequence,
        Some(registry),
        block_height,
    )?;
    Ok(())
}

pub fn verify_token_issuance_proof<const DEPTH: usize, const OUTPUTS: usize>(
    k: u32,
    issuance: &AuthorizedTokenIssuance,
) -> Result<(), TokenIssuanceError> {
    issuance.validate_structure()?;
    verify_authorized_token_issuance::<DEPTH, OUTPUTS>(
        k,
        &issuance.transaction,
        issuance.issued_amount,
        issuance.sequence,
        None,
        0,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use group::{Curve, GroupEncoding};
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    use halo2_proofs::pasta::Fp;
    use pasta_curves::pallas;

    use crate::authorization::sign_binding_authorization;
    use crate::keys::MasterSeed;
    use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
    use crate::proof::{create_token_issuance_proof, TokenIssuanceWitness};
    use crate::state::{CanonicalField, ShieldedState};
    use crate::token_program::{
        issuance_function_id, issuance_public_data_hash, standard_token_program,
        TokenIssuancePolicy,
    };
    use crate::transaction::{
        AuthorizedTransaction, ProgramCall, PublicOutput, TransactionPreimage,
    };

    use super::*;

    #[test]
    fn issuer_authorized_issuance_proves_applies_and_rejects_replay() {
        const DEPTH: usize = 2;
        const K: u32 = 14;
        let network = [7u8; 16];
        let keys = MasterSeed::new([81; 32]).derive(network).unwrap();
        let policy = TokenIssuancePolicy {
            issuer: keys.address(0).unwrap().spend_authority_key,
            max_supply: 100,
            metadata: b"symbol=ISS;decimals=2".to_vec(),
        };
        let entry = standard_token_program::<DEPTH>(K, &policy.encode().unwrap(), 1, None).unwrap();
        let program_id = entry.id().unwrap();
        let program = crate::types::pack_32(&program_id);
        let values = vec![60u64, 40];
        let randomness = vec![Fp::from(31), Fp::from(32)];
        let mut notes = Vec::new();
        let mut commitments = Vec::new();
        let mut outputs = Vec::new();
        for index in 0..2 {
            let mut note =
                std::array::from_fn(|field| Fp::from(200 + index as u64 * 20 + field as u64));
            note[1] = crate::types::network_field(&network);
            note[2] = program[0];
            note[3] = program[1];
            note[4] = program[0];
            note[5] = program[1];
            note[6] = Fp::from(values[index]);
            note[13] = randomness[index];
            let note_commitment =
                Hash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                    .hash(note);
            let value_commitment = (crate::spend_auth_circuit::value_generator()
                * pallas::Scalar::from(values[index])
                + crate::spend_auth_circuit::binding_generator()
                    * pallas::Scalar::from(31 + index as u64))
            .to_affine();
            notes.push(note);
            commitments.push(value_commitment);
            outputs.push(PublicOutput {
                commitment: CanonicalField::from_field(note_commitment),
                value_commitment: value_commitment.to_bytes(),
                ephemeral_key: [9 + index as u8; 32],
                ciphertext: vec![10 + index as u8; 48],
                outgoing_ciphertext: vec![11 + index as u8; 32],
            });
        }
        let witness = TokenIssuanceWitness {
            output_values: values,
            output_notes: notes,
            output_value_randomness: randomness.clone(),
            output_value_commitments: commitments,
        };
        let proof =
            create_token_issuance_proof::<2>(K, &witness, 100, network, program_id).unwrap();
        let mut state = ShieldedState::<DEPTH>::new(10);
        state.register_program(entry).unwrap();
        let wallet_built = crate::wallet::build_token_issuance(
            &keys,
            &keys.address(1).unwrap(),
            state.root(),
            program_id,
            0,
            25,
            20,
            b"wallet issuance".to_vec(),
            K,
        )
        .unwrap();
        verify_token_issuance::<DEPTH, 1>(K, &wallet_built, state.program_registry(), 1).unwrap();
        let wallet_encoded = wallet_built.encode().unwrap();
        let mut wallet_ptr = std::ptr::null_mut();
        let mut wallet_len = 0usize;
        let mut wallet_balance = 0u64;
        let mut wallet_notes = 0usize;
        let mut wallet_root = [0u8; 32];
        assert_eq!(
            crate::onyx_wallet_scan(
                std::ptr::null(),
                0,
                [81u8; 32].as_ptr(),
                network.as_ptr(),
                3,
                wallet_encoded.as_ptr(),
                wallet_encoded.len(),
                &mut wallet_ptr,
                &mut wallet_len,
                &mut wallet_balance,
                &mut wallet_notes,
                wallet_root.as_mut_ptr(),
            ),
            1
        );
        crate::onyx_free(wallet_ptr, wallet_len);
        assert_eq!(wallet_balance, 25);
        assert_eq!(wallet_notes, 1);
        let preimage = TransactionPreimage {
            network_id: network,
            anchor: state.root(),
            expiry_height: 20,
            fee: 0,
            spends: vec![],
            outputs,
            programs: vec![ProgramCall {
                program_id,
                function_id: issuance_function_id(2).unwrap(),
                public_data_hash: issuance_public_data_hash(0, 100),
            }],
        };
        let binding_signature =
            sign_binding_authorization(&preimage, TOKEN_PROGRAM_BACKEND, &proof, &[], &randomness)
                .unwrap();
        let mut issuance = AuthorizedTokenIssuance {
            sequence: 0,
            issued_amount: 100,
            transaction: AuthorizedTransaction {
                preimage,
                backend_id: TOKEN_PROGRAM_BACKEND.to_owned(),
                proof,
                spend_signatures: vec![],
                binding_signature,
            },
            issuer_signature: [0; 64],
        };
        issuance.issuer_signature = sign_issuer_authorization(&keys, &issuance).unwrap();
        let encoded = issuance.encode().unwrap();
        assert_eq!(AuthorizedTokenIssuance::decode(&encoded).unwrap(), issuance);
        verify_token_issuance::<DEPTH, 2>(K, &issuance, state.program_registry(), 1).unwrap();

        let mut extracted_network = [0u8; 16];
        let mut extracted_anchor = [0u8; 32];
        let mut extracted_expiry = 0u64;
        let mut extracted_program = [0u8; 32];
        let mut extracted_sequence = u64::MAX;
        let mut extracted_amount = 0u64;
        let mut extracted_commitments = [0u8; 64];
        let mut extracted_commitment_count = 0usize;
        assert_eq!(
            crate::onyx_verify_and_extract_token_issuance(
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                extracted_network.as_mut_ptr(),
                extracted_anchor.as_mut_ptr(),
                &mut extracted_expiry,
                extracted_program.as_mut_ptr(),
                &mut extracted_sequence,
                &mut extracted_amount,
                extracted_commitments.as_mut_ptr(),
                2,
                &mut extracted_commitment_count,
            ),
            1
        );
        assert_eq!(extracted_network, network);
        assert_eq!(extracted_program, program_id);
        assert_eq!(extracted_sequence, 0);
        assert_eq!(extracted_amount, 100);
        assert_eq!(extracted_commitment_count, 2);

        let initial_snapshot = state.encode_snapshot();
        let mut applied_ptr = std::ptr::null_mut();
        let mut applied_len = 0usize;
        let mut applied_program = [0u8; 32];
        let mut applied_sequence = u64::MAX;
        let mut applied_amount = 0u64;
        assert_eq!(
            crate::onyx_verify_apply_token_issuance(
                initial_snapshot.as_ptr(),
                initial_snapshot.len(),
                encoded.as_ptr(),
                encoded.len(),
                DEPTH as u32,
                K,
                network.as_ptr(),
                1,
                &mut applied_ptr,
                &mut applied_len,
                applied_program.as_mut_ptr(),
                &mut applied_sequence,
                &mut applied_amount,
            ),
            1
        );
        let ffi_snapshot = unsafe { std::slice::from_raw_parts(applied_ptr, applied_len) }.to_vec();
        crate::onyx_free(applied_ptr, applied_len);
        let ffi_state = ShieldedState::<DEPTH>::decode_snapshot(&ffi_snapshot).unwrap();
        assert_eq!(ffi_state.token_issued_supply(&program_id), 100);
        assert_eq!(applied_program, program_id);
        assert_eq!(applied_sequence, 0);
        assert_eq!(applied_amount, 100);

        let mut bad_signature = issuance.clone();
        bad_signature.issuer_signature[0] ^= 1;
        assert_eq!(
            verify_token_issuance::<DEPTH, 2>(K, &bad_signature, state.program_registry(), 1).err(),
            Some(TokenIssuanceError::InvalidIssuer)
        );

        state
            .apply_token_issuance(
                &issuance.transaction.preimage,
                issuance.sequence,
                issuance.issued_amount,
                1,
            )
            .unwrap();
        assert_eq!(state.token_issued_supply(&program_id), 100);
        let applied = state.encode_snapshot();
        assert_eq!(
            state
                .apply_token_issuance(
                    &issuance.transaction.preimage,
                    issuance.sequence,
                    issuance.issued_amount,
                    1,
                )
                .err(),
            Some(crate::state::StateError::InvalidProgram)
        );
        assert_eq!(state.encode_snapshot(), applied);
    }
}
