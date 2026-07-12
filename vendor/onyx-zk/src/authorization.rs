//! Transaction transcript binding and Orchard RedPallas spend authorization.

use ff::{Field, PrimeField};
use pasta_curves::pallas;
use reddsa::orchard::SpendAuth;
use reddsa::{Signature, SigningKey, VerificationKey};
use sha2::{Digest, Sha256};

use crate::keys::KeyBundle;
use crate::transaction::{
    AuthorizedTransaction, TransactionError, TransactionPreimage, MAX_BACKEND_ID_BYTES,
    MAX_PROOF_BYTES,
};

const AUTHORIZATION_DOMAIN: &[u8] = b"bytecoin.onyx.v6.spend-authorization";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorizationError {
    InvalidBackendId,
    ProofTooLarge,
    InvalidSpendKey,
    InvalidVerificationKey,
    InvalidSignature,
    WrongSignatureCount,
    PreparedKeyMismatch,
    Transaction(TransactionError),
}

pub struct PreparedSpendAuthorizations {
    randomized_keys: Vec<SigningKey<SpendAuth>>,
    randomizers: Vec<halo2_proofs::pasta::Fp>,
}

impl PreparedSpendAuthorizations {
    pub fn randomizers(&self) -> &[halo2_proofs::pasta::Fp] {
        &self.randomizers
    }
}

pub fn prepare_same_owner_spends(
    keys: &KeyBundle,
    transaction: &mut TransactionPreimage,
) -> Result<PreparedSpendAuthorizations, AuthorizationError> {
    let signing_key = SigningKey::<SpendAuth>::try_from(keys.spend_key_bytes())
        .map_err(|_| AuthorizationError::InvalidSpendKey)?;
    let mut rng = rand::rngs::OsRng;
    let mut randomized_keys = Vec::with_capacity(transaction.spends.len());
    let mut randomizers = Vec::with_capacity(transaction.spends.len());
    for spend in &mut transaction.spends {
        let randomizer = halo2_proofs::pasta::Fp::random(&mut rng);
        let scalar =
            Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(randomizer.to_repr()))
                .expect("every Pallas base element is canonical in its scalar field");
        let randomized = signing_key.randomize(&scalar);
        spend.randomized_key = VerificationKey::from(&randomized).into();
        randomized_keys.push(randomized);
        randomizers.push(randomizer);
    }
    Ok(PreparedSpendAuthorizations {
        randomized_keys,
        randomizers,
    })
}

pub fn sign_prepared_spends(
    prepared: &PreparedSpendAuthorizations,
    transaction: &TransactionPreimage,
    backend_id: &str,
    proof: &[u8],
) -> Result<Vec<[u8; 64]>, AuthorizationError> {
    if prepared.randomized_keys.len() != transaction.spends.len() {
        return Err(AuthorizationError::WrongSignatureCount);
    }
    for (key, spend) in prepared.randomized_keys.iter().zip(&transaction.spends) {
        let expected: [u8; 32] = VerificationKey::from(key).into();
        if expected != spend.randomized_key {
            return Err(AuthorizationError::PreparedKeyMismatch);
        }
    }
    let digest = authorization_digest(transaction, backend_id, proof)?;
    let mut rng = rand::rngs::OsRng;
    Ok(prepared
        .randomized_keys
        .iter()
        .map(|key| key.sign(&mut rng, &digest).into())
        .collect())
}

impl From<TransactionError> for AuthorizationError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}

pub fn authorization_digest(
    transaction: &TransactionPreimage,
    backend_id: &str,
    proof: &[u8],
) -> Result<[u8; 32], AuthorizationError> {
    if backend_id.is_empty() || backend_id.len() > MAX_BACKEND_ID_BYTES || !backend_id.is_ascii() {
        return Err(AuthorizationError::InvalidBackendId);
    }
    if proof.len() > MAX_PROOF_BYTES {
        return Err(AuthorizationError::ProofTooLarge);
    }
    let transaction = transaction.encode()?;
    let mut hash = Sha256::new();
    hash.update(AUTHORIZATION_DOMAIN);
    hash.update((transaction.len() as u64).to_le_bytes());
    hash.update(transaction);
    hash.update((backend_id.len() as u64).to_le_bytes());
    hash.update(backend_id.as_bytes());
    hash.update((proof.len() as u64).to_le_bytes());
    hash.update(proof);
    Ok(hash.finalize().into())
}

/// Randomizes every spend key, writes the corresponding public keys into the transaction preimage,
/// then signs the final transaction/proof digest. This ordering avoids circular transcript binding.
pub fn authorize_same_owner_spends(
    keys: &KeyBundle,
    transaction: &mut TransactionPreimage,
    backend_id: &str,
    proof: &[u8],
) -> Result<Vec<[u8; 64]>, AuthorizationError> {
    let prepared = prepare_same_owner_spends(keys, transaction)?;
    sign_prepared_spends(&prepared, transaction, backend_id, proof)
}

pub fn verify_spend_authorizations(
    transaction: &TransactionPreimage,
    backend_id: &str,
    proof: &[u8],
    signatures: &[[u8; 64]],
) -> Result<(), AuthorizationError> {
    if signatures.len() != transaction.spends.len() {
        return Err(AuthorizationError::WrongSignatureCount);
    }
    let digest = authorization_digest(transaction, backend_id, proof)?;
    for (spend, signature) in transaction.spends.iter().zip(signatures) {
        let key = VerificationKey::<SpendAuth>::try_from(spend.randomized_key)
            .map_err(|_| AuthorizationError::InvalidVerificationKey)?;
        let signature = Signature::<SpendAuth>::from(*signature);
        key.verify(&digest, &signature)
            .map_err(|_| AuthorizationError::InvalidSignature)?;
    }
    Ok(())
}

pub fn authorize_transaction(
    keys: &KeyBundle,
    mut preimage: TransactionPreimage,
    backend_id: String,
    proof: Vec<u8>,
) -> Result<AuthorizedTransaction, AuthorizationError> {
    let spend_signatures = authorize_same_owner_spends(keys, &mut preimage, &backend_id, &proof)?;
    let transaction = AuthorizedTransaction {
        preimage,
        backend_id,
        proof,
        spend_signatures,
    };
    transaction.encode()?;
    Ok(transaction)
}

pub fn verify_authorized_transaction(
    transaction: &AuthorizedTransaction,
) -> Result<(), AuthorizationError> {
    transaction.encode()?;
    verify_spend_authorizations(
        &transaction.preimage,
        &transaction.backend_id,
        &transaction.proof,
        &transaction.spend_signatures,
    )
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_proofs::pasta::Fp;

    use crate::keys::MasterSeed;
    use crate::state::{CanonicalField, Nullifier};
    use crate::transaction::{PublicOutput, PublicSpend};
    use crate::types::NETWORK_ID_BYTES;

    use super::*;

    fn field(value: u64) -> CanonicalField {
        CanonicalField::from_bytes(Fp::from(value).to_repr()).unwrap()
    }

    fn transaction() -> TransactionPreimage {
        TransactionPreimage {
            network_id: [1; NETWORK_ID_BYTES],
            anchor: field(2),
            expiry_height: 100,
            fee: 7,
            spends: vec![PublicSpend {
                nullifier: Nullifier([3; 32]),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    halo2_proofs::pasta::Fp::from(2),
                ),
                randomized_key: [0; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: field(5),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    halo2_proofs::pasta::Fp::from(3),
                ),
                ephemeral_key: [6; 32],
                ciphertext: vec![7; 48],
                outgoing_ciphertext: vec![8; 32],
            }],
            programs: vec![],
        }
    }

    #[test]
    fn authorization_binds_transaction_and_proof() {
        let keys = MasterSeed::new([9; 32])
            .derive([1; NETWORK_ID_BYTES])
            .unwrap();
        let mut tx = transaction();
        let proof = b"proof bytes";
        let signatures =
            authorize_same_owner_spends(&keys, &mut tx, "halo2-ipa-pasta-v1", proof).unwrap();
        assert!(verify_spend_authorizations(&tx, "halo2-ipa-pasta-v1", proof, &signatures).is_ok());

        let mut changed = tx.clone();
        changed.fee += 1;
        assert_eq!(
            verify_spend_authorizations(&changed, "halo2-ipa-pasta-v1", proof, &signatures),
            Err(AuthorizationError::InvalidSignature)
        );
        assert_eq!(
            verify_spend_authorizations(&tx, "halo2-ipa-pasta-v1", b"other proof", &signatures),
            Err(AuthorizationError::InvalidSignature)
        );
        changed = tx.clone();
        changed.outputs[0].ciphertext[0] ^= 1;
        assert_eq!(
            verify_spend_authorizations(&changed, "halo2-ipa-pasta-v1", proof, &signatures),
            Err(AuthorizationError::InvalidSignature)
        );
    }

    #[test]
    fn authorization_rejects_bad_shapes_before_crypto() {
        let tx = transaction();
        assert_eq!(
            authorization_digest(&tx, "", b"proof"),
            Err(AuthorizationError::InvalidBackendId)
        );
        assert_eq!(
            verify_spend_authorizations(&tx, "halo2", b"proof", &[]),
            Err(AuthorizationError::WrongSignatureCount)
        );
    }

    #[test]
    fn authorized_envelope_builds_and_verifies_as_one_object() {
        let keys = MasterSeed::new([9; 32])
            .derive([1; NETWORK_ID_BYTES])
            .unwrap();
        let transaction = authorize_transaction(
            &keys,
            transaction(),
            "halo2-ipa-pasta-v1".to_owned(),
            b"proof".to_vec(),
        )
        .unwrap();
        assert!(verify_authorized_transaction(&transaction).is_ok());
        assert_eq!(
            AuthorizedTransaction::decode(&transaction.encode().unwrap()).unwrap(),
            transaction
        );
    }
}
