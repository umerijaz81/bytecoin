//! Proof creation and verification for the current O2 linked transfer circuit.
//!
//! This API is deliberately not exported over the consensus FFI yet. The circuit binds native
//! balance, input/output note commitments, anchor, and nullifier. In-circuit authorization remains
//! required before the backend can be marked consensus-capable.

use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

use crate::authorization::{verify_authorized_transaction, AuthorizationError};
use crate::linked_transfer_circuit::LinkedTransferCircuit;
use crate::membership_circuit::MembershipCircuit;
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::state::CanonicalField;
use crate::transaction::{AuthorizedTransaction, TransactionError, MAX_PROOF_BYTES};

pub const EXPERIMENTAL_TRANSFER_BACKEND: &str = "halo2-ipa-pasta-onyx-o2-experimental";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofError {
    InvalidShape,
    InvalidPublicInput,
    ProofTooLarge,
    ProvingFailed,
    VerificationFailed,
    Authorization(AuthorizationError),
    Transaction(TransactionError),
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

#[derive(Clone)]
pub struct TransferWitness<const DEPTH: usize> {
    pub input_values: Vec<u64>,
    pub output_values: Vec<u64>,
    pub commitment: Fp,
    pub input_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub output_note: [Fp; NOTE_COMMITMENT_INPUTS],
    pub siblings: Vec<Fp>,
    pub position: u64,
    pub nullifier_key: Fp,
    pub rho: Fp,
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
    let notes = [
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
            .hash(witness.output_note),
    ];
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&public, &membership, &notes]],
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
    );
    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).map_err(|_| ProofError::VerificationFailed)?;
    let public = [Fp::from(transaction.preimage.fee)];
    let membership = [transaction.preimage.anchor.field(), nullifier.field()];
    let notes = [transaction.preimage.outputs[0].commitment.field()];
    let mut transcript =
        Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&transaction.proof[..]);
    verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
        &params,
        &vk,
        SingleVerifier::new(&params),
        &[&[&public, &membership, &notes]],
        &mut transcript,
    )
    .map_err(|_| ProofError::VerificationFailed)
}

pub fn verify_authorized_transfer<const DEPTH: usize>(
    k: u32,
    transaction: &AuthorizedTransaction,
) -> Result<(), ProofError> {
    verify_authorized_transaction(transaction)?;
    verify_transfer_proof::<DEPTH>(k, transaction)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};

    use crate::authorization::authorize_transaction;
    use crate::keys::MasterSeed;
    use crate::state::Nullifier;
    use crate::transaction::{PublicOutput, PublicSpend, TransactionPreimage};
    use crate::types::NETWORK_ID_BYTES;

    use super::*;

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    #[test]
    fn experimental_transfer_backend_proves_then_authenticates() {
        const DEPTH: usize = 4;
        const K: u32 = 14;
        let mut input_note = std::array::from_fn(|index| Fp::from(index as u64 + 40));
        input_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(30);
        let commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(input_note);
        let mut output_note = std::array::from_fn(|index| Fp::from(index as u64 + 80));
        output_note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(25);
        let output_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(output_note);
        let siblings = vec![Fp::from(11), Fp::from(12), Fp::from(13), Fp::from(14)];
        let position = 5u64;
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
        let witness: TransferWitness<DEPTH> = TransferWitness {
            input_values: vec![30],
            output_values: vec![25],
            commitment,
            input_note,
            output_note,
            siblings,
            position,
            nullifier_key,
            rho,
        };
        let anchor = CanonicalField::from_field(root);
        let proof = create_transfer_proof(K, &witness, 5, anchor, nullifier).unwrap();
        let mut mismatched_opening = witness.clone();
        mismatched_opening.input_note[0] += Fp::one();
        let mismatched_proof =
            create_transfer_proof(K, &mismatched_opening, 5, anchor, nullifier).unwrap();
        let preimage = TransactionPreimage {
            network_id: [1; NETWORK_ID_BYTES],
            anchor,
            expiry_height: 100,
            fee: 5,
            spends: vec![PublicSpend {
                nullifier: Nullifier(nullifier),
                randomized_key: [0; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: CanonicalField::from_field(output_commitment),
                ephemeral_key: [32; 32],
                ciphertext: vec![33; 48],
                outgoing_ciphertext: vec![34; 32],
            }],
            programs: vec![],
        };
        let keys = MasterSeed::new([9; 32])
            .derive([1; NETWORK_ID_BYTES])
            .unwrap();
        let transaction = authorize_transaction(
            &keys,
            preimage,
            EXPERIMENTAL_TRANSFER_BACKEND.to_owned(),
            proof,
        )
        .unwrap();
        assert!(verify_authorized_transfer::<DEPTH>(K, &transaction).is_ok());

        let mut mismatched_transaction = transaction.clone();
        mismatched_transaction.proof = mismatched_proof;
        assert_eq!(
            verify_transfer_proof::<DEPTH>(K, &mismatched_transaction),
            Err(ProofError::VerificationFailed)
        );

        let mut changed = transaction;
        changed.preimage.fee = 4;
        assert!(verify_authorized_transfer::<DEPTH>(K, &changed).is_err());
    }
}
