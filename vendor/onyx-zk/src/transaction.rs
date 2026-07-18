//! Canonical public statement for Onyx transactions.

use crate::state::{CanonicalField, Nullifier};
use crate::types::{write_varint, DecodeError, Reader, NETWORK_ID_BYTES};
use group::{Curve, GroupEncoding};
use pasta_curves::{arithmetic::CurveAffine, pallas};
use sha2::{Digest, Sha256};

pub const ONYX_TRANSACTION_VERSION: u8 = 6;
pub const MAX_SPENDS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_PROGRAMS: usize = 8;
pub const MAX_CIPHERTEXT_BYTES: usize = 4096;
pub const MAX_OUT_CIPHERTEXT_BYTES: usize = 512;
pub const MAX_BACKEND_ID_BYTES: usize = 64;
pub const MAX_PROOF_BYTES: usize = 192 * 1024;
const TRANSACTION_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.transaction-id";
const ENCRYPTION_BINDING_DOMAIN: &[u8] = b"bytecoin.onyx.v6.encryption-binding";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSpend {
    pub nullifier: Nullifier,
    pub value_commitment: [u8; 32],
    pub randomized_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOutput {
    pub commitment: CanonicalField,
    pub value_commitment: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub outgoing_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramCall {
    pub program_id: [u8; 32],
    pub function_id: u32,
    pub public_data_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPreimage {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub anchor: CanonicalField,
    pub expiry_height: u64,
    pub fee: u64,
    pub spends: Vec<PublicSpend>,
    pub outputs: Vec<PublicOutput>,
    pub programs: Vec<ProgramCall>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTransaction {
    pub preimage: TransactionPreimage,
    pub backend_id: String,
    pub proof: Vec<u8>,
    pub spend_signatures: Vec<[u8; 64]>,
    pub binding_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionError {
    Decode(DecodeError),
    TooManySpends,
    TooManyOutputs,
    TooManyPrograms,
    CiphertextTooLarge,
    EmptyTransaction,
    InvalidBackendId,
    ProofTooLarge,
    WrongSignatureCount,
    NonCanonicalNullifier,
    InvalidValueCommitment,
}

impl From<DecodeError> for TransactionError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl TransactionPreimage {
    fn validate(&self) -> Result<(), TransactionError> {
        if self.spends.is_empty() && self.outputs.is_empty() {
            return Err(TransactionError::EmptyTransaction);
        }
        if self.spends.len() > MAX_SPENDS {
            return Err(TransactionError::TooManySpends);
        }
        if self
            .spends
            .iter()
            .any(|spend| CanonicalField::from_bytes(spend.nullifier.0).is_none())
        {
            return Err(TransactionError::NonCanonicalNullifier);
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(TransactionError::TooManyOutputs);
        }
        if self
            .spends
            .iter()
            .map(|spend| &spend.value_commitment)
            .chain(self.outputs.iter().map(|output| &output.value_commitment))
            .any(|bytes| !valid_nonidentity_point(bytes))
        {
            return Err(TransactionError::InvalidValueCommitment);
        }
        if self.programs.len() > MAX_PROGRAMS {
            return Err(TransactionError::TooManyPrograms);
        }
        if self.outputs.iter().any(|output| {
            output.ciphertext.len() > MAX_CIPHERTEXT_BYTES
                || output.outgoing_ciphertext.len() > MAX_OUT_CIPHERTEXT_BYTES
        }) {
            return Err(TransactionError::CiphertextTooLarge);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(ONYX_TRANSACTION_VERSION);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.anchor.bytes());
        write_varint(self.expiry_height, &mut out);
        write_varint(self.fee, &mut out);
        write_varint(self.spends.len() as u64, &mut out);
        for spend in &self.spends {
            out.extend_from_slice(&spend.nullifier.0);
            out.extend_from_slice(&spend.value_commitment);
            out.extend_from_slice(&spend.randomized_key);
        }
        write_varint(self.outputs.len() as u64, &mut out);
        for output in &self.outputs {
            write_public_output(output, &mut out);
        }
        write_varint(self.programs.len() as u64, &mut out);
        for program in &self.programs {
            out.extend_from_slice(&program.program_id);
            write_varint(program.function_id.into(), &mut out);
            out.extend_from_slice(&program.public_data_hash);
        }
        Ok(out)
    }

    /// Stable note-encryption context. Ephemeral keys and ciphertexts are excluded to avoid a
    /// construction cycle; associated data binds them separately together with output index and
    /// commitment. Program identifiers and functions are included, but contextual public-data
    /// hashes are finalized after ciphertext construction and are authenticated by transaction
    /// authorization plus the program proof.
    pub fn encryption_binding(&self) -> Result<[u8; 32], TransactionError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.push(ONYX_TRANSACTION_VERSION);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.anchor.bytes());
        write_varint(self.expiry_height, &mut bytes);
        write_varint(self.fee, &mut bytes);
        write_varint(self.spends.len() as u64, &mut bytes);
        for spend in &self.spends {
            bytes.extend_from_slice(&spend.nullifier.0);
            bytes.extend_from_slice(&spend.value_commitment);
            bytes.extend_from_slice(&spend.randomized_key);
        }
        write_varint(self.outputs.len() as u64, &mut bytes);
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.bytes());
            bytes.extend_from_slice(&output.value_commitment);
        }
        write_varint(self.programs.len() as u64, &mut bytes);
        for program in &self.programs {
            bytes.extend_from_slice(&program.program_id);
            write_varint(program.function_id.into(), &mut bytes);
        }
        let mut hash = Sha256::new();
        hash.update(ENCRYPTION_BINDING_DOMAIN);
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    pub fn decode(input: &[u8]) -> Result<Self, TransactionError> {
        let mut reader = Reader::new(input);
        if reader.byte()? != ONYX_TRANSACTION_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let network_id = reader.array()?;
        let anchor = reader.field()?;
        let expiry_height = reader.varint()?;
        let fee = reader.varint()?;

        let spend_count = bounded_count(
            reader.varint()?,
            MAX_SPENDS,
            TransactionError::TooManySpends,
        )?;
        let mut spends = Vec::with_capacity(spend_count);
        for _ in 0..spend_count {
            spends.push(PublicSpend {
                nullifier: Nullifier(reader.array()?),
                value_commitment: reader.array()?,
                randomized_key: reader.array()?,
            });
        }

        let output_count = bounded_count(
            reader.varint()?,
            MAX_OUTPUTS,
            TransactionError::TooManyOutputs,
        )?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(read_public_output(&mut reader)?);
        }

        let program_count = bounded_count(
            reader.varint()?,
            MAX_PROGRAMS,
            TransactionError::TooManyPrograms,
        )?;
        let mut programs = Vec::with_capacity(program_count);
        for _ in 0..program_count {
            let program_id = reader.array()?;
            let function = reader.varint()?;
            if function > u32::MAX.into() {
                return Err(DecodeError::VarintOverflow.into());
            }
            programs.push(ProgramCall {
                program_id,
                function_id: function as u32,
                public_data_hash: reader.array()?,
            });
        }
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let tx = Self {
            network_id,
            anchor,
            expiry_height,
            fee,
            spends,
            outputs,
            programs,
        };
        tx.validate()?;
        Ok(tx)
    }
}

pub(crate) fn valid_nonidentity_point(bytes: &[u8; 32]) -> bool {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
        .map(|point| bool::from(point.to_affine().coordinates().is_some()))
        .unwrap_or(false)
}

pub(crate) fn validate_public_output(output: &PublicOutput) -> Result<(), TransactionError> {
    if !valid_nonidentity_point(&output.value_commitment) {
        return Err(TransactionError::InvalidValueCommitment);
    }
    if output.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || output.outgoing_ciphertext.len() > MAX_OUT_CIPHERTEXT_BYTES
    {
        return Err(TransactionError::CiphertextTooLarge);
    }
    Ok(())
}

pub(crate) fn write_public_output(output: &PublicOutput, out: &mut Vec<u8>) {
    out.extend_from_slice(&output.commitment.bytes());
    out.extend_from_slice(&output.value_commitment);
    out.extend_from_slice(&output.ephemeral_key);
    write_bytes(&output.ciphertext, out);
    write_bytes(&output.outgoing_ciphertext, out);
}

pub(crate) fn read_public_output(
    reader: &mut Reader<'_>,
) -> Result<PublicOutput, TransactionError> {
    let output = PublicOutput {
        commitment: reader.field()?,
        value_commitment: reader.array()?,
        ephemeral_key: reader.array()?,
        ciphertext: read_bytes(reader, MAX_CIPHERTEXT_BYTES)?,
        outgoing_ciphertext: read_bytes(reader, MAX_OUT_CIPHERTEXT_BYTES)?,
    };
    validate_public_output(&output)?;
    Ok(output)
}

impl AuthorizedTransaction {
    fn validate(&self) -> Result<(), TransactionError> {
        self.preimage.validate()?;
        if self.backend_id.is_empty()
            || self.backend_id.len() > MAX_BACKEND_ID_BYTES
            || !self.backend_id.is_ascii()
        {
            return Err(TransactionError::InvalidBackendId);
        }
        if self.proof.len() > MAX_PROOF_BYTES {
            return Err(TransactionError::ProofTooLarge);
        }
        if self.spend_signatures.len() != self.preimage.spends.len() {
            return Err(TransactionError::WrongSignatureCount);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        self.validate()?;
        let preimage = self.preimage.encode()?;
        let mut out = Vec::with_capacity(
            preimage.len()
                + self.backend_id.len()
                + self.proof.len()
                + self.spend_signatures.len() * 64
                + 32,
        );
        write_bytes(&preimage, &mut out);
        write_bytes(self.backend_id.as_bytes(), &mut out);
        write_bytes(&self.proof, &mut out);
        write_varint(self.spend_signatures.len() as u64, &mut out);
        for signature in &self.spend_signatures {
            out.extend_from_slice(signature);
        }
        out.extend_from_slice(&self.binding_signature);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TransactionError> {
        let mut reader = Reader::new(input);
        let preimage_bytes = read_bounded_bytes(
            &mut reader,
            256 * 1024,
            TransactionError::CiphertextTooLarge,
        )?;
        let preimage = TransactionPreimage::decode(&preimage_bytes)?;
        let backend_bytes = read_bounded_bytes(
            &mut reader,
            MAX_BACKEND_ID_BYTES,
            TransactionError::InvalidBackendId,
        )?;
        let backend_id =
            String::from_utf8(backend_bytes).map_err(|_| TransactionError::InvalidBackendId)?;
        let proof = read_bounded_bytes(
            &mut reader,
            MAX_PROOF_BYTES,
            TransactionError::ProofTooLarge,
        )?;
        let signature_count = bounded_count(
            reader.varint()?,
            MAX_SPENDS,
            TransactionError::WrongSignatureCount,
        )?;
        let mut spend_signatures = Vec::with_capacity(signature_count);
        for _ in 0..signature_count {
            spend_signatures.push(reader.array()?);
        }
        let binding_signature = reader.array()?;
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let transaction = Self {
            preimage,
            backend_id,
            proof,
            spend_signatures,
            binding_signature,
        };
        transaction.validate()?;
        Ok(transaction)
    }

    pub fn id(&self) -> Result<[u8; 32], TransactionError> {
        let encoding = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(TRANSACTION_ID_DOMAIN);
        hash.update((encoding.len() as u64).to_le_bytes());
        hash.update(encoding);
        Ok(hash.finalize().into())
    }
}

fn bounded_count(
    value: u64,
    limit: usize,
    error: TransactionError,
) -> Result<usize, TransactionError> {
    if value > limit as u64 {
        Err(error)
    } else {
        Ok(value as usize)
    }
}

pub(crate) fn write_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

pub(crate) fn read_bytes(
    reader: &mut Reader<'_>,
    limit: usize,
) -> Result<Vec<u8>, TransactionError> {
    read_bounded_bytes(reader, limit, TransactionError::CiphertextTooLarge)
}

fn read_bounded_bytes(
    reader: &mut Reader<'_>,
    limit: usize,
    error: TransactionError,
) -> Result<Vec<u8>, TransactionError> {
    let count = reader.varint()?;
    if count > limit as u64 {
        return Err(error);
    }
    Ok(reader.take(count as usize)?.to_vec())
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_proofs::pasta::Fp;

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
                    Fp::from(2),
                ),
                randomized_key: [4; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: field(5),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    Fp::from(3),
                ),
                ephemeral_key: [6; 32],
                ciphertext: vec![7; 48],
                outgoing_ciphertext: vec![8; 32],
            }],
            programs: vec![ProgramCall {
                program_id: [9; 32],
                function_id: 10,
                public_data_hash: [11; 32],
            }],
        }
    }

    #[test]
    fn public_statement_round_trips() {
        let tx = transaction();
        assert_eq!(TransactionPreimage::decode(&tx.encode().unwrap()), Ok(tx));
    }

    #[test]
    fn encryption_binding_is_stable_and_non_circular() {
        let tx = transaction();
        let binding = tx.encryption_binding().unwrap();
        let mut ciphertext = tx.clone();
        ciphertext.outputs[0].ciphertext[0] ^= 1;
        ciphertext.outputs[0].ephemeral_key[0] ^= 1;
        assert_eq!(ciphertext.encryption_binding().unwrap(), binding);
        let mut contextual_hash = ciphertext.clone();
        contextual_hash.programs[0].public_data_hash[0] ^= 1;
        assert_eq!(contextual_hash.encryption_binding().unwrap(), binding);
        contextual_hash.programs[0].program_id[0] ^= 1;
        assert_ne!(contextual_hash.encryption_binding().unwrap(), binding);
        let mut commitment = tx;
        commitment.outputs[0].commitment = field(12);
        assert_ne!(commitment.encryption_binding().unwrap(), binding);
    }

    #[test]
    fn public_statement_rejects_trailing_and_unknown_version() {
        let mut encoded = transaction().encode().unwrap();
        encoded.push(0);
        assert_eq!(
            TransactionPreimage::decode(&encoded),
            Err(TransactionError::Decode(DecodeError::TrailingData))
        );
        encoded = transaction().encode().unwrap();
        encoded[0] += 1;
        assert_eq!(
            TransactionPreimage::decode(&encoded),
            Err(TransactionError::Decode(DecodeError::WrongVersion))
        );
    }

    #[test]
    fn public_statement_enforces_limits_before_allocation() {
        let mut tx = transaction();
        tx.spends = (0..=MAX_SPENDS)
            .map(|value| PublicSpend {
                nullifier: Nullifier([value as u8; 32]),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    Fp::from(value as u64 + 1),
                ),
                randomized_key: [value as u8; 32],
            })
            .collect();
        assert_eq!(tx.encode(), Err(TransactionError::TooManySpends));

        tx = transaction();
        tx.outputs[0].ciphertext = vec![0; MAX_CIPHERTEXT_BYTES + 1];
        assert_eq!(tx.encode(), Err(TransactionError::CiphertextTooLarge));
    }

    #[test]
    fn empty_statement_is_rejected() {
        let mut tx = transaction();
        tx.spends.clear();
        tx.outputs.clear();
        assert_eq!(tx.encode(), Err(TransactionError::EmptyTransaction));
    }

    #[test]
    fn public_statement_rejects_noncanonical_nullifier() {
        let mut tx = transaction();
        tx.spends[0].nullifier = Nullifier([0xff; 32]);
        assert_eq!(tx.encode(), Err(TransactionError::NonCanonicalNullifier));
    }

    #[test]
    fn public_statement_rejects_invalid_value_commitments() {
        let mut tx = transaction();
        tx.outputs[0].value_commitment = [0xff; 32];
        assert_eq!(tx.encode(), Err(TransactionError::InvalidValueCommitment));
        tx = transaction();
        tx.spends[0].value_commitment = [0; 32];
        assert_eq!(tx.encode(), Err(TransactionError::InvalidValueCommitment));
    }

    #[test]
    fn authorized_transaction_round_trip_and_id_bind_every_byte() {
        let mut preimage = transaction();
        preimage.spends[0].randomized_key = [12; 32];
        let transaction = AuthorizedTransaction {
            preimage,
            backend_id: "halo2-ipa-pasta-v1".to_owned(),
            proof: vec![13; 96],
            spend_signatures: vec![[14; 64]],
            binding_signature: [15; 64],
        };
        let encoded = transaction.encode().unwrap();
        assert_eq!(
            AuthorizedTransaction::decode(&encoded),
            Ok(transaction.clone())
        );
        let id = transaction.id().unwrap();
        let mut changed = transaction;
        changed.proof[0] ^= 1;
        assert_ne!(id, changed.id().unwrap());
    }

    #[test]
    fn authorized_transaction_rejects_unbounded_or_mismatched_fields() {
        let mut transaction = AuthorizedTransaction {
            preimage: transaction(),
            backend_id: "halo2".to_owned(),
            proof: vec![],
            spend_signatures: vec![],
            binding_signature: [0; 64],
        };
        assert_eq!(
            transaction.encode(),
            Err(TransactionError::WrongSignatureCount)
        );
        transaction.spend_signatures.push([0; 64]);
        transaction.backend_id.clear();
        assert_eq!(
            transaction.encode(),
            Err(TransactionError::InvalidBackendId)
        );
        transaction.backend_id = "halo2".to_owned();
        transaction.proof = vec![0; MAX_PROOF_BYTES + 1];
        assert_eq!(transaction.encode(), Err(TransactionError::ProofTooLarge));
    }
}
