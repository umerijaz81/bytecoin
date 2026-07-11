//! Canonical public statement for Onyx transactions.

use crate::state::{CanonicalField, Nullifier};
use crate::types::{write_varint, DecodeError, Reader, NETWORK_ID_BYTES};

pub const ONYX_TRANSACTION_VERSION: u8 = 6;
pub const MAX_SPENDS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_PROGRAMS: usize = 8;
pub const MAX_CIPHERTEXT_BYTES: usize = 4096;
pub const MAX_OUT_CIPHERTEXT_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSpend {
    pub nullifier: Nullifier,
    pub randomized_key: CanonicalField,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicOutput {
    pub commitment: CanonicalField,
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
pub enum TransactionError {
    Decode(DecodeError),
    TooManySpends,
    TooManyOutputs,
    TooManyPrograms,
    CiphertextTooLarge,
    EmptyTransaction,
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
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(TransactionError::TooManyOutputs);
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
            out.extend_from_slice(&spend.randomized_key.bytes());
        }
        write_varint(self.outputs.len() as u64, &mut out);
        for output in &self.outputs {
            out.extend_from_slice(&output.commitment.bytes());
            out.extend_from_slice(&output.ephemeral_key);
            write_bytes(&output.ciphertext, &mut out);
            write_bytes(&output.outgoing_ciphertext, &mut out);
        }
        write_varint(self.programs.len() as u64, &mut out);
        for program in &self.programs {
            out.extend_from_slice(&program.program_id);
            write_varint(program.function_id.into(), &mut out);
            out.extend_from_slice(&program.public_data_hash);
        }
        Ok(out)
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
                randomized_key: reader.field()?,
            });
        }

        let output_count = bounded_count(
            reader.varint()?,
            MAX_OUTPUTS,
            TransactionError::TooManyOutputs,
        )?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            let commitment = reader.field()?;
            let ephemeral_key = reader.array()?;
            let ciphertext = read_bytes(&mut reader, MAX_CIPHERTEXT_BYTES)?;
            let outgoing_ciphertext = read_bytes(&mut reader, MAX_OUT_CIPHERTEXT_BYTES)?;
            outputs.push(PublicOutput {
                commitment,
                ephemeral_key,
                ciphertext,
                outgoing_ciphertext,
            });
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

fn write_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn read_bytes(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<u8>, TransactionError> {
    let count = reader.varint()?;
    if count > limit as u64 {
        return Err(TransactionError::CiphertextTooLarge);
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
                randomized_key: field(4),
            }],
            outputs: vec![PublicOutput {
                commitment: field(5),
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
                randomized_key: field(value as u64),
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
}
