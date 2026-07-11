//! Canonical Onyx O1 note encodings and deterministic identifiers.

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_gadgets::sinsemilla::primitives::HashDomain;
use halo2_proofs::pasta::Fp;

use crate::state::{CanonicalField, Nullifier};

pub const ONYX_NOTE_VERSION: u8 = 1;
pub const NETWORK_ID_BYTES: usize = 16;
pub const DIVERSIFIER_BYTES: usize = 11;
pub const MAX_MEMO_BYTES: usize = 4096;
const NOTE_DOMAIN: &str = "bytecoin.onyx.v6.note";
const NULLIFIER_TAG: u64 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    TrailingData,
    WrongVersion,
    NonCanonicalField,
    NonMinimalVarint,
    VarintOverflow,
    MemoTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotePlaintext {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub program_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub value: u64,
    pub diversifier: [u8; DIVERSIFIER_BYTES],
    pub transmission_key: CanonicalField,
    pub rho: CanonicalField,
    pub randomness: CanonicalField,
    pub memo: Vec<u8>,
}

impl NotePlaintext {
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        if self.memo.len() > MAX_MEMO_BYTES {
            return Err(DecodeError::MemoTooLarge);
        }
        let mut out = Vec::with_capacity(190 + self.memo.len());
        out.push(ONYX_NOTE_VERSION);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.program_id);
        out.extend_from_slice(&self.asset_id);
        write_varint(self.value, &mut out);
        out.extend_from_slice(&self.diversifier);
        out.extend_from_slice(&self.transmission_key.bytes());
        out.extend_from_slice(&self.rho.bytes());
        out.extend_from_slice(&self.randomness.bytes());
        write_varint(self.memo.len() as u64, &mut out);
        out.extend_from_slice(&self.memo);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(input);
        if reader.byte()? != ONYX_NOTE_VERSION {
            return Err(DecodeError::WrongVersion);
        }
        let network_id = reader.array()?;
        let program_id = reader.array()?;
        let asset_id = reader.array()?;
        let value = reader.varint()?;
        let diversifier = reader.array()?;
        let transmission_key = reader.field()?;
        let rho = reader.field()?;
        let randomness = reader.field()?;
        let memo_len = reader.varint()?;
        if memo_len > MAX_MEMO_BYTES as u64 {
            return Err(DecodeError::MemoTooLarge);
        }
        let memo = reader.take(memo_len as usize)?.to_vec();
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData);
        }
        Ok(Self {
            network_id,
            program_id,
            asset_id,
            value,
            diversifier,
            transmission_key,
            rho,
            randomness,
            memo,
        })
    }

    pub fn commitment(&self) -> Result<CanonicalField, DecodeError> {
        let encoding = self.encode()?;
        let bits = encoding
            .iter()
            .flat_map(|byte| (0..8).map(move |bit| ((byte >> bit) & 1) == 1));
        let point = HashDomain::new(NOTE_DOMAIN)
            .hash(bits)
            .into_option()
            .ok_or(DecodeError::NonCanonicalField)?;
        Ok(CanonicalField::from_field(point))
    }

    pub fn nullifier(&self, nullifier_key: CanonicalField, position: u64) -> Nullifier {
        let inner = poseidon2(nullifier_key.field(), self.rho.field());
        let positioned = poseidon2(inner, Fp::from(position));
        Nullifier(poseidon2(Fp::from(NULLIFIER_TAG), positioned).to_repr())
    }
}

fn poseidon2(a: Fp, b: Fp) -> Fp {
    PoseidonHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

pub(crate) fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub(crate) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { remaining: input }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining.len() < count {
            return Err(DecodeError::Truncated);
        }
        let (value, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        Ok(value)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?.try_into().map_err(|_| DecodeError::Truncated)
    }

    pub(crate) fn field(&mut self) -> Result<CanonicalField, DecodeError> {
        CanonicalField::from_bytes(self.array()?).ok_or(DecodeError::NonCanonicalField)
    }

    pub(crate) fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.byte()?;
            if index == 9 && byte > 1 {
                return Err(DecodeError::VarintOverflow);
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && byte == 0 {
                    return Err(DecodeError::NonMinimalVarint);
                }
                return Ok(value);
            }
        }
        Err(DecodeError::VarintOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note() -> NotePlaintext {
        NotePlaintext {
            network_id: [1; NETWORK_ID_BYTES],
            program_id: [2; 32],
            asset_id: [3; 32],
            value: 42,
            diversifier: [4; DIVERSIFIER_BYTES],
            transmission_key: CanonicalField::from_field(Fp::from(5)),
            rho: CanonicalField::from_field(Fp::from(6)),
            randomness: CanonicalField::from_field(Fp::from(7)),
            memo: b"onyx".to_vec(),
        }
    }

    #[test]
    fn note_round_trip_and_commitment_bind_every_field() {
        let note = note();
        let encoded = note.encode().unwrap();
        assert_eq!(NotePlaintext::decode(&encoded), Ok(note.clone()));
        let commitment = note.commitment().unwrap();
        assert_eq!(
            hex(&commitment.bytes()),
            "cb3ce323c4c91231ed6349a53aa8e08b4d4d8a8e00fb8c62e2fe447b5e243b28"
        );
        let mut changed = note;
        changed.value += 1;
        assert_ne!(commitment, changed.commitment().unwrap());
    }

    #[test]
    fn parser_rejects_truncation_trailing_and_unknown_version() {
        let encoded = note().encode().unwrap();
        assert_eq!(
            NotePlaintext::decode(&encoded[..encoded.len() - 1]),
            Err(DecodeError::Truncated)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            NotePlaintext::decode(&trailing),
            Err(DecodeError::TrailingData)
        );
        let mut unknown = encoded;
        unknown[0] = ONYX_NOTE_VERSION + 1;
        assert_eq!(
            NotePlaintext::decode(&unknown),
            Err(DecodeError::WrongVersion)
        );
    }

    #[test]
    fn parser_rejects_noncanonical_field_and_oversized_memo() {
        let mut encoded = note().encode().unwrap();
        let transmission_offset = 1 + NETWORK_ID_BYTES + 32 + 32 + 1 + DIVERSIFIER_BYTES;
        encoded[transmission_offset..transmission_offset + 32].fill(0xff);
        assert_eq!(
            NotePlaintext::decode(&encoded),
            Err(DecodeError::NonCanonicalField)
        );

        let mut oversized = note();
        oversized.memo = vec![0; MAX_MEMO_BYTES + 1];
        assert_eq!(oversized.encode(), Err(DecodeError::MemoTooLarge));
    }

    #[test]
    fn parser_rejects_nonminimal_varint() {
        let encoded = note().encode().unwrap();
        let value_offset = 1 + NETWORK_ID_BYTES + 32 + 32;
        let mut nonminimal = encoded[..value_offset].to_vec();
        nonminimal.extend_from_slice(&[0xaa, 0x00]);
        nonminimal.extend_from_slice(&encoded[value_offset + 1..]);
        assert_eq!(
            NotePlaintext::decode(&nonminimal),
            Err(DecodeError::NonMinimalVarint)
        );
    }

    #[test]
    fn nullifier_binds_key_rho_and_position() {
        let note = note();
        let key = CanonicalField::from_field(Fp::from(9));
        let nf = note.nullifier(key, 10);
        assert_eq!(
            hex(&nf.0),
            "dd2257dec1598f87b930c8f3a9973ee6d1bf0b3e0b2402473516377831eea203"
        );
        assert_ne!(nf, note.nullifier(key, 11));
        assert_ne!(
            nf,
            note.nullifier(CanonicalField::from_field(Fp::from(10)), 10)
        );
        let mut changed = note;
        changed.rho = CanonicalField::from_field(Fp::from(11));
        assert_ne!(nf, changed.nullifier(key, 10));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
