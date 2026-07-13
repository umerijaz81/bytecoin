//! Canonical Onyx O1 note encodings and deterministic identifiers.

use ff::PrimeField;
use group::{Curve, GroupEncoding};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_proofs::pasta::Fp;
use pasta_curves::{arithmetic::CurveAffine, pallas};

use crate::state::{CanonicalField, Nullifier};

pub const ONYX_NOTE_VERSION: u8 = 1;
pub const NETWORK_ID_BYTES: usize = 16;
pub const DIVERSIFIER_BYTES: usize = 11;
pub const MAX_MEMO_BYTES: usize = 4096;
pub const NATIVE_ASSET_ID: [u8; 32] = [
    0x7d, 0x34, 0x23, 0x48, 0x2b, 0x6e, 0x8a, 0x24, 0x2f, 0xc0, 0xe5, 0xa2, 0xf6, 0xa5, 0x4b, 0x36,
    0xcf, 0x4f, 0x03, 0x42, 0xa9, 0x53, 0xea, 0x93, 0xec, 0x70, 0x25, 0xcd, 0x7c, 0x95, 0x5b, 0xe3,
];
const NOTE_TAG: u64 = 4;
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
    InvalidSpendAuthorityKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotePlaintext {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub program_id: [u8; 32],
    pub asset_id: [u8; 32],
    pub value: u64,
    pub diversifier: [u8; DIVERSIFIER_BYTES],
    pub transmission_key: [u8; 32],
    pub spend_authority_key: [u8; 32],
    pub rho: CanonicalField,
    pub randomness: CanonicalField,
    pub memo: Vec<u8>,
}

impl NotePlaintext {
    pub fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        if self.memo.len() > MAX_MEMO_BYTES {
            return Err(DecodeError::MemoTooLarge);
        }
        self.spend_authority_coordinates()?;
        let mut out = Vec::with_capacity(190 + self.memo.len());
        out.push(ONYX_NOTE_VERSION);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.program_id);
        out.extend_from_slice(&self.asset_id);
        write_varint(self.value, &mut out);
        out.extend_from_slice(&self.diversifier);
        out.extend_from_slice(&self.transmission_key);
        out.extend_from_slice(&self.spend_authority_key);
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
        let transmission_key = reader.array()?;
        let spend_authority_key = reader.array()?;
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
        let note = Self {
            network_id,
            program_id,
            asset_id,
            value,
            diversifier,
            transmission_key,
            spend_authority_key,
            rho,
            randomness,
            memo,
        };
        note.spend_authority_coordinates()?;
        Ok(note)
    }

    pub fn commitment(&self) -> Result<CanonicalField, DecodeError> {
        let inputs = self.commitment_inputs()?;
        Ok(CanonicalField::from_field(
            PoseidonHash::<Fp, P128Pow5T3, ConstantLength<14>, 3, 2>::init().hash(inputs),
        ))
    }

    pub fn commitment_inputs(&self) -> Result<[Fp; 14], DecodeError> {
        let program = pack_32(&self.program_id);
        let asset = pack_32(&self.asset_id);
        let transmission = pack_32(&self.transmission_key);
        let spend_authority = self.spend_authority_coordinates()?;
        Ok([
            Fp::from(NOTE_TAG),
            pack_short(&self.network_id),
            program[0],
            program[1],
            asset[0],
            asset[1],
            Fp::from(self.value),
            pack_short(&self.diversifier),
            transmission[0],
            transmission[1],
            spend_authority[0],
            spend_authority[1],
            self.rho.field(),
            self.randomness.field(),
        ])
    }

    pub fn spend_authority_coordinates(&self) -> Result<[Fp; 2], DecodeError> {
        let point =
            Option::<pallas::Point>::from(pallas::Point::from_bytes(&self.spend_authority_key))
                .ok_or(DecodeError::InvalidSpendAuthorityKey)?
                .to_affine();
        let coordinates = point.coordinates();
        if bool::from(coordinates.is_none()) {
            return Err(DecodeError::InvalidSpendAuthorityKey);
        }
        let coordinates = coordinates.unwrap();
        Ok([*coordinates.x(), *coordinates.y()])
    }

    pub fn nullifier(&self, nullifier_key: CanonicalField, position: u64) -> Nullifier {
        let inner = poseidon2(nullifier_key.field(), self.rho.field());
        let positioned = poseidon2(inner, Fp::from(position));
        Nullifier(poseidon2(Fp::from(NULLIFIER_TAG), positioned).to_repr())
    }
}

fn pack_32(bytes: &[u8; 32]) -> [Fp; 2] {
    [pack_short(&bytes[..31]), pack_short(&bytes[31..])]
}

pub(crate) fn native_asset_fields() -> [Fp; 2] {
    pack_32(&NATIVE_ASSET_ID)
}

pub(crate) fn network_field(network_id: &[u8; NETWORK_ID_BYTES]) -> Fp {
    pack_short(network_id)
}

fn pack_short(bytes: &[u8]) -> Fp {
    assert!(bytes.len() <= 31);
    let mut representation = [0u8; 32];
    representation[..bytes.len()].copy_from_slice(bytes);
    Option::<Fp>::from(Fp::from_repr(representation)).expect("31-byte value is canonical")
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
            transmission_key: [5; 32],
            spend_authority_key: [
                99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68,
                95, 62, 124, 24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
            ],
            rho: CanonicalField::from_field(Fp::from(6)),
            randomness: CanonicalField::from_field(Fp::from(7)),
            memo: b"onyx".to_vec(),
        }
    }

    #[test]
    fn note_round_trip_and_commitment_bind_consensus_fields() {
        let note = note();
        let encoded = note.encode().unwrap();
        assert_eq!(NotePlaintext::decode(&encoded), Ok(note.clone()));
        let commitment = note.commitment().unwrap();
        assert_eq!(
            hex(&commitment.bytes()),
            "971ffe49dde4e2b5f6ae85f917c44b962dfbd27ae05cb1f550307a4881177f0d"
        );
        let mut changed = note.clone();
        changed.value += 1;
        assert_ne!(commitment, changed.commitment().unwrap());
        changed = note;
        changed.memo.push(0);
        assert_eq!(commitment, changed.commitment().unwrap());
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
        let rho_offset = 1 + NETWORK_ID_BYTES + 32 + 32 + 1 + DIVERSIFIER_BYTES + 32 + 32;
        encoded[rho_offset..rho_offset + 32].fill(0xff);
        assert_eq!(
            NotePlaintext::decode(&encoded),
            Err(DecodeError::NonCanonicalField)
        );

        let mut oversized = note();
        oversized.memo = vec![0; MAX_MEMO_BYTES + 1];
        assert_eq!(oversized.encode(), Err(DecodeError::MemoTooLarge));

        let mut invalid_authority = note();
        invalid_authority.spend_authority_key = [0xff; 32];
        assert_eq!(
            invalid_authority.encode(),
            Err(DecodeError::InvalidSpendAuthorityKey)
        );
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
