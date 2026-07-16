//! Canonical, non-circular public context for stateful Onyx program calls.

use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

use crate::state::CanonicalField;
use crate::transaction::{write_public_output, ProgramCall, TransactionPreimage, MAX_PROGRAMS};
use crate::types::{network_field, pack_32, write_varint, DecodeError, Reader, NETWORK_ID_BYTES};

pub const PROGRAM_CONTEXT_VERSION: u8 = 1;
pub const MAX_PROGRAM_PUBLIC_DATA_BYTES: usize = 4096;
pub const PROGRAM_CONTEXT_PUBLIC_INPUT_COUNT: usize = 22;
pub const PROGRAM_CONTEXT_SCHEMA_HASH: [u8; 32] = [
    0x05, 0xb9, 0xfa, 0xf1, 0x49, 0xf9, 0xfa, 0x69, 0xd9, 0x41, 0x53, 0xd2, 0xf2, 0x2c, 0xe8, 0x5b,
    0xd5, 0x15, 0x28, 0x25, 0x6f, 0x0e, 0x25, 0xf1, 0x5a, 0x1e, 0xdf, 0xbd, 0x1a, 0xd5, 0xe9, 0x41,
];
const CONTEXT_HASH_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.v1";
const PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.public-data.v1";
pub const PROGRAM_CONTEXT_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.schema.v1";
pub const PROGRAM_CONTEXT_PUBLIC_INPUT_SCHEMA: &[u8] = b"network:field,anchor:field,valid_from:u64,expiry:u64,fee:u64,call_index:u8,program:field[2],function:u32,spends:field[2],outputs:field[2],calls:field[2],has_state:bool,prior:field[2],next:field[2],application:field[2]";
const SPENDS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.spends.v1";
const OUTPUTS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.outputs.v1";
const CALLS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.calls.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramStateTransition {
    pub prior: [u8; 32],
    pub next: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramContext {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub anchor: [u8; 32],
    pub valid_from_height: u64,
    pub expiry_height: u64,
    pub fee: u64,
    pub call_index: u8,
    pub program_id: [u8; 32],
    pub function_id: u32,
    pub spends_digest: [u8; 32],
    pub outputs_digest: [u8; 32],
    pub call_headers_digest: [u8; 32],
    pub state: Option<ProgramStateTransition>,
    pub application_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramContextError {
    Decode(DecodeError),
    InvalidCall,
    InvalidHeightWindow,
    PublicDataTooLarge,
    Transaction,
    BindingMismatch,
}

impl From<DecodeError> for ProgramContextError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl ProgramContext {
    pub fn from_transaction(
        transaction: &TransactionPreimage,
        call_index: usize,
        valid_from_height: u64,
        state: Option<ProgramStateTransition>,
        application_data: Vec<u8>,
    ) -> Result<Self, ProgramContextError> {
        transaction
            .encode()
            .map_err(|_| ProgramContextError::Transaction)?;
        let call = transaction
            .programs
            .get(call_index)
            .ok_or(ProgramContextError::InvalidCall)?;
        if call_index >= MAX_PROGRAMS || valid_from_height > transaction.expiry_height {
            return Err(ProgramContextError::InvalidHeightWindow);
        }
        if application_data.len() > MAX_PROGRAM_PUBLIC_DATA_BYTES {
            return Err(ProgramContextError::PublicDataTooLarge);
        }
        Ok(Self {
            network_id: transaction.network_id,
            anchor: transaction.anchor.bytes(),
            valid_from_height,
            expiry_height: transaction.expiry_height,
            fee: transaction.fee,
            call_index: call_index as u8,
            program_id: call.program_id,
            function_id: call.function_id,
            spends_digest: spends_digest(transaction),
            outputs_digest: outputs_digest(transaction),
            call_headers_digest: call_headers_digest(&transaction.programs),
            state,
            application_data,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProgramContextError> {
        if self.application_data.len() > MAX_PROGRAM_PUBLIC_DATA_BYTES {
            return Err(ProgramContextError::PublicDataTooLarge);
        }
        if usize::from(self.call_index) >= MAX_PROGRAMS
            || self.valid_from_height > self.expiry_height
        {
            return Err(ProgramContextError::InvalidHeightWindow);
        }
        if CanonicalField::from_bytes(self.anchor).is_none() {
            return Err(ProgramContextError::Decode(DecodeError::NonCanonicalField));
        }
        let mut out = Vec::with_capacity(224 + self.application_data.len());
        out.push(PROGRAM_CONTEXT_VERSION);
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.anchor);
        write_varint(self.valid_from_height, &mut out);
        write_varint(self.expiry_height, &mut out);
        write_varint(self.fee, &mut out);
        write_varint(self.call_index.into(), &mut out);
        out.extend_from_slice(&self.program_id);
        write_varint(self.function_id.into(), &mut out);
        out.extend_from_slice(&self.spends_digest);
        out.extend_from_slice(&self.outputs_digest);
        out.extend_from_slice(&self.call_headers_digest);
        match &self.state {
            None => out.push(0),
            Some(state) => {
                out.push(1);
                out.extend_from_slice(&state.prior);
                out.extend_from_slice(&state.next);
            }
        }
        write_varint(self.application_data.len() as u64, &mut out);
        out.extend_from_slice(&self.application_data);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProgramContextError> {
        let mut reader = Reader::new(input);
        if reader.byte()? != PROGRAM_CONTEXT_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let network_id = reader.array()?;
        let anchor = reader.array()?;
        if CanonicalField::from_bytes(anchor).is_none() {
            return Err(DecodeError::NonCanonicalField.into());
        }
        let valid_from_height = reader.varint()?;
        let expiry_height = reader.varint()?;
        let fee = reader.varint()?;
        let call_index = reader.varint()?;
        if call_index >= MAX_PROGRAMS as u64 {
            return Err(ProgramContextError::InvalidCall);
        }
        let program_id = reader.array()?;
        let function_id = reader.varint()?;
        if function_id > u32::MAX.into() {
            return Err(ProgramContextError::InvalidCall);
        }
        let spends_digest = reader.array()?;
        let outputs_digest = reader.array()?;
        let call_headers_digest = reader.array()?;
        let state = match reader.byte()? {
            0 => None,
            1 => Some(ProgramStateTransition {
                prior: reader.array()?,
                next: reader.array()?,
            }),
            _ => return Err(ProgramContextError::InvalidCall),
        };
        let application_length = reader.varint()?;
        if application_length > MAX_PROGRAM_PUBLIC_DATA_BYTES as u64 {
            return Err(ProgramContextError::PublicDataTooLarge);
        }
        let application_data = reader.take(application_length as usize)?.to_vec();
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let context = Self {
            network_id,
            anchor,
            valid_from_height,
            expiry_height,
            fee,
            call_index: call_index as u8,
            program_id,
            function_id: function_id as u32,
            spends_digest,
            outputs_digest,
            call_headers_digest,
            state,
            application_data,
        };
        context.encode()?;
        Ok(context)
    }

    pub fn hash(&self) -> Result<[u8; 32], ProgramContextError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(CONTEXT_HASH_DOMAIN);
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    /// Fixed circuit ABI. Arbitrary 32-byte identifiers are split into a canonical 31-byte limb and
    /// one-byte limb; absent state uses a false flag and four zero limbs.
    pub fn public_inputs(&self) -> Result<Vec<Fp>, ProgramContextError> {
        self.encode()?;
        let program = pack_32(&self.program_id);
        let spends = pack_32(&self.spends_digest);
        let outputs = pack_32(&self.outputs_digest);
        let calls = pack_32(&self.call_headers_digest);
        let (has_state, prior, next) = match &self.state {
            Some(state) => (Fp::one(), pack_32(&state.prior), pack_32(&state.next)),
            None => (Fp::zero(), [Fp::zero(); 2], [Fp::zero(); 2]),
        };
        let application = pack_32(&domain_hash(PUBLIC_DATA_DOMAIN, &self.application_data));
        let anchor = CanonicalField::from_bytes(self.anchor)
            .ok_or(ProgramContextError::Decode(DecodeError::NonCanonicalField))?
            .field();
        let inputs = vec![
            network_field(&self.network_id),
            anchor,
            Fp::from(self.valid_from_height),
            Fp::from(self.expiry_height),
            Fp::from(self.fee),
            Fp::from(u64::from(self.call_index)),
            program[0],
            program[1],
            Fp::from(u64::from(self.function_id)),
            spends[0],
            spends[1],
            outputs[0],
            outputs[1],
            calls[0],
            calls[1],
            has_state,
            prior[0],
            prior[1],
            next[0],
            next[1],
            application[0],
            application[1],
        ];
        debug_assert_eq!(inputs.len(), PROGRAM_CONTEXT_PUBLIC_INPUT_COUNT);
        Ok(inputs)
    }

    pub fn public_input_schema_hash() -> [u8; 32] {
        PROGRAM_CONTEXT_SCHEMA_HASH
    }

    #[cfg(test)]
    fn derived_public_input_schema_hash() -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(PROGRAM_CONTEXT_SCHEMA_DOMAIN);
        hash.update([PROGRAM_CONTEXT_VERSION]);
        hash.update((PROGRAM_CONTEXT_PUBLIC_INPUT_COUNT as u64).to_le_bytes());
        hash.update((PROGRAM_CONTEXT_PUBLIC_INPUT_SCHEMA.len() as u64).to_le_bytes());
        hash.update(PROGRAM_CONTEXT_PUBLIC_INPUT_SCHEMA);
        hash.finalize().into()
    }

    pub fn validate_binding(
        &self,
        transaction: &TransactionPreimage,
        block_height: u64,
    ) -> Result<(), ProgramContextError> {
        transaction
            .encode()
            .map_err(|_| ProgramContextError::Transaction)?;
        if block_height < self.valid_from_height || block_height > self.expiry_height {
            return Err(ProgramContextError::InvalidHeightWindow);
        }
        let call = transaction
            .programs
            .get(usize::from(self.call_index))
            .ok_or(ProgramContextError::InvalidCall)?;
        let matches = self.network_id == transaction.network_id
            && self.anchor == transaction.anchor.bytes()
            && self.expiry_height == transaction.expiry_height
            && self.fee == transaction.fee
            && self.program_id == call.program_id
            && self.function_id == call.function_id
            && self.spends_digest == spends_digest(transaction)
            && self.outputs_digest == outputs_digest(transaction)
            && self.call_headers_digest == call_headers_digest(&transaction.programs)
            && call.public_data_hash == self.hash()?;
        if matches {
            Ok(())
        } else {
            Err(ProgramContextError::BindingMismatch)
        }
    }
}

fn spends_digest(transaction: &TransactionPreimage) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(transaction.spends.len() * 96 + 8);
    write_varint(transaction.spends.len() as u64, &mut bytes);
    for spend in &transaction.spends {
        bytes.extend_from_slice(&spend.nullifier.0);
        bytes.extend_from_slice(&spend.value_commitment);
        bytes.extend_from_slice(&spend.randomized_key);
    }
    domain_hash(SPENDS_DOMAIN, &bytes)
}

fn outputs_digest(transaction: &TransactionPreimage) -> [u8; 32] {
    let mut bytes = Vec::new();
    write_varint(transaction.outputs.len() as u64, &mut bytes);
    for output in &transaction.outputs {
        write_public_output(output, &mut bytes);
    }
    domain_hash(OUTPUTS_DOMAIN, &bytes)
}

fn call_headers_digest(calls: &[ProgramCall]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(calls.len() * 40 + 8);
    write_varint(calls.len() as u64, &mut bytes);
    for call in calls {
        bytes.extend_from_slice(&call.program_id);
        write_varint(call.function_id.into(), &mut bytes);
    }
    domain_hash(CALLS_DOMAIN, &bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_proofs::pasta::Fp;

    use super::*;
    use crate::state::{CanonicalField, Nullifier};
    use crate::transaction::{PublicOutput, PublicSpend};

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
                nullifier: Nullifier(field(3).bytes()),
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
                public_data_hash: [0; 32],
            }],
        }
    }

    fn bound() -> (TransactionPreimage, ProgramContext) {
        let mut transaction = transaction();
        let context = ProgramContext::from_transaction(
            &transaction,
            0,
            50,
            Some(ProgramStateTransition {
                prior: [11; 32],
                next: [12; 32],
            }),
            b"vesting-policy-v1".to_vec(),
        )
        .unwrap();
        transaction.programs[0].public_data_hash = context.hash().unwrap();
        (transaction, context)
    }

    #[test]
    fn context_round_trips_and_binds_inclusion_window() {
        let (transaction, context) = bound();
        let encoded = context.encode().unwrap();
        assert_eq!(ProgramContext::decode(&encoded), Ok(context.clone()));
        context.validate_binding(&transaction, 50).unwrap();
        context.validate_binding(&transaction, 100).unwrap();
        assert_eq!(
            context.validate_binding(&transaction, 49),
            Err(ProgramContextError::InvalidHeightWindow)
        );
        assert_eq!(
            context.validate_binding(&transaction, 101),
            Err(ProgramContextError::InvalidHeightWindow)
        );
    }

    #[test]
    fn every_transaction_projection_is_committed() {
        let (transaction, context) = bound();
        let mutations: Vec<Box<dyn Fn(&mut TransactionPreimage)>> = vec![
            Box::new(|tx| tx.network_id[0] ^= 1),
            Box::new(|tx| tx.anchor = field(20)),
            Box::new(|tx| tx.expiry_height += 1),
            Box::new(|tx| tx.fee += 1),
            Box::new(|tx| tx.spends[0].randomized_key[0] ^= 1),
            Box::new(|tx| tx.outputs[0].ciphertext[0] ^= 1),
            Box::new(|tx| tx.programs[0].program_id[0] ^= 1),
            Box::new(|tx| tx.programs[0].function_id += 1),
            Box::new(|tx| tx.programs[0].public_data_hash[0] ^= 1),
        ];
        for mutate in mutations {
            let mut changed = transaction.clone();
            mutate(&mut changed);
            assert!(context.validate_binding(&changed, 50).is_err());
        }
    }

    #[test]
    fn state_and_application_data_change_the_context_hash() {
        let (_, context) = bound();
        let original = context.hash().unwrap();
        let mut changed = context.clone();
        changed.state.as_mut().unwrap().next[0] ^= 1;
        assert_ne!(changed.hash().unwrap(), original);
        changed = context.clone();
        changed.application_data.push(0);
        assert_ne!(changed.hash().unwrap(), original);
    }

    #[test]
    fn circuit_public_inputs_are_fixed_and_complete() {
        let (_, context) = bound();
        let original = context.public_inputs().unwrap();
        assert_eq!(original.len(), PROGRAM_CONTEXT_PUBLIC_INPUT_COUNT);
        let mut changed = context.clone();
        changed.valid_from_height += 1;
        assert_ne!(changed.public_inputs().unwrap(), original);
        changed = context.clone();
        changed.application_data[0] ^= 1;
        assert_ne!(changed.public_inputs().unwrap(), original);
        changed = context;
        changed.state = None;
        assert_ne!(changed.public_inputs().unwrap(), original);
        assert_eq!(
            ProgramContext::public_input_schema_hash(),
            ProgramContext::derived_public_input_schema_hash()
        );
    }

    #[test]
    fn decoder_rejects_noncanonical_and_unbounded_contexts() {
        let (_, context) = bound();
        let mut trailing = context.encode().unwrap();
        trailing.push(0);
        assert!(ProgramContext::decode(&trailing).is_err());
        let mut wrong_version = context.encode().unwrap();
        wrong_version[0] += 1;
        assert_eq!(
            ProgramContext::decode(&wrong_version),
            Err(ProgramContextError::Decode(DecodeError::WrongVersion))
        );
        let canonical = context.encode().unwrap();
        let valid_from_offset = 1 + NETWORK_ID_BYTES + 32;
        let mut overlong = canonical[..valid_from_offset].to_vec();
        overlong.extend_from_slice(&[0xb2, 0x00]);
        overlong.extend_from_slice(&canonical[valid_from_offset + 1..]);
        assert_eq!(
            ProgramContext::decode(&overlong),
            Err(ProgramContextError::Decode(DecodeError::NonMinimalVarint))
        );
        let mut noncanonical_anchor = canonical;
        noncanonical_anchor[1 + NETWORK_ID_BYTES..1 + NETWORK_ID_BYTES + 32].fill(0xff);
        assert_eq!(
            ProgramContext::decode(&noncanonical_anchor),
            Err(ProgramContextError::Decode(DecodeError::NonCanonicalField))
        );
        assert_eq!(
            ProgramContext::from_transaction(&transaction(), 0, 101, None, Vec::new()),
            Err(ProgramContextError::InvalidHeightWindow)
        );
        assert_eq!(
            ProgramContext::from_transaction(
                &transaction(),
                0,
                100,
                None,
                vec![0; MAX_PROGRAM_PUBLIC_DATA_BYTES + 1],
            ),
            Err(ProgramContextError::PublicDataTooLarge)
        );
    }
}
