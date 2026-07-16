//! Canonical, non-circular public context for stateful Onyx program calls.

use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

use crate::authorization::verify_authorized_transaction;
use crate::compiler_backend::{
    compiler_vk_descriptor_for_export, verify_compiler_proof_for_export, COMPILER_PROGRAM_BACKEND,
};
use crate::program::ProgramRegistry;
use crate::proof::{
    multi_transfer_backend_id, program_transfer_backend_id, verify_multi_transfer_proof,
    verify_program_multi_transfer_proof,
};
use crate::state::CanonicalField;
use crate::transaction::{
    write_public_output, AuthorizedTransaction, ProgramCall, TransactionPreimage,
    MAX_BACKEND_ID_BYTES, MAX_PROGRAMS, MAX_PROOF_BYTES,
};
use crate::types::{network_field, pack_32, write_varint, DecodeError, Reader, NETWORK_ID_BYTES};

pub const PROGRAM_CONTEXT_VERSION: u8 = 1;
pub const MAX_PROGRAM_PUBLIC_DATA_BYTES: usize = 4096;
pub const MAX_PROGRAM_CONTEXT_BYTES: usize = 8192;
pub const MAX_CONTEXTUAL_TRANSACTION_BYTES: usize = 512 * 1024;
pub const CONTEXTUAL_TRANSACTION_VERSION: u8 = 1;
pub const CONTEXTUAL_PROOF_BUNDLE_VERSION: u8 = 1;
pub const CONTEXTUAL_PROGRAM_BACKEND: &str = "halo2-ipa-pasta-onyx-context-v1";
pub const MAX_CONTEXTUAL_PROGRAM_COST: u64 = 10_000_000;
pub const PROGRAM_CONTEXT_PUBLIC_INPUT_COUNT: usize = 22;
pub const PROGRAM_CONTEXT_SCHEMA_HASH: [u8; 32] = [
    0x05, 0xb9, 0xfa, 0xf1, 0x49, 0xf9, 0xfa, 0x69, 0xd9, 0x41, 0x53, 0xd2, 0xf2, 0x2c, 0xe8, 0x5b,
    0xd5, 0x15, 0x28, 0x25, 0x6f, 0x0e, 0x25, 0xf1, 0x5a, 0x1e, 0xdf, 0xbd, 0x1a, 0xd5, 0xe9, 0x41,
];
pub const CONTEXTUAL_COMPILER_SCHEMA_HASH: [u8; 32] = [
    0xcb, 0x29, 0x2c, 0x9b, 0x8a, 0xd1, 0x9b, 0x96, 0x39, 0x01, 0xe7, 0xe5, 0x9f, 0x42, 0x04, 0x91,
    0x00, 0x5a, 0x0e, 0xf9, 0x08, 0x51, 0xb8, 0x47, 0x6e, 0xe0, 0x3c, 0x76, 0x3f, 0xb9, 0xc9, 0xc1,
];
const CONTEXT_HASH_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.v1";
const ENVELOPE_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.contextual-transaction-id.v1";
const PUBLIC_DATA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.public-data.v1";
pub const PROGRAM_CONTEXT_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.schema.v1";
pub const PROGRAM_CONTEXT_PUBLIC_INPUT_SCHEMA: &[u8] = b"network:field,anchor:field,valid_from:u64,expiry:u64,fee:u64,call_index:u8,program:field[2],function:u32,spends:field[2],outputs:field[2],calls:field[2],has_state:bool,prior:field[2],next:field[2],application:field[2]";
const SPENDS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.spends.v1";
const OUTPUTS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.outputs.v1";
const CALLS_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program-context.calls.v1";
const COMPILER_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.contextual-compiler.schema.v1";
const COMPILER_PUBLIC_INPUT_SCHEMA: &[u8] = b"program-context-v1:field[22],result:bool";

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
pub struct ContextualAuthorizedTransaction {
    pub transaction: AuthorizedTransaction,
    pub contexts: Vec<ProgramContext>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextualProofBundle {
    pub base_backend_id: String,
    pub base_proof: Vec<u8>,
    pub program_proofs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextualProgramArtifact {
    pub ir: Vec<u8>,
    pub export: String,
    pub circuit_k: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramContextError {
    Decode(DecodeError),
    InvalidCall,
    InvalidHeightWindow,
    PublicDataTooLarge,
    Transaction,
    BindingMismatch,
    EnvelopeTooLarge,
    InvalidContextCount,
    InvalidProofBundle,
    Registry,
    Authorization,
    BaseProof,
    ProgramProof,
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

impl ContextualAuthorizedTransaction {
    fn validate_structure(&self) -> Result<(), ProgramContextError> {
        if self.transaction.preimage.programs.is_empty()
            || self.contexts.len() != self.transaction.preimage.programs.len()
            || self.contexts.len() > MAX_PROGRAMS
        {
            return Err(ProgramContextError::InvalidContextCount);
        }
        self.transaction
            .encode()
            .map_err(|_| ProgramContextError::Transaction)?;
        if self.transaction.backend_id != CONTEXTUAL_PROGRAM_BACKEND {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let proof_bundle = ContextualProofBundle::decode(&self.transaction.proof)?;
        if proof_bundle.program_proofs.len() != self.contexts.len() {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        for (index, context) in self.contexts.iter().enumerate() {
            if usize::from(context.call_index) != index
                || context
                    .validate_binding(&self.transaction.preimage, context.valid_from_height)
                    .is_err()
            {
                return Err(ProgramContextError::BindingMismatch);
            }
        }
        Ok(())
    }

    pub fn validate_at_height(&self, block_height: u64) -> Result<(), ProgramContextError> {
        self.validate_structure()?;
        for context in &self.contexts {
            context.validate_binding(&self.transaction.preimage, block_height)?;
        }
        Ok(())
    }

    pub fn proof_bundle(&self) -> Result<ContextualProofBundle, ProgramContextError> {
        self.validate_structure()?;
        ContextualProofBundle::decode(&self.transaction.proof)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProgramContextError> {
        self.validate_structure()?;
        let transaction = self
            .transaction
            .encode()
            .map_err(|_| ProgramContextError::Transaction)?;
        let mut encoded_contexts = Vec::with_capacity(self.contexts.len());
        for context in &self.contexts {
            let encoded = context.encode()?;
            if encoded.len() > MAX_PROGRAM_CONTEXT_BYTES {
                return Err(ProgramContextError::EnvelopeTooLarge);
            }
            encoded_contexts.push(encoded);
        }
        let mut out = Vec::with_capacity(
            transaction.len() + encoded_contexts.iter().map(Vec::len).sum::<usize>() + 32,
        );
        out.push(CONTEXTUAL_TRANSACTION_VERSION);
        write_varint(transaction.len() as u64, &mut out);
        out.extend_from_slice(&transaction);
        write_varint(encoded_contexts.len() as u64, &mut out);
        for context in encoded_contexts {
            write_varint(context.len() as u64, &mut out);
            out.extend_from_slice(&context);
        }
        if out.len() > MAX_CONTEXTUAL_TRANSACTION_BYTES {
            return Err(ProgramContextError::EnvelopeTooLarge);
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProgramContextError> {
        if input.is_empty() || input.len() > MAX_CONTEXTUAL_TRANSACTION_BYTES {
            return Err(ProgramContextError::EnvelopeTooLarge);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != CONTEXTUAL_TRANSACTION_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let transaction_length = reader.varint()?;
        if transaction_length == 0 || transaction_length > MAX_CONTEXTUAL_TRANSACTION_BYTES as u64 {
            return Err(ProgramContextError::EnvelopeTooLarge);
        }
        let transaction = AuthorizedTransaction::decode(reader.take(transaction_length as usize)?)
            .map_err(|_| ProgramContextError::Transaction)?;
        let context_count = reader.varint()?;
        if context_count == 0 || context_count > MAX_PROGRAMS as u64 {
            return Err(ProgramContextError::InvalidContextCount);
        }
        let mut contexts = Vec::with_capacity(context_count as usize);
        for _ in 0..context_count {
            let length = reader.varint()?;
            if length == 0 || length > MAX_PROGRAM_CONTEXT_BYTES as u64 {
                return Err(ProgramContextError::EnvelopeTooLarge);
            }
            contexts.push(ProgramContext::decode(reader.take(length as usize)?)?);
        }
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let envelope = Self {
            transaction,
            contexts,
        };
        envelope.validate_structure()?;
        Ok(envelope)
    }

    pub fn id(&self) -> Result<[u8; 32], ProgramContextError> {
        let encoded = self.encode()?;
        let mut hash = Sha256::new();
        hash.update(ENVELOPE_ID_DOMAIN);
        hash.update((encoded.len() as u64).to_le_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    /// Verifies the signed contextual bundle, its base value layer, and every registered compiler
    /// predicate. State mutation remains a separate atomic operation after this returns success.
    pub fn verify(
        &self,
        registry: &ProgramRegistry,
        block_height: u64,
        merkle_depth: u32,
        base_circuit_k: u32,
        artifacts: &[ContextualProgramArtifact],
    ) -> Result<(), ProgramContextError> {
        self.validate_at_height(block_height)?;
        if artifacts.len() != self.contexts.len() || !(10..=20).contains(&base_circuit_k) {
            return Err(ProgramContextError::ProgramProof);
        }
        registry
            .validate_calls(
                &self.transaction.preimage.programs,
                block_height,
                MAX_CONTEXTUAL_PROGRAM_COST,
            )
            .map_err(|_| ProgramContextError::Registry)?;
        verify_authorized_transaction(&self.transaction)
            .map_err(|_| ProgramContextError::Authorization)?;
        let bundle = self.proof_bundle()?;
        verify_contextual_base(
            &self.transaction,
            &bundle,
            &self.contexts,
            merkle_depth,
            base_circuit_k,
        )?;
        let schema_hash = contextual_compiler_schema_hash();
        for (index, ((context, artifact), proof)) in self
            .contexts
            .iter()
            .zip(artifacts)
            .zip(&bundle.program_proofs)
            .enumerate()
        {
            let call = &self.transaction.preimage.programs[index];
            let (entry, function) = registry
                .active_function(&call.program_id, call.function_id, block_height)
                .map_err(|_| ProgramContextError::Registry)?;
            if entry.backend != COMPILER_PROGRAM_BACKEND
                || function.public_input_schema_hash != schema_hash
                || artifact.export.is_empty()
            {
                return Err(ProgramContextError::ProgramProof);
            }
            let descriptor = compiler_vk_descriptor_for_export(
                &artifact.ir,
                artifact.circuit_k,
                &artifact.export,
            )
            .map_err(|_| ProgramContextError::ProgramProof)?;
            if descriptor != function.verifying_key {
                return Err(ProgramContextError::ProgramProof);
            }
            let mut public_inputs = context.public_inputs()?;
            public_inputs.push(Fp::one());
            verify_compiler_proof_for_export(
                &artifact.ir,
                artifact.circuit_k,
                &artifact.export,
                &public_inputs,
                proof,
            )
            .map_err(|_| ProgramContextError::ProgramProof)?;
        }
        Ok(())
    }
}

pub fn contextual_compiler_schema_hash() -> [u8; 32] {
    CONTEXTUAL_COMPILER_SCHEMA_HASH
}

fn verify_contextual_base(
    transaction: &AuthorizedTransaction,
    bundle: &ContextualProofBundle,
    contexts: &[ProgramContext],
    merkle_depth: u32,
    circuit_k: u32,
) -> Result<(), ProgramContextError> {
    let mut base = transaction.clone();
    base.preimage.programs.clear();
    base.backend_id = bundle.base_backend_id.clone();
    base.proof = bundle.base_proof.clone();
    let spends = base.preimage.spends.len();
    let outputs = base.preimage.outputs.len();
    macro_rules! verify_shape {
        ($depth:literal, $spends:literal, $outputs:literal) => {{
            if bundle.base_backend_id == multi_transfer_backend_id($spends, $outputs) {
                verify_multi_transfer_proof::<$depth, $spends, $outputs>(circuit_k, &base)
            } else if contexts.len() == 1
                && bundle.base_backend_id == program_transfer_backend_id($spends, $outputs)
            {
                verify_program_multi_transfer_proof::<$depth, $spends, $outputs>(
                    circuit_k,
                    &base,
                    &contexts[0].program_id,
                )
            } else {
                return Err(ProgramContextError::BaseProof);
            }
        }};
    }
    let result = match (merkle_depth, spends, outputs) {
        (2, 1, 1) => verify_shape!(2, 1, 1),
        (2, 1, 2) => verify_shape!(2, 1, 2),
        (2, 2, 1) => verify_shape!(2, 2, 1),
        (2, 2, 2) => verify_shape!(2, 2, 2),
        (4, 1, 1) => verify_shape!(4, 1, 1),
        (4, 1, 2) => verify_shape!(4, 1, 2),
        (4, 2, 1) => verify_shape!(4, 2, 1),
        (4, 2, 2) => verify_shape!(4, 2, 2),
        (32, 1, 1) => verify_shape!(32, 1, 1),
        (32, 1, 2) => verify_shape!(32, 1, 2),
        (32, 2, 1) => verify_shape!(32, 2, 1),
        (32, 2, 2) => verify_shape!(32, 2, 2),
        _ => return Err(ProgramContextError::BaseProof),
    };
    result.map_err(|_| ProgramContextError::BaseProof)
}

impl ContextualProofBundle {
    fn validate(&self) -> Result<(), ProgramContextError> {
        if self.base_backend_id.is_empty()
            || self.base_backend_id.len() > MAX_BACKEND_ID_BYTES
            || !self
                .base_backend_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || self.base_proof.is_empty()
            || self.base_proof.len() > MAX_PROOF_BYTES
            || self.program_proofs.is_empty()
            || self.program_proofs.len() > MAX_PROGRAMS
            || self
                .program_proofs
                .iter()
                .any(|proof| proof.is_empty() || proof.len() > MAX_PROOF_BYTES)
        {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProgramContextError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(CONTEXTUAL_PROOF_BUNDLE_VERSION);
        write_varint(self.base_backend_id.len() as u64, &mut out);
        out.extend_from_slice(self.base_backend_id.as_bytes());
        write_varint(self.base_proof.len() as u64, &mut out);
        out.extend_from_slice(&self.base_proof);
        write_varint(self.program_proofs.len() as u64, &mut out);
        for proof in &self.program_proofs {
            write_varint(proof.len() as u64, &mut out);
            out.extend_from_slice(proof);
        }
        if out.len() > MAX_PROOF_BYTES {
            return Err(ProgramContextError::EnvelopeTooLarge);
        }
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProgramContextError> {
        if input.is_empty() || input.len() > MAX_PROOF_BYTES {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != CONTEXTUAL_PROOF_BUNDLE_VERSION {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let backend_length = reader.varint()?;
        if backend_length == 0 || backend_length > MAX_BACKEND_ID_BYTES as u64 {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let base_backend_id = String::from_utf8(reader.take(backend_length as usize)?.to_vec())
            .map_err(|_| ProgramContextError::InvalidProofBundle)?;
        let base_proof_length = reader.varint()?;
        if base_proof_length == 0 || base_proof_length > MAX_PROOF_BYTES as u64 {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let base_proof = reader.take(base_proof_length as usize)?.to_vec();
        let proof_count = reader.varint()?;
        if proof_count == 0 || proof_count > MAX_PROGRAMS as u64 {
            return Err(ProgramContextError::InvalidProofBundle);
        }
        let mut program_proofs = Vec::with_capacity(proof_count as usize);
        for _ in 0..proof_count {
            let length = reader.varint()?;
            if length == 0 || length > MAX_PROOF_BYTES as u64 {
                return Err(ProgramContextError::InvalidProofBundle);
            }
            program_proofs.push(reader.take(length as usize)?.to_vec());
        }
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let bundle = Self {
            base_backend_id,
            base_proof,
            program_proofs,
        };
        bundle.validate()?;
        Ok(bundle)
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
    use crate::transaction::{AuthorizedTransaction, PublicOutput, PublicSpend};

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

    fn envelope() -> ContextualAuthorizedTransaction {
        let (preimage, context) = bound();
        let proof = ContextualProofBundle {
            base_backend_id: "halo2-ipa-pasta-onyx-1x1-v1".to_owned(),
            base_proof: vec![13, 14, 15],
            program_proofs: vec![vec![16, 17, 18]],
        }
        .encode()
        .unwrap();
        ContextualAuthorizedTransaction {
            transaction: AuthorizedTransaction {
                preimage,
                backend_id: CONTEXTUAL_PROGRAM_BACKEND.to_owned(),
                proof,
                spend_signatures: vec![[19; 64]],
                binding_signature: [20; 64],
            },
            contexts: vec![context],
        }
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
    fn contextual_compiler_schema_hash_is_frozen() {
        assert_eq!(
            domain_hash(COMPILER_SCHEMA_DOMAIN, COMPILER_PUBLIC_INPUT_SCHEMA),
            CONTEXTUAL_COMPILER_SCHEMA_HASH
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

    #[test]
    fn contextual_envelope_round_trips_and_rechecks_height() {
        let envelope = envelope();
        let encoded = envelope.encode().unwrap();
        assert_eq!(
            ContextualAuthorizedTransaction::decode(&encoded),
            Ok(envelope.clone())
        );
        envelope.validate_at_height(50).unwrap();
        assert_eq!(
            envelope.validate_at_height(49),
            Err(ProgramContextError::InvalidHeightWindow)
        );
        assert_ne!(envelope.id().unwrap(), [0; 32]);
    }

    #[test]
    fn contextual_envelope_rejects_missing_reordered_and_trailing_contexts() {
        let envelope = envelope();
        let mut missing = envelope.clone();
        missing.contexts.clear();
        assert_eq!(
            missing.encode(),
            Err(ProgramContextError::InvalidContextCount)
        );
        let mut wrong_index = envelope.clone();
        wrong_index.contexts[0].call_index = 1;
        assert_eq!(
            wrong_index.encode(),
            Err(ProgramContextError::BindingMismatch)
        );
        let mut trailing = envelope.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            ContextualAuthorizedTransaction::decode(&trailing),
            Err(ProgramContextError::Decode(DecodeError::TrailingData))
        );
        assert_eq!(
            ContextualAuthorizedTransaction::decode(&vec![0; MAX_CONTEXTUAL_TRANSACTION_BYTES + 1]),
            Err(ProgramContextError::EnvelopeTooLarge)
        );
    }

    #[test]
    fn contextual_envelope_id_commits_authorization_bytes() {
        let envelope = envelope();
        let original = envelope.id().unwrap();
        let mut changed = envelope;
        let mut proof_bundle = changed.proof_bundle().unwrap();
        proof_bundle.base_proof[0] ^= 1;
        changed.transaction.proof = proof_bundle.encode().unwrap();
        assert_ne!(changed.id().unwrap(), original);
        proof_bundle.base_proof[0] ^= 1;
        changed.transaction.proof = proof_bundle.encode().unwrap();
        changed.transaction.binding_signature[0] ^= 1;
        assert_ne!(changed.id().unwrap(), original);
    }

    #[test]
    fn contextual_proof_bundle_is_ordered_bounded_and_canonical() {
        let envelope = envelope();
        let bundle = envelope.proof_bundle().unwrap();
        assert_eq!(
            ContextualProofBundle::decode(&bundle.encode().unwrap()),
            Ok(bundle)
        );
        let mut wrong_count = envelope;
        let mut bundle = wrong_count.proof_bundle().unwrap();
        bundle.program_proofs.push(vec![1]);
        wrong_count.transaction.proof = bundle.encode().unwrap();
        assert_eq!(
            wrong_count.encode(),
            Err(ProgramContextError::InvalidProofBundle)
        );
        let mut trailing = ContextualProofBundle {
            base_backend_id: "base".to_owned(),
            base_proof: vec![1],
            program_proofs: vec![vec![2]],
        }
        .encode()
        .unwrap();
        trailing.push(0);
        assert_eq!(
            ContextualProofBundle::decode(&trailing),
            Err(ProgramContextError::Decode(DecodeError::TrailingData))
        );
    }
}
