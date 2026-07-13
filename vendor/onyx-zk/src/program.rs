//! Canonical rollback-safe Onyx program and verifying-key registry.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::transaction::ProgramCall;
use crate::types::{write_varint, DecodeError, Reader};

const PROGRAM_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.program";
const REGISTRY_VERSION: u8 = 1;
pub const MAX_MANIFEST_BYTES: usize = 4096;
pub const MAX_VERIFYING_KEY_BYTES: usize = 64 * 1024;
pub const MAX_BACKEND_BYTES: usize = 64;
pub const MAX_FUNCTIONS: usize = 16;
pub const MAX_REGISTERED_PROGRAMS: usize = 128;
pub const MAX_REGISTRY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramFunction {
    pub function_id: u32,
    pub verifying_key: Vec<u8>,
    pub public_input_schema_hash: [u8; 32],
    pub max_cost: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramEntry {
    pub manifest: Vec<u8>,
    pub backend: String,
    pub activation_height: u64,
    pub deactivation_height: Option<u64>,
    pub functions: Vec<ProgramFunction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramError {
    Decode(DecodeError),
    InvalidManifest,
    InvalidBackend,
    InvalidActivation,
    InvalidFunction,
    InvalidVerifyingKey,
    TooManyFunctions,
    TooManyPrograms,
    RegistryTooLarge,
    DuplicateProgram,
    UnknownProgram,
    InactiveProgram,
    UnknownFunction,
    DuplicateCall,
    CostOverflow,
    CostLimit,
    NonCanonicalRegistry,
}

impl From<DecodeError> for ProgramError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl ProgramEntry {
    pub fn validate(&self) -> Result<(), ProgramError> {
        if self.manifest.is_empty() || self.manifest.len() > MAX_MANIFEST_BYTES {
            return Err(ProgramError::InvalidManifest);
        }
        if self.backend.is_empty()
            || self.backend.len() > MAX_BACKEND_BYTES
            || !self
                .backend
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ProgramError::InvalidBackend);
        }
        if self
            .deactivation_height
            .is_some_and(|height| height <= self.activation_height || height == u64::MAX)
        {
            return Err(ProgramError::InvalidActivation);
        }
        if self.functions.is_empty() || self.functions.len() > MAX_FUNCTIONS {
            return Err(ProgramError::TooManyFunctions);
        }
        let mut previous = None;
        for function in &self.functions {
            if previous.is_some_and(|id| id >= function.function_id) || function.max_cost == 0 {
                return Err(ProgramError::InvalidFunction);
            }
            if function.verifying_key.is_empty()
                || function.verifying_key.len() > MAX_VERIFYING_KEY_BYTES
            {
                return Err(ProgramError::InvalidVerifyingKey);
            }
            previous = Some(function.function_id);
        }
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32], ProgramError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(PROGRAM_ID_DOMAIN);
        hash.update(self.canonical_bytes());
        Ok(hash.finalize().into())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_bytes(&self.manifest, &mut out);
        write_bytes(self.backend.as_bytes(), &mut out);
        write_varint(self.activation_height, &mut out);
        write_varint(self.deactivation_height.unwrap_or(u64::MAX), &mut out);
        write_varint(self.functions.len() as u64, &mut out);
        for function in &self.functions {
            write_varint(function.function_id.into(), &mut out);
            write_bytes(&function.verifying_key, &mut out);
            out.extend_from_slice(&function.public_input_schema_hash);
            write_varint(function.max_cost, &mut out);
        }
        out
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self, ProgramError> {
        let manifest = read_bytes(reader, MAX_MANIFEST_BYTES)?;
        let backend = String::from_utf8(read_bytes(reader, MAX_BACKEND_BYTES)?)
            .map_err(|_| ProgramError::InvalidBackend)?;
        let activation_height = reader.varint()?;
        let deactivation = reader.varint()?;
        let function_count = bounded(
            reader.varint()?,
            MAX_FUNCTIONS,
            ProgramError::TooManyFunctions,
        )?;
        let mut functions = Vec::with_capacity(function_count);
        for _ in 0..function_count {
            let function_id = reader.varint()?;
            if function_id > u32::MAX.into() {
                return Err(ProgramError::InvalidFunction);
            }
            functions.push(ProgramFunction {
                function_id: function_id as u32,
                verifying_key: read_bytes(reader, MAX_VERIFYING_KEY_BYTES)?,
                public_input_schema_hash: reader.array()?,
                max_cost: reader.varint()?,
            });
        }
        let entry = Self {
            manifest,
            backend,
            activation_height,
            deactivation_height: (deactivation != u64::MAX).then_some(deactivation),
            functions,
        };
        entry.validate()?;
        Ok(entry)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramRegistry {
    entries: BTreeMap<[u8; 32], ProgramEntry>,
}

pub struct ProgramDelta {
    program_id: [u8; 32],
}

impl ProgramRegistry {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, program_id: &[u8; 32]) -> Option<&ProgramEntry> {
        self.entries.get(program_id)
    }

    pub fn active_function(
        &self,
        program_id: &[u8; 32],
        function_id: u32,
        height: u64,
    ) -> Result<(&ProgramEntry, &ProgramFunction), ProgramError> {
        let entry = self
            .entries
            .get(program_id)
            .ok_or(ProgramError::UnknownProgram)?;
        if height < entry.activation_height
            || entry
                .deactivation_height
                .is_some_and(|deactivation| height >= deactivation)
        {
            return Err(ProgramError::InactiveProgram);
        }
        let function = entry
            .functions
            .iter()
            .find(|function| function.function_id == function_id)
            .ok_or(ProgramError::UnknownFunction)?;
        Ok((entry, function))
    }

    pub fn register(&mut self, entry: ProgramEntry) -> Result<ProgramDelta, ProgramError> {
        let program_id = entry.id()?;
        if self.entries.contains_key(&program_id) {
            return Err(ProgramError::DuplicateProgram);
        }
        if self.entries.len() >= MAX_REGISTERED_PROGRAMS {
            return Err(ProgramError::TooManyPrograms);
        }
        self.entries.insert(program_id, entry);
        if self.encode().len() > MAX_REGISTRY_BYTES {
            self.entries.remove(&program_id);
            return Err(ProgramError::RegistryTooLarge);
        }
        Ok(ProgramDelta { program_id })
    }

    pub fn rollback(&mut self, delta: ProgramDelta) {
        assert!(self.entries.remove(&delta.program_id).is_some());
    }

    pub fn validate_calls(
        &self,
        calls: &[ProgramCall],
        height: u64,
        max_total_cost: u64,
    ) -> Result<u64, ProgramError> {
        let mut seen = BTreeMap::new();
        let mut total = 0u64;
        for call in calls {
            if seen
                .insert((call.program_id, call.function_id), ())
                .is_some()
            {
                return Err(ProgramError::DuplicateCall);
            }
            let (_, function) = self.active_function(&call.program_id, call.function_id, height)?;
            total = total
                .checked_add(function.max_cost)
                .ok_or(ProgramError::CostOverflow)?;
            if total > max_total_cost {
                return Err(ProgramError::CostLimit);
            }
        }
        Ok(total)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![REGISTRY_VERSION];
        write_varint(self.entries.len() as u64, &mut out);
        for (program_id, entry) in &self.entries {
            out.extend_from_slice(program_id);
            let bytes = entry.canonical_bytes();
            write_bytes(&bytes, &mut out);
        }
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProgramError> {
        if input.len() > MAX_REGISTRY_BYTES {
            return Err(ProgramError::RegistryTooLarge);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != REGISTRY_VERSION {
            return Err(ProgramError::NonCanonicalRegistry);
        }
        let count = bounded(
            reader.varint()?,
            MAX_REGISTERED_PROGRAMS,
            ProgramError::TooManyPrograms,
        )?;
        let mut entries = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let program_id: [u8; 32] = reader.array()?;
            if previous.is_some_and(|id| id >= program_id) {
                return Err(ProgramError::NonCanonicalRegistry);
            }
            let encoded = read_bytes(
                &mut reader,
                MAX_MANIFEST_BYTES + MAX_FUNCTIONS * (MAX_VERIFYING_KEY_BYTES + 64),
            )?;
            let mut entry_reader = Reader::new(&encoded);
            let entry = ProgramEntry::decode(&mut entry_reader)?;
            if !entry_reader.is_empty() || entry.id()? != program_id {
                return Err(ProgramError::NonCanonicalRegistry);
            }
            entries.insert(program_id, entry);
            previous = Some(program_id);
        }
        if !reader.is_empty() {
            return Err(ProgramError::NonCanonicalRegistry);
        }
        Ok(Self { entries })
    }
}

fn write_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    write_varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn read_bytes(reader: &mut Reader<'_>, maximum: usize) -> Result<Vec<u8>, ProgramError> {
    let length = bounded(
        reader.varint()?,
        maximum,
        ProgramError::NonCanonicalRegistry,
    )?;
    Ok(reader.take(length)?.to_vec())
}

fn bounded(value: u64, maximum: usize, error: ProgramError) -> Result<usize, ProgramError> {
    if value > maximum as u64 {
        Err(error)
    } else {
        Ok(value as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(activation: u64, deactivation: Option<u64>) -> ProgramEntry {
        ProgramEntry {
            manifest: b"onyx.test.token/v1".to_vec(),
            backend: "halo2-ipa-pasta".to_owned(),
            activation_height: activation,
            deactivation_height: deactivation,
            functions: vec![
                ProgramFunction {
                    function_id: 1,
                    verifying_key: vec![1, 2, 3],
                    public_input_schema_hash: [4; 32],
                    max_cost: 20,
                },
                ProgramFunction {
                    function_id: 2,
                    verifying_key: vec![5, 6, 7],
                    public_input_schema_hash: [8; 32],
                    max_cost: 30,
                },
            ],
        }
    }

    #[test]
    fn registry_round_trip_dispatch_and_rollback_are_canonical() {
        let program = entry(10, Some(20));
        let program_id = program.id().unwrap();
        assert_eq!(program_id, program.id().unwrap());
        let mut registry = ProgramRegistry::default();
        let delta = registry.register(program.clone()).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            registry.register(program),
            Err(ProgramError::DuplicateProgram)
        ));
        let encoded = registry.encode();
        assert_eq!(ProgramRegistry::decode(&encoded).unwrap().encode(), encoded);

        let call = ProgramCall {
            program_id,
            function_id: 1,
            public_data_hash: [9; 32],
        };
        assert_eq!(
            registry.validate_calls(std::slice::from_ref(&call), 10, 20),
            Ok(20)
        );
        assert!(matches!(
            registry.validate_calls(std::slice::from_ref(&call), 9, 20),
            Err(ProgramError::InactiveProgram)
        ));
        assert!(matches!(
            registry.validate_calls(std::slice::from_ref(&call), 20, 20),
            Err(ProgramError::InactiveProgram)
        ));
        assert!(matches!(
            registry.validate_calls(&[call.clone(), call.clone()], 10, 100),
            Err(ProgramError::DuplicateCall)
        ));
        let mut costly = call;
        costly.function_id = 2;
        assert!(matches!(
            registry.validate_calls(&[costly], 10, 29),
            Err(ProgramError::CostLimit)
        ));
        registry.rollback(delta);
        assert!(registry.get(&program_id).is_none());
    }

    #[test]
    fn malformed_entries_and_registry_encodings_fail_closed() {
        let mut unordered = entry(1, None);
        unordered.functions.swap(0, 1);
        assert_eq!(unordered.validate(), Err(ProgramError::InvalidFunction));
        let mut empty_key = entry(1, None);
        empty_key.functions[0].verifying_key.clear();
        assert_eq!(empty_key.validate(), Err(ProgramError::InvalidVerifyingKey));
        let mut ambiguous_backend = entry(1, None);
        ambiguous_backend.backend = "halo2 ipa".to_owned();
        assert_eq!(
            ambiguous_backend.validate(),
            Err(ProgramError::InvalidBackend)
        );
        assert_eq!(
            ProgramRegistry::decode(&vec![0; MAX_REGISTRY_BYTES + 1]).err(),
            Some(ProgramError::RegistryTooLarge)
        );

        let mut registry = ProgramRegistry::default();
        registry.register(entry(1, None)).unwrap();
        let encoded = registry.encode();
        assert!(ProgramRegistry::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            ProgramRegistry::decode(&trailing).err(),
            Some(ProgramError::NonCanonicalRegistry)
        );
    }
}
