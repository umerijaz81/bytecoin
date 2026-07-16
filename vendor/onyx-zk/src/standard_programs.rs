//! Canonical public application-data profiles for approved contextual programs.

use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

use crate::program_context::ProgramContext;
use crate::state::CanonicalField;
use crate::types::{pack_32, write_varint, DecodeError, Reader};

pub const STANDARD_APPLICATION_VERSION: u8 = 1;
const STANDARD_SCHEMA_DOMAIN: &[u8] = b"bytecoin.onyx.v6.standard-program.schema.v1";
pub const NFT_SCHEMA_HASH: [u8; 32] = [
    0x20, 0x47, 0x30, 0x97, 0x8f, 0x78, 0x8b, 0x8d, 0x1e, 0x45, 0x8e, 0xe8, 0x1c, 0x1c, 0x12, 0xff,
    0x39, 0xd0, 0x44, 0x4f, 0x17, 0x4f, 0xe9, 0xd1, 0x92, 0x24, 0x6d, 0x80, 0x89, 0x0b, 0xb1, 0x32,
];
pub const VESTING_SCHEMA_HASH: [u8; 32] = [
    0xc3, 0x6e, 0xfa, 0x02, 0x93, 0x0c, 0x25, 0x51, 0x17, 0x9a, 0x94, 0x92, 0x14, 0xf1, 0xa1, 0x81,
    0x72, 0x0d, 0xdd, 0x83, 0x64, 0xe4, 0x4a, 0x19, 0x7c, 0x7a, 0x0b, 0x75, 0x6c, 0xd0, 0x86, 0x2c,
];
pub const MULTISIG_SCHEMA_HASH: [u8; 32] = [
    0x87, 0x03, 0xb1, 0xc7, 0x51, 0xde, 0x78, 0x81, 0x66, 0x7f, 0x76, 0x50, 0x7f, 0xdf, 0x7f, 0x04,
    0xa3, 0x03, 0x99, 0xda, 0x2c, 0x4b, 0x1b, 0xb2, 0x7f, 0x8b, 0x91, 0xe8, 0x6a, 0x5b, 0xa5, 0x89,
];
pub const SWAP_SCHEMA_HASH: [u8; 32] = [
    0x87, 0x38, 0x06, 0x24, 0x76, 0x88, 0x0a, 0x23, 0xaf, 0xdd, 0x40, 0xb5, 0xc6, 0x4c, 0x8e, 0xc2,
    0x12, 0x0d, 0x8c, 0x69, 0x81, 0x31, 0x5d, 0xba, 0x90, 0x77, 0x62, 0x66, 0xdd, 0xde, 0x4f, 0xce,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StandardProgramKind {
    Nft = 1,
    Vesting = 2,
    Multisig = 3,
    Swap = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandardApplication {
    Nft {
        collection_id: [u8; 32],
        token_id: [u8; 32],
        serial: u64,
        transfer_nonce: u64,
    },
    Vesting {
        schedule_id: [u8; 32],
        beneficiary: [u8; 32],
        unlock_height: u64,
    },
    Multisig {
        policy_commitment: [u8; 32],
        action_digest: [u8; 32],
        threshold: u8,
        participant_count: u8,
    },
    Swap {
        swap_id: [u8; 32],
        hashlock: [u8; 32],
        timeout_height: u64,
        refund: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StandardProgramError {
    Decode(DecodeError),
    WrongKind,
    InvalidField,
    MissingState,
    InvalidTransition,
    Timelock,
}

impl From<DecodeError> for StandardProgramError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl StandardApplication {
    pub fn kind(&self) -> StandardProgramKind {
        match self {
            Self::Nft { .. } => StandardProgramKind::Nft,
            Self::Vesting { .. } => StandardProgramKind::Vesting,
            Self::Multisig { .. } => StandardProgramKind::Multisig,
            Self::Swap { .. } => StandardProgramKind::Swap,
        }
    }

    pub fn decode(input: &[u8]) -> Result<Self, StandardProgramError> {
        let mut reader = Reader::new(input);
        if reader.byte()? != STANDARD_APPLICATION_VERSION {
            return Err(StandardProgramError::Decode(DecodeError::WrongVersion));
        }
        let application = match reader.byte()? {
            1 => Self::Nft {
                collection_id: reader.array()?,
                token_id: reader.array()?,
                serial: reader.varint()?,
                transfer_nonce: reader.varint()?,
            },
            2 => Self::Vesting {
                schedule_id: reader.array()?,
                beneficiary: reader.array()?,
                unlock_height: reader.varint()?,
            },
            3 => {
                let policy_commitment = reader.array()?;
                let action_digest = reader.array()?;
                let threshold = reader.varint()?;
                let participant_count = reader.varint()?;
                if threshold > u8::MAX.into() || participant_count > u8::MAX.into() {
                    return Err(StandardProgramError::InvalidField);
                }
                Self::Multisig {
                    policy_commitment,
                    action_digest,
                    threshold: threshold as u8,
                    participant_count: participant_count as u8,
                }
            }
            4 => Self::Swap {
                swap_id: reader.array()?,
                hashlock: reader.array()?,
                timeout_height: reader.varint()?,
                refund: match reader.byte()? {
                    0 => false,
                    1 => true,
                    _ => return Err(StandardProgramError::InvalidField),
                },
            },
            _ => return Err(StandardProgramError::WrongKind),
        };
        if !reader.is_empty() {
            return Err(StandardProgramError::Decode(DecodeError::TrailingData));
        }
        application.validate_fields()?;
        Ok(application)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StandardProgramError> {
        self.validate_fields()?;
        let mut out = vec![STANDARD_APPLICATION_VERSION, self.kind() as u8];
        match self {
            Self::Nft {
                collection_id,
                token_id,
                serial,
                transfer_nonce,
            } => {
                out.extend(collection_id);
                out.extend(token_id);
                write_varint(*serial, &mut out);
                write_varint(*transfer_nonce, &mut out);
            }
            Self::Vesting {
                schedule_id,
                beneficiary,
                unlock_height,
            } => {
                out.extend(schedule_id);
                out.extend(beneficiary);
                write_varint(*unlock_height, &mut out);
            }
            Self::Multisig {
                policy_commitment,
                action_digest,
                threshold,
                participant_count,
            } => {
                out.extend(policy_commitment);
                out.extend(action_digest);
                write_varint(u64::from(*threshold), &mut out);
                write_varint(u64::from(*participant_count), &mut out);
            }
            Self::Swap {
                swap_id,
                hashlock,
                timeout_height,
                refund,
            } => {
                out.extend(swap_id);
                out.extend(hashlock);
                write_varint(*timeout_height, &mut out);
                out.push(u8::from(*refund));
            }
        }
        Ok(out)
    }

    fn validate_fields(&self) -> Result<(), StandardProgramError> {
        let nonzero = |value: &[u8; 32]| value.iter().any(|byte| *byte != 0);
        match self {
            Self::Nft {
                collection_id,
                token_id,
                ..
            } if nonzero(collection_id) && nonzero(token_id) => Ok(()),
            Self::Vesting {
                schedule_id,
                beneficiary,
                ..
            } if nonzero(schedule_id) && nonzero(beneficiary) => Ok(()),
            Self::Multisig {
                policy_commitment,
                action_digest,
                threshold,
                participant_count,
            } if nonzero(policy_commitment)
                && CanonicalField::from_bytes(*policy_commitment).is_some()
                && nonzero(action_digest)
                && *participant_count <= 16
                && *threshold > 0
                && *threshold <= *participant_count =>
            {
                Ok(())
            }
            Self::Swap {
                swap_id, hashlock, ..
            } if nonzero(swap_id)
                && nonzero(hashlock)
                && CanonicalField::from_bytes(*hashlock).is_some() =>
            {
                Ok(())
            }
            _ => Err(StandardProgramError::InvalidField),
        }
    }

    pub fn validate_context(&self, context: &ProgramContext) -> Result<(), StandardProgramError> {
        self.validate_fields()?;
        let state = context
            .state
            .as_ref()
            .ok_or(StandardProgramError::MissingState)?;
        if state.prior == state.next {
            return Err(StandardProgramError::InvalidTransition);
        }
        if CanonicalField::from_bytes(state.prior).is_none()
            || CanonicalField::from_bytes(state.next).is_none()
        {
            return Err(StandardProgramError::InvalidField);
        }
        match self {
            Self::Vesting { unlock_height, .. } if context.valid_from_height < *unlock_height => {
                Err(StandardProgramError::Timelock)
            }
            Self::Swap {
                timeout_height,
                refund: true,
                ..
            } if context.valid_from_height < *timeout_height => Err(StandardProgramError::Timelock),
            _ => Ok(()),
        }
    }

    pub fn public_suffix(&self) -> Result<Vec<Fp>, StandardProgramError> {
        let mut fields = vec![Fp::from(self.kind() as u64)];
        match self {
            Self::Nft {
                collection_id,
                token_id,
                serial,
                transfer_nonce,
            } => {
                fields.extend(pack_32(collection_id));
                fields.extend(pack_32(token_id));
                fields.push(Fp::from(*serial));
                fields.push(Fp::from(*transfer_nonce));
            }
            Self::Vesting {
                schedule_id,
                beneficiary,
                unlock_height,
            } => {
                fields.extend(pack_32(schedule_id));
                fields.extend(pack_32(beneficiary));
                fields.push(Fp::from(*unlock_height));
            }
            Self::Multisig {
                policy_commitment,
                action_digest,
                threshold,
                participant_count,
            } => {
                fields.push(
                    CanonicalField::from_bytes(*policy_commitment)
                        .ok_or(StandardProgramError::InvalidField)?
                        .field(),
                );
                fields.extend(pack_32(action_digest));
                fields.push(Fp::from(u64::from(*threshold)));
                fields.push(Fp::from(u64::from(*participant_count)));
            }
            Self::Swap {
                swap_id,
                hashlock,
                timeout_height,
                refund,
            } => {
                fields.extend(pack_32(swap_id));
                fields.push(
                    CanonicalField::from_bytes(*hashlock)
                        .ok_or(StandardProgramError::InvalidField)?
                        .field(),
                );
                fields.push(Fp::from(*timeout_height));
                fields.push(Fp::from(u64::from(u8::from(*refund))));
            }
        }
        Ok(fields)
    }

    pub fn schema_hash(kind: StandardProgramKind) -> [u8; 32] {
        let hash = match kind {
            StandardProgramKind::Nft => NFT_SCHEMA_HASH,
            StandardProgramKind::Vesting => VESTING_SCHEMA_HASH,
            StandardProgramKind::Multisig => MULTISIG_SCHEMA_HASH,
            StandardProgramKind::Swap => SWAP_SCHEMA_HASH,
        };
        debug_assert_eq!(hash, Self::derived_schema_hash(kind));
        hash
    }

    fn derived_schema_hash(kind: StandardProgramKind) -> [u8; 32] {
        let suffix = match kind {
            StandardProgramKind::Nft => {
                b"nft:kind,collection[2],token[2],serial,nonce,prior,next,result".as_slice()
            }
            StandardProgramKind::Vesting => {
                b"vesting:kind,schedule[2],beneficiary[2],unlock,prior,next,result".as_slice()
            }
            StandardProgramKind::Multisig => {
                b"multisig:kind,policy,action[2],threshold,count,prior,next,result".as_slice()
            }
            StandardProgramKind::Swap => {
                b"swap:kind,id[2],hashlock,timeout,refund,prior,next,result".as_slice()
            }
        };
        let mut hash = Sha256::new();
        hash.update(STANDARD_SCHEMA_DOMAIN);
        hash.update([kind as u8]);
        hash.update((suffix.len() as u64).to_le_bytes());
        hash.update(suffix);
        hash.finalize().into()
    }
}

pub fn contextual_public_inputs(
    context: &ProgramContext,
    expected: StandardProgramKind,
) -> Result<Vec<Fp>, StandardProgramError> {
    let application = StandardApplication::decode(&context.application_data)?;
    if application.kind() != expected {
        return Err(StandardProgramError::WrongKind);
    }
    application.validate_context(context)?;
    let mut inputs = context
        .public_inputs()
        .map_err(|_| StandardProgramError::InvalidField)?;
    inputs.extend(application.public_suffix()?);
    let state = context
        .state
        .as_ref()
        .ok_or(StandardProgramError::MissingState)?;
    inputs.push(
        CanonicalField::from_bytes(state.prior)
            .ok_or(StandardProgramError::InvalidField)?
            .field(),
    );
    inputs.push(
        CanonicalField::from_bytes(state.next)
            .ok_or(StandardProgramError::InvalidField)?
            .field(),
    );
    inputs.push(Fp::one());
    Ok(inputs)
}

pub fn kind_for_schema(hash: &[u8; 32]) -> Option<StandardProgramKind> {
    [
        StandardProgramKind::Nft,
        StandardProgramKind::Vesting,
        StandardProgramKind::Multisig,
        StandardProgramKind::Swap,
    ]
    .into_iter()
    .find(|kind| StandardApplication::schema_hash(*kind) == *hash)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;

    use super::*;
    use crate::program_context::ProgramStateTransition;

    fn context(application_data: Vec<u8>, valid_from_height: u64) -> ProgramContext {
        ProgramContext {
            network_id: [1; 16],
            anchor: Fp::from(2).to_repr(),
            valid_from_height,
            expiry_height: 100,
            fee: 0,
            call_index: 0,
            program_id: [3; 32],
            function_id: 4,
            spends_digest: [5; 32],
            outputs_digest: [6; 32],
            call_headers_digest: [7; 32],
            state: Some(ProgramStateTransition {
                prior: Fp::from(8).to_repr(),
                next: Fp::from(9).to_repr(),
            }),
            application_data,
        }
    }

    #[test]
    fn vesting_and_refund_timelocks_use_consensus_valid_from() {
        let mut vesting = vec![1, 2];
        vesting.extend([1; 32]);
        vesting.extend([2; 32]);
        vesting.push(50);
        assert_eq!(
            contextual_public_inputs(&context(vesting.clone(), 49), StandardProgramKind::Vesting),
            Err(StandardProgramError::Timelock)
        );
        assert!(
            contextual_public_inputs(&context(vesting, 50), StandardProgramKind::Vesting).is_ok()
        );

        let mut refund = vec![1, 4];
        refund.extend([3; 32]);
        refund.extend(Fp::from(4).to_repr());
        refund.push(60);
        refund.push(1);
        assert_eq!(
            contextual_public_inputs(&context(refund, 59), StandardProgramKind::Swap),
            Err(StandardProgramError::Timelock)
        );
    }

    #[test]
    fn profiles_reject_trailing_wrong_kind_and_invalid_multisig() {
        let mut nft = vec![1, 1];
        nft.extend([1; 32]);
        nft.extend([2; 32]);
        nft.extend([0, 0]);
        nft.push(0);
        assert!(matches!(
            StandardApplication::decode(&nft),
            Err(StandardProgramError::Decode(DecodeError::TrailingData))
        ));

        let mut multisig = vec![1, 3];
        multisig.extend([1; 32]);
        multisig.extend([2; 32]);
        multisig.extend([3, 2]);
        assert_eq!(
            StandardApplication::decode(&multisig),
            Err(StandardProgramError::InvalidField)
        );

        let valid_nft = StandardApplication::Nft {
            collection_id: [1; 32],
            token_id: [2; 32],
            serial: 3,
            transfer_nonce: 4,
        };
        let encoded = valid_nft.encode().unwrap();
        assert_eq!(StandardApplication::decode(&encoded).unwrap(), valid_nft);
        assert_eq!(
            contextual_public_inputs(&context(encoded, 1), StandardProgramKind::Vesting),
            Err(StandardProgramError::WrongKind)
        );
    }

    #[test]
    fn standard_schema_hashes_are_frozen() {
        for kind in [
            StandardProgramKind::Nft,
            StandardProgramKind::Vesting,
            StandardProgramKind::Multisig,
            StandardProgramKind::Swap,
        ] {
            assert_eq!(
                StandardApplication::schema_hash(kind),
                StandardApplication::derived_schema_hash(kind)
            );
        }
    }
}
