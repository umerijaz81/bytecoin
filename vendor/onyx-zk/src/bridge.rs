//! Canonical one-way legacy-to-Onyx bridge envelope.
//!
//! Legacy ownership is checked by the C++ consensus layer against the disclosed amount/global
//! output index using a one-member CryptoNote ring signature and key image. The Halo2 bridge
//! circuit separately proves that the sole hidden Onyx note carries `legacy_amount - fee`.

use sha2::{Digest, Sha256};

use crate::transaction::{
    read_bytes, read_public_output, validate_public_output, write_bytes, write_public_output,
    PublicOutput, TransactionError, MAX_BACKEND_ID_BYTES, MAX_PROOF_BYTES,
};
use crate::types::{write_varint, DecodeError, Reader, NETWORK_ID_BYTES};

pub const BRIDGE_VERSION: u8 = 1;
const BRIDGE_SIGHASH_DOMAIN: &[u8] = b"bytecoin.onyx.v6.bridge-sighash";
const BRIDGE_ID_DOMAIN: &[u8] = b"bytecoin.onyx.v6.bridge-id";
const BRIDGE_ENCRYPTION_BINDING_DOMAIN: &[u8] = b"bytecoin.onyx.v6.bridge-encryption-binding";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgePreimage {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub expiry_height: u64,
    pub fee: u64,
    pub legacy_amount: u64,
    pub legacy_stack_index: u64,
    pub legacy_key_image: [u8; 32],
    pub output: PublicOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedBridge {
    pub preimage: BridgePreimage,
    pub backend_id: String,
    pub proof: Vec<u8>,
    /// Native CryptoNote signature bytes; decoded and verified only by the C++ consensus layer.
    pub ownership_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeError {
    Decode(DecodeError),
    Transaction(TransactionError),
    InvalidValue,
    InvalidBackendId,
    ProofTooLarge,
}

impl From<DecodeError> for BridgeError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<TransactionError> for BridgeError {
    fn from(value: TransactionError) -> Self {
        Self::Transaction(value)
    }
}

impl BridgePreimage {
    fn validate(&self) -> Result<(), BridgeError> {
        if self.legacy_amount == 0 || self.fee >= self.legacy_amount {
            return Err(BridgeError::InvalidValue);
        }
        validate_public_output(&self.output)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, BridgeError> {
        self.validate()?;
        let mut out = Vec::new();
        out.push(BRIDGE_VERSION);
        out.extend_from_slice(&self.network_id);
        write_varint(self.expiry_height, &mut out);
        write_varint(self.fee, &mut out);
        write_varint(self.legacy_amount, &mut out);
        write_varint(self.legacy_stack_index, &mut out);
        out.extend_from_slice(&self.legacy_key_image);
        write_public_output(&self.output, &mut out);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BridgeError> {
        let mut reader = Reader::new(input);
        if reader.byte()? != BRIDGE_VERSION {
            return Err(DecodeError::WrongVersion.into());
        }
        let result = Self {
            network_id: reader.array()?,
            expiry_height: reader.varint()?,
            fee: reader.varint()?,
            legacy_amount: reader.varint()?,
            legacy_stack_index: reader.varint()?,
            legacy_key_image: reader.array()?,
            output: read_public_output(&mut reader)?,
        };
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        result.validate()?;
        Ok(result)
    }

    pub fn encryption_binding(&self) -> Result<[u8; 32], BridgeError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(BRIDGE_ENCRYPTION_BINDING_DOMAIN);
        hash.update([BRIDGE_VERSION]);
        hash.update(self.network_id);
        hash.update(self.expiry_height.to_le_bytes());
        hash.update(self.fee.to_le_bytes());
        hash.update(self.legacy_amount.to_le_bytes());
        hash.update(self.legacy_stack_index.to_le_bytes());
        hash.update(self.legacy_key_image);
        hash.update(self.output.commitment.bytes());
        hash.update(self.output.value_commitment);
        Ok(hash.finalize().into())
    }
}

impl AuthorizedBridge {
    fn validate(&self) -> Result<(), BridgeError> {
        self.preimage.validate()?;
        if self.backend_id.is_empty()
            || self.backend_id.len() > MAX_BACKEND_ID_BYTES
            || !self.backend_id.is_ascii()
        {
            return Err(BridgeError::InvalidBackendId);
        }
        if self.proof.is_empty() || self.proof.len() > MAX_PROOF_BYTES {
            return Err(BridgeError::ProofTooLarge);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, BridgeError> {
        self.validate()?;
        let preimage = self.preimage.encode()?;
        let mut out = Vec::new();
        write_bytes(&preimage, &mut out);
        write_bytes(self.backend_id.as_bytes(), &mut out);
        write_bytes(&self.proof, &mut out);
        out.extend_from_slice(&self.ownership_signature);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BridgeError> {
        let mut reader = Reader::new(input);
        let preimage = BridgePreimage::decode(&read_bytes(&mut reader, 64 * 1024)?)?;
        let backend = read_bytes(&mut reader, MAX_BACKEND_ID_BYTES)?;
        let backend_id = String::from_utf8(backend).map_err(|_| BridgeError::InvalidBackendId)?;
        let proof = read_bytes(&mut reader, MAX_PROOF_BYTES)?;
        let ownership_signature = reader.array()?;
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        let result = Self {
            preimage,
            backend_id,
            proof,
            ownership_signature,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn ownership_sighash(&self) -> Result<[u8; 32], BridgeError> {
        let mut hash = Sha256::new();
        hash.update(BRIDGE_SIGHASH_DOMAIN);
        hash.update(self.preimage.encode()?);
        hash.update(self.backend_id.as_bytes());
        hash.update(&self.proof);
        Ok(hash.finalize().into())
    }

    pub fn id(&self) -> Result<[u8; 32], BridgeError> {
        let mut hash = Sha256::new();
        hash.update(BRIDGE_ID_DOMAIN);
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::pasta::Fp;

    use crate::state::CanonicalField;
    use crate::value_commitment_circuit::value_commitment_bytes;

    use super::*;

    fn bridge() -> AuthorizedBridge {
        AuthorizedBridge {
            preimage: BridgePreimage {
                network_id: [1; NETWORK_ID_BYTES],
                expiry_height: 100,
                fee: 5,
                legacy_amount: 30,
                legacy_stack_index: 42,
                legacy_key_image: [7; 32],
                output: PublicOutput {
                    commitment: CanonicalField::from_field(Fp::from(9)),
                    value_commitment: value_commitment_bytes(25, Fp::from(11)),
                    ephemeral_key: [12; 32],
                    ciphertext: vec![13; 48],
                    outgoing_ciphertext: vec![14; 32],
                },
            },
            backend_id: "halo2-ipa-pasta/onyx-bridge-v1".to_owned(),
            proof: vec![15; 128],
            ownership_signature: [16; 64],
        }
    }

    #[test]
    fn bridge_round_trip_and_id_bind_every_byte() {
        let bridge = bridge();
        let encoded = bridge.encode().unwrap();
        assert_eq!(AuthorizedBridge::decode(&encoded).unwrap(), bridge);
        let mut changed = bridge.clone();
        changed.preimage.legacy_stack_index += 1;
        assert_ne!(bridge.id().unwrap(), changed.id().unwrap());
        assert_ne!(
            bridge.ownership_sighash().unwrap(),
            changed.ownership_sighash().unwrap()
        );
        let binding = bridge.preimage.encryption_binding().unwrap();
        let mut ciphertext = bridge.preimage.clone();
        ciphertext.output.ciphertext[0] ^= 1;
        ciphertext.output.ephemeral_key[0] ^= 1;
        assert_eq!(ciphertext.encryption_binding().unwrap(), binding);
    }

    #[test]
    fn bridge_rejects_inflation_and_noncanonical_encodings() {
        let mut invalid = bridge();
        invalid.preimage.fee = invalid.preimage.legacy_amount;
        assert_eq!(invalid.encode(), Err(BridgeError::InvalidValue));

        let encoded = bridge().encode().unwrap();
        assert!(AuthorizedBridge::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            AuthorizedBridge::decode(&trailing),
            Err(BridgeError::Decode(DecodeError::TrailingData))
        ));
    }
}
