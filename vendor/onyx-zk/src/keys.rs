//! Onyx O1 key separation and authenticated note encryption.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ff::{FromUniformBytes, PrimeField};
use halo2_proofs::pasta::Fp;
use hkdf::Hkdf;
use pasta_curves::pallas;
use rand::RngCore;
use reddsa::orchard::SpendAuth;
use reddsa::{SigningKey, VerificationKey};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::state::CanonicalField;
use crate::types::{DecodeError, NotePlaintext, DIVERSIFIER_BYTES, NETWORK_ID_BYTES};

const KEY_DOMAIN: &[u8] = b"bytecoin.onyx.v6.keys";
const ENCRYPTION_DOMAIN: &[u8] = b"bytecoin.onyx.v6.note-encryption";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyError {
    Derivation,
    RecipientMismatch,
    InvalidSharedSecret,
    Encryption,
    Decryption,
    Decode(DecodeError),
    CommitmentMismatch,
    NetworkMismatch,
    InvalidViewingKey,
}

impl From<DecodeError> for KeyError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

pub struct MasterSeed(Zeroizing<[u8; 32]>);

impl MasterSeed {
    pub fn new(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    pub fn derive(&self, network_id: [u8; NETWORK_ID_BYTES]) -> Result<KeyBundle, KeyError> {
        let mut spend_wide = Zeroizing::new([0u8; 64]);
        expand(self.0.as_ref(), &network_id, b"spend", spend_wide.as_mut())?;
        let spend = pallas::Scalar::from_uniform_bytes(&spend_wide).to_repr();
        let incoming = derive_32(self.0.as_ref(), &network_id, b"incoming-view")?;
        let outgoing = derive_32(self.0.as_ref(), &network_id, b"outgoing-view")?;
        let diversifier = derive_32(self.0.as_ref(), &network_id, b"diversifier")?;
        let mut wide = Zeroizing::new([0u8; 64]);
        expand(self.0.as_ref(), &network_id, b"nullifier", wide.as_mut())?;
        let nullifier = CanonicalField::from_field(Fp::from_uniform_bytes(&wide));
        Ok(KeyBundle {
            network_id,
            spend: Zeroizing::new(spend),
            incoming: Zeroizing::new(incoming),
            outgoing: Zeroizing::new(outgoing),
            diversifier: Zeroizing::new(diversifier),
            nullifier,
        })
    }
}

pub struct KeyBundle {
    network_id: [u8; NETWORK_ID_BYTES],
    spend: Zeroizing<[u8; 32]>,
    incoming: Zeroizing<[u8; 32]>,
    outgoing: Zeroizing<[u8; 32]>,
    diversifier: Zeroizing<[u8; 32]>,
    nullifier: CanonicalField,
}

pub struct FullViewingKey {
    network_id: [u8; NETWORK_ID_BYTES],
    incoming: Zeroizing<[u8; 32]>,
    outgoing: Zeroizing<[u8; 32]>,
    diversifier: Zeroizing<[u8; 32]>,
    nullifier: CanonicalField,
    spend_authority_key: [u8; 32],
}

const FULL_VIEWING_KEY_VERSION: u8 = 1;
pub const FULL_VIEWING_KEY_BYTES: usize = 1 + NETWORK_ID_BYTES + 32 * 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientAddress {
    pub network_id: [u8; NETWORK_ID_BYTES],
    pub diversifier: [u8; DIVERSIFIER_BYTES],
    pub transmission_key: [u8; 32],
    pub spend_authority_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedNote {
    pub ephemeral_key: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub outgoing_ciphertext: Vec<u8>,
}

impl KeyBundle {
    fn spend_authority_key(&self) -> Result<[u8; 32], KeyError> {
        let signing =
            SigningKey::<SpendAuth>::try_from(*self.spend).map_err(|_| KeyError::Derivation)?;
        Ok(VerificationKey::from(&signing).into())
    }

    pub fn address(&self, index: u32) -> Result<RecipientAddress, KeyError> {
        self.full_viewing_key()?.address(index)
    }

    pub fn nullifier_key(&self) -> CanonicalField {
        self.nullifier
    }

    pub fn outgoing_viewing_key(&self) -> [u8; 32] {
        *self.outgoing
    }

    pub fn full_viewing_key(&self) -> Result<FullViewingKey, KeyError> {
        Ok(FullViewingKey {
            network_id: self.network_id,
            incoming: Zeroizing::new(*self.incoming),
            outgoing: Zeroizing::new(*self.outgoing),
            diversifier: Zeroizing::new(*self.diversifier),
            nullifier: self.nullifier,
            spend_authority_key: self.spend_authority_key()?,
        })
    }

    pub fn spend_key_fingerprint(&self) -> Result<[u8; 32], KeyError> {
        derive_32(self.spend.as_ref(), &self.network_id, b"spend-fingerprint")
    }

    pub(crate) fn spend_key_bytes(&self) -> [u8; 32] {
        *self.spend
    }

    pub fn encrypt_note(
        &self,
        note: &NotePlaintext,
        recipient: &RecipientAddress,
        tx_binding: [u8; 32],
        output_index: u32,
    ) -> Result<EncryptedNote, KeyError> {
        let mut ephemeral = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral);
        encrypt_note_with_ephemeral(
            note,
            recipient,
            &self.outgoing,
            ephemeral,
            tx_binding,
            output_index,
        )
    }

    pub fn decrypt_received_note(
        &self,
        encrypted: &EncryptedNote,
        commitment: CanonicalField,
        tx_binding: [u8; 32],
        output_index: u32,
    ) -> Result<NotePlaintext, KeyError> {
        self.full_viewing_key()?.decrypt_received_note(
            encrypted,
            commitment,
            tx_binding,
            output_index,
        )
    }

    pub fn decrypt_sent_note(
        &self,
        encrypted: &EncryptedNote,
        commitment: CanonicalField,
        tx_binding: [u8; 32],
        output_index: u32,
    ) -> Result<NotePlaintext, KeyError> {
        self.full_viewing_key()?
            .decrypt_sent_note(encrypted, commitment, tx_binding, output_index)
    }
}

impl FullViewingKey {
    pub fn encode(&self) -> [u8; FULL_VIEWING_KEY_BYTES] {
        let mut out = [0u8; FULL_VIEWING_KEY_BYTES];
        out[0] = FULL_VIEWING_KEY_VERSION;
        out[1..17].copy_from_slice(&self.network_id);
        out[17..49].copy_from_slice(self.incoming.as_ref());
        out[49..81].copy_from_slice(self.outgoing.as_ref());
        out[81..113].copy_from_slice(self.diversifier.as_ref());
        out[113..145].copy_from_slice(&self.nullifier.bytes());
        out[145..177].copy_from_slice(&self.spend_authority_key);
        out
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KeyError> {
        if encoded.len() != FULL_VIEWING_KEY_BYTES || encoded[0] != FULL_VIEWING_KEY_VERSION {
            return Err(KeyError::InvalidViewingKey);
        }
        let network_id = encoded[1..17].try_into().unwrap();
        let incoming = encoded[17..49].try_into().unwrap();
        let outgoing = encoded[49..81].try_into().unwrap();
        let diversifier = encoded[81..113].try_into().unwrap();
        let nullifier = CanonicalField::from_bytes(encoded[113..145].try_into().unwrap())
            .ok_or(KeyError::InvalidViewingKey)?;
        let spend_authority_key: [u8; 32] = encoded[145..177].try_into().unwrap();
        VerificationKey::<SpendAuth>::try_from(spend_authority_key)
            .map_err(|_| KeyError::InvalidViewingKey)?;
        Ok(Self {
            network_id,
            incoming: Zeroizing::new(incoming),
            outgoing: Zeroizing::new(outgoing),
            diversifier: Zeroizing::new(diversifier),
            nullifier,
            spend_authority_key,
        })
    }

    pub fn network_id(&self) -> [u8; NETWORK_ID_BYTES] {
        self.network_id
    }

    pub fn nullifier_key(&self) -> CanonicalField {
        self.nullifier
    }

    pub fn address(&self, index: u32) -> Result<RecipientAddress, KeyError> {
        let incoming = StaticSecret::from(*self.incoming);
        let transmission_key = PublicKey::from(&incoming).to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), self.diversifier.as_ref());
        let mut diversifier = [0u8; DIVERSIFIER_BYTES];
        let mut info = Vec::with_capacity(NETWORK_ID_BYTES + 16);
        info.extend_from_slice(&self.network_id);
        info.extend_from_slice(b"address");
        info.extend_from_slice(&index.to_le_bytes());
        hk.expand(&info, &mut diversifier)
            .map_err(|_| KeyError::Derivation)?;
        Ok(RecipientAddress {
            network_id: self.network_id,
            diversifier,
            transmission_key,
            spend_authority_key: self.spend_authority_key,
        })
    }

    pub fn decrypt_received_note(
        &self,
        encrypted: &EncryptedNote,
        commitment: CanonicalField,
        tx_binding: [u8; 32],
        output_index: u32,
    ) -> Result<NotePlaintext, KeyError> {
        let secret = StaticSecret::from(*self.incoming);
        let shared = secret.diffie_hellman(&PublicKey::from(encrypted.ephemeral_key));
        if shared.as_bytes() == &[0u8; 32] {
            return Err(KeyError::InvalidSharedSecret);
        }
        let (key, nonce) = derive_note_aead(
            shared.as_bytes(),
            &self.network_id,
            commitment,
            &encrypted.ephemeral_key,
            output_index,
            b"incoming",
        )?;
        let aad = associated_data(
            &self.network_id,
            tx_binding,
            output_index,
            commitment,
            &encrypted.ephemeral_key,
        );
        let plaintext = decrypt(&key, &nonce, &encrypted.ciphertext, &aad)?;
        validate_decrypted_note(
            plaintext,
            self.network_id,
            PublicKey::from(&secret).to_bytes(),
            self.spend_authority_key,
            commitment,
        )
    }

    pub fn decrypt_sent_note(
        &self,
        encrypted: &EncryptedNote,
        commitment: CanonicalField,
        tx_binding: [u8; 32],
        output_index: u32,
    ) -> Result<NotePlaintext, KeyError> {
        let (key, nonce) = derive_note_aead(
            self.outgoing.as_ref(),
            &self.network_id,
            commitment,
            &encrypted.ephemeral_key,
            output_index,
            b"outgoing",
        )?;
        let aad = associated_data(
            &self.network_id,
            tx_binding,
            output_index,
            commitment,
            &encrypted.ephemeral_key,
        );
        let plaintext = decrypt(&key, &nonce, &encrypted.outgoing_ciphertext, &aad)?;
        let note = NotePlaintext::decode(&plaintext)?;
        if note.network_id != self.network_id {
            return Err(KeyError::NetworkMismatch);
        }
        if note.commitment()? != commitment {
            return Err(KeyError::CommitmentMismatch);
        }
        Ok(note)
    }
}

pub fn encrypt_note_with_ephemeral(
    note: &NotePlaintext,
    recipient: &RecipientAddress,
    sender_outgoing_key: &[u8; 32],
    ephemeral_secret: [u8; 32],
    tx_binding: [u8; 32],
    output_index: u32,
) -> Result<EncryptedNote, KeyError> {
    if note.network_id != recipient.network_id {
        return Err(KeyError::NetworkMismatch);
    }
    if note.diversifier != recipient.diversifier
        || note.transmission_key != recipient.transmission_key
        || note.spend_authority_key != recipient.spend_authority_key
    {
        return Err(KeyError::RecipientMismatch);
    }
    let commitment = note.commitment()?;
    let ephemeral = StaticSecret::from(ephemeral_secret);
    let ephemeral_key = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(recipient.transmission_key));
    if shared.as_bytes() == &[0u8; 32] {
        return Err(KeyError::InvalidSharedSecret);
    }
    let aad = associated_data(
        &note.network_id,
        tx_binding,
        output_index,
        commitment,
        &ephemeral_key,
    );
    let plaintext = note.encode()?;
    let (incoming_key, incoming_nonce) = derive_note_aead(
        shared.as_bytes(),
        &note.network_id,
        commitment,
        &ephemeral_key,
        output_index,
        b"incoming",
    )?;
    let (outgoing_key, outgoing_nonce) = derive_note_aead(
        sender_outgoing_key,
        &note.network_id,
        commitment,
        &ephemeral_key,
        output_index,
        b"outgoing",
    )?;
    Ok(EncryptedNote {
        ephemeral_key,
        ciphertext: encrypt(&incoming_key, &incoming_nonce, &plaintext, &aad)?,
        outgoing_ciphertext: encrypt(&outgoing_key, &outgoing_nonce, &plaintext, &aad)?,
    })
}

fn validate_decrypted_note(
    plaintext: Vec<u8>,
    network_id: [u8; NETWORK_ID_BYTES],
    transmission_key: [u8; 32],
    spend_authority_key: [u8; 32],
    commitment: CanonicalField,
) -> Result<NotePlaintext, KeyError> {
    let note = NotePlaintext::decode(&plaintext)?;
    if note.network_id != network_id {
        return Err(KeyError::NetworkMismatch);
    }
    if note.transmission_key != transmission_key || note.spend_authority_key != spend_authority_key
    {
        return Err(KeyError::RecipientMismatch);
    }
    if note.commitment()? != commitment {
        return Err(KeyError::CommitmentMismatch);
    }
    Ok(note)
}

fn expand(
    seed: &[u8],
    network_id: &[u8; NETWORK_ID_BYTES],
    label: &[u8],
    out: &mut [u8],
) -> Result<(), KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), seed);
    let mut info = Vec::with_capacity(network_id.len() + label.len());
    info.extend_from_slice(network_id);
    info.extend_from_slice(label);
    hk.expand(&info, out).map_err(|_| KeyError::Derivation)
}

fn derive_32(
    seed: &[u8],
    network_id: &[u8; NETWORK_ID_BYTES],
    label: &[u8],
) -> Result<[u8; 32], KeyError> {
    let mut out = [0u8; 32];
    expand(seed, network_id, label, &mut out)?;
    Ok(out)
}

fn derive_note_aead(
    secret: &[u8],
    network_id: &[u8; NETWORK_ID_BYTES],
    commitment: CanonicalField,
    ephemeral_key: &[u8; 32],
    output_index: u32,
    direction: &[u8],
) -> Result<([u8; 32], [u8; 12]), KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(ENCRYPTION_DOMAIN), secret);
    let mut info = Vec::new();
    info.extend_from_slice(network_id);
    info.extend_from_slice(&commitment.bytes());
    info.extend_from_slice(ephemeral_key);
    info.extend_from_slice(&output_index.to_le_bytes());
    info.extend_from_slice(direction);
    let mut material = Zeroizing::new([0u8; 44]);
    hk.expand(&info, material.as_mut())
        .map_err(|_| KeyError::Derivation)?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&material[..32]);
    nonce.copy_from_slice(&material[32..]);
    Ok((key, nonce))
}

fn associated_data(
    network_id: &[u8; NETWORK_ID_BYTES],
    tx_binding: [u8; 32],
    output_index: u32,
    commitment: CanonicalField,
    ephemeral_key: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(network_id);
    aad.extend_from_slice(&tx_binding);
    aad.extend_from_slice(&output_index.to_le_bytes());
    aad.extend_from_slice(&commitment.bytes());
    aad.extend_from_slice(ephemeral_key);
    aad
}

fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KeyError> {
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeyError::Encryption)
}

fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KeyError> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| KeyError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(address: &RecipientAddress) -> NotePlaintext {
        NotePlaintext {
            network_id: address.network_id,
            program_id: [2; 32],
            asset_id: [3; 32],
            value: 42,
            diversifier: address.diversifier,
            transmission_key: address.transmission_key,
            spend_authority_key: address.spend_authority_key,
            rho: CanonicalField::from_field(Fp::from(6)),
            randomness: CanonicalField::from_field(Fp::from(7)),
            memo: b"encrypted onyx note".to_vec(),
        }
    }

    #[test]
    fn key_hierarchy_is_deterministic_and_network_separated() {
        let seed = [7; 32];
        let a = MasterSeed::new(seed).derive([1; NETWORK_ID_BYTES]).unwrap();
        let b = MasterSeed::new(seed).derive([1; NETWORK_ID_BYTES]).unwrap();
        let other = MasterSeed::new(seed).derive([2; NETWORK_ID_BYTES]).unwrap();
        assert_eq!(a.address(0), b.address(0));
        assert_ne!(a.address(0), a.address(1));
        assert_ne!(a.address(0), other.address(0));
        assert_eq!(a.nullifier_key(), b.nullifier_key());
        assert_ne!(a.nullifier_key(), other.nullifier_key());
        let viewing = a.full_viewing_key().unwrap();
        let encoded = viewing.encode();
        let restored = FullViewingKey::decode(&encoded).unwrap();
        assert_eq!(restored.network_id(), [1; NETWORK_ID_BYTES]);
        assert_eq!(restored.address(7), a.address(7));
        assert_eq!(restored.nullifier_key(), a.nullifier_key());
        let mut wrong_version = encoded;
        wrong_version[0] += 1;
        assert!(matches!(
            FullViewingKey::decode(&wrong_version),
            Err(KeyError::InvalidViewingKey)
        ));
    }

    #[test]
    fn incoming_and_outgoing_note_recovery_round_trip() {
        let sender = MasterSeed::new([1; 32])
            .derive([9; NETWORK_ID_BYTES])
            .unwrap();
        let receiver = MasterSeed::new([2; 32])
            .derive([9; NETWORK_ID_BYTES])
            .unwrap();
        let address = receiver.address(3).unwrap();
        let note = note(&address);
        let commitment = note.commitment().unwrap();
        let encrypted = encrypt_note_with_ephemeral(
            &note,
            &address,
            &sender.outgoing_viewing_key(),
            [4; 32],
            [5; 32],
            0,
        )
        .unwrap();
        assert_eq!(
            receiver.decrypt_received_note(&encrypted, commitment, [5; 32], 0),
            Ok(note.clone())
        );
        assert_eq!(
            sender.decrypt_sent_note(&encrypted, commitment, [5; 32], 0),
            Ok(note)
        );
    }

    #[test]
    fn note_encryption_binds_transaction_output_and_commitment() {
        let sender = MasterSeed::new([1; 32])
            .derive([9; NETWORK_ID_BYTES])
            .unwrap();
        let receiver = MasterSeed::new([2; 32])
            .derive([9; NETWORK_ID_BYTES])
            .unwrap();
        let address = receiver.address(0).unwrap();
        let note = note(&address);
        let commitment = note.commitment().unwrap();
        let mut encrypted = encrypt_note_with_ephemeral(
            &note,
            &address,
            &sender.outgoing_viewing_key(),
            [4; 32],
            [5; 32],
            0,
        )
        .unwrap();
        assert_eq!(
            receiver.decrypt_received_note(&encrypted, commitment, [6; 32], 0),
            Err(KeyError::Decryption)
        );
        assert_eq!(
            receiver.decrypt_received_note(&encrypted, commitment, [5; 32], 1),
            Err(KeyError::Decryption)
        );
        encrypted.ciphertext[0] ^= 1;
        assert_eq!(
            receiver.decrypt_received_note(&encrypted, commitment, [5; 32], 0),
            Err(KeyError::Decryption)
        );
    }
}
