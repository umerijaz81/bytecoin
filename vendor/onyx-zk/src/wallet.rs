//! Deterministic Onyx wallet scanning and witness state.

use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use halo2_proofs::pasta::Fp;
use pasta_curves::pallas;
use rand::RngCore;

use crate::bridge::{AuthorizedBridge, BridgePreimage};
use crate::keys::{EncryptedNote, FullViewingKey, KeyBundle, RecipientAddress};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::proof::{create_bridge_proof, BridgeWitness, BRIDGE_BACKEND};
use crate::state::{CanonicalField, MerklePath, WitnessError, WitnessTree, ONYX_MERKLE_DEPTH};
use crate::transaction::{AuthorizedTransaction, PublicOutput};
use crate::types::NATIVE_ASSET_ID;
use crate::types::{write_varint, DecodeError, NotePlaintext, Reader};
use crate::value_commitment_circuit::value_commitment_bytes;

const WALLET_SNAPSHOT_VERSION: u8 = 1;
const MAX_WALLET_LEAVES: usize = 1_000_000;
const MAX_WALLET_NOTES: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletNote {
    pub commitment: CanonicalField,
    pub position: u64,
    pub plaintext: NotePlaintext,
    pub spent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletError {
    WrongNetwork,
    Transaction,
    Tree(WitnessError),
    Note(DecodeError),
    Snapshot,
}

#[derive(Debug)]
pub enum WalletBuildError {
    InvalidValue,
    InvalidRecipient,
    Crypto,
}

pub fn build_bridge(
    sender: &KeyBundle,
    recipient: &RecipientAddress,
    expiry_height: u64,
    fee: u64,
    legacy_amount: u64,
    legacy_stack_index: u64,
    legacy_key_image: [u8; 32],
    memo: Vec<u8>,
    circuit_k: u32,
) -> Result<AuthorizedBridge, WalletBuildError> {
    let note_value = legacy_amount
        .checked_sub(fee)
        .filter(|value| *value != 0)
        .ok_or(WalletBuildError::InvalidValue)?;
    if recipient.network_id
        != sender
            .full_viewing_key()
            .map_err(|_| WalletBuildError::Crypto)?
            .network_id()
    {
        return Err(WalletBuildError::InvalidRecipient);
    }
    let mut rho_wide = [0u8; 64];
    let mut randomness_wide = [0u8; 64];
    let mut value_randomness_wide = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut rho_wide);
    rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
    rand::rngs::OsRng.fill_bytes(&mut value_randomness_wide);
    let rho = CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide));
    let randomness = CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide));
    let value_randomness = Fp::from_uniform_bytes(&value_randomness_wide);
    let note = NotePlaintext {
        network_id: recipient.network_id,
        program_id: [0; 32],
        asset_id: NATIVE_ASSET_ID,
        value: note_value,
        diversifier: recipient.diversifier,
        transmission_key: recipient.transmission_key,
        spend_authority_key: recipient.spend_authority_key,
        rho,
        randomness,
        memo,
    };
    let commitment = note
        .commitment()
        .map_err(|_| WalletBuildError::InvalidRecipient)?;
    let value_commitment_bytes = value_commitment_bytes(note_value, value_randomness);
    let value_commitment =
        Option::<pallas::Point>::from(pallas::Point::from_bytes(&value_commitment_bytes))
            .ok_or(WalletBuildError::Crypto)?
            .to_affine();
    let mut preimage = BridgePreimage {
        network_id: recipient.network_id,
        expiry_height,
        fee,
        legacy_amount,
        legacy_stack_index,
        legacy_key_image,
        output: PublicOutput {
            commitment,
            value_commitment: value_commitment_bytes,
            ephemeral_key: [0; 32],
            ciphertext: vec![],
            outgoing_ciphertext: vec![],
        },
    };
    let binding = preimage
        .encryption_binding()
        .map_err(|_| WalletBuildError::Crypto)?;
    let encrypted = sender
        .encrypt_note(&note, recipient, binding, 0)
        .map_err(|_| WalletBuildError::Crypto)?;
    preimage.output.ephemeral_key = encrypted.ephemeral_key;
    preimage.output.ciphertext = encrypted.ciphertext;
    preimage.output.outgoing_ciphertext = encrypted.outgoing_ciphertext;
    let note_inputs: [Fp; NOTE_COMMITMENT_INPUTS] = note
        .commitment_inputs()
        .map_err(|_| WalletBuildError::Crypto)?;
    let proof = create_bridge_proof(
        circuit_k,
        &preimage,
        &BridgeWitness {
            output_note: note_inputs,
            output_value_randomness: value_randomness,
            output_value_commitment: value_commitment,
        },
    )
    .map_err(|_| WalletBuildError::Crypto)?;
    Ok(AuthorizedBridge {
        preimage,
        backend_id: BRIDGE_BACKEND.to_owned(),
        proof,
        ownership_signature: [0; 64],
    })
}

impl From<WitnessError> for WalletError {
    fn from(value: WitnessError) -> Self {
        Self::Tree(value)
    }
}

#[derive(Clone)]
pub struct WalletState<const DEPTH: usize = ONYX_MERKLE_DEPTH> {
    network_id: [u8; 16],
    tree: WitnessTree<DEPTH>,
    notes: Vec<WalletNote>,
}

impl<const DEPTH: usize> WalletState<DEPTH> {
    pub fn new(network_id: [u8; 16]) -> Self {
        Self {
            network_id,
            tree: WitnessTree::default(),
            notes: Vec::new(),
        }
    }

    pub fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn notes(&self) -> &[WalletNote] {
        &self.notes
    }

    pub fn unspent_balance(&self) -> Result<u64, WalletError> {
        self.notes
            .iter()
            .filter(|note| !note.spent)
            .try_fold(0u64, |sum, note| {
                sum.checked_add(note.plaintext.value)
                    .ok_or(WalletError::Snapshot)
            })
    }

    pub fn witness(&self, note_index: usize) -> Result<MerklePath, WalletError> {
        let note = self.notes.get(note_index).ok_or(WalletError::Transaction)?;
        Ok(self.tree.witness(note.position)?)
    }

    pub fn encode_snapshot(&self) -> Result<Vec<u8>, WalletError> {
        let mut out = Vec::new();
        out.push(WALLET_SNAPSHOT_VERSION);
        out.push(DEPTH as u8);
        out.extend_from_slice(&self.network_id);
        write_varint(self.tree.leaf_count(), &mut out);
        for commitment in self.tree.commitments() {
            out.extend_from_slice(&commitment.bytes());
        }
        write_varint(self.notes.len() as u64, &mut out);
        for note in &self.notes {
            out.extend_from_slice(&note.commitment.bytes());
            write_varint(note.position, &mut out);
            out.push(u8::from(note.spent));
            let plaintext = note.plaintext.encode().map_err(WalletError::Note)?;
            write_varint(plaintext.len() as u64, &mut out);
            out.extend_from_slice(&plaintext);
        }
        Ok(out)
    }

    pub fn decode_snapshot(input: &[u8]) -> Result<Self, WalletError> {
        let mut reader = Reader::new(input);
        if reader.byte().map_err(WalletError::Note)? != WALLET_SNAPSHOT_VERSION
            || usize::from(reader.byte().map_err(WalletError::Note)?) != DEPTH
        {
            return Err(WalletError::Snapshot);
        }
        let network_id = reader.array().map_err(WalletError::Note)?;
        let leaf_count = bounded_count(
            reader.varint().map_err(WalletError::Note)?,
            MAX_WALLET_LEAVES,
        )?;
        let mut tree = WitnessTree::<DEPTH>::default();
        for _ in 0..leaf_count {
            tree.append(reader.field().map_err(WalletError::Note)?)?;
        }
        let note_count = bounded_count(
            reader.varint().map_err(WalletError::Note)?,
            MAX_WALLET_NOTES,
        )?;
        let mut notes = Vec::with_capacity(note_count);
        let mut positions = std::collections::HashSet::with_capacity(note_count);
        for _ in 0..note_count {
            let commitment = reader.field().map_err(WalletError::Note)?;
            let position = reader.varint().map_err(WalletError::Note)?;
            let spent = match reader.byte().map_err(WalletError::Note)? {
                0 => false,
                1 => true,
                _ => return Err(WalletError::Snapshot),
            };
            let plaintext_len = bounded_count(
                reader.varint().map_err(WalletError::Note)?,
                crate::types::MAX_MEMO_BYTES + 256,
            )?;
            let plaintext =
                NotePlaintext::decode(reader.take(plaintext_len).map_err(WalletError::Note)?)
                    .map_err(WalletError::Note)?;
            if position >= tree.leaf_count()
                || !positions.insert(position)
                || tree.commitments()[position as usize] != commitment
                || plaintext.network_id != network_id
                || plaintext.commitment().map_err(WalletError::Note)? != commitment
            {
                return Err(WalletError::Snapshot);
            }
            notes.push(WalletNote {
                commitment,
                position,
                plaintext,
                spent,
            });
        }
        if !reader.is_empty() {
            return Err(WalletError::Snapshot);
        }
        Ok(Self {
            network_id,
            tree,
            notes,
        })
    }

    pub fn scan_transfer(
        &mut self,
        keys: &FullViewingKey,
        transaction: &AuthorizedTransaction,
    ) -> Result<(), WalletError> {
        if transaction.preimage.network_id != self.network_id {
            return Err(WalletError::WrongNetwork);
        }
        let binding = transaction
            .preimage
            .encryption_binding()
            .map_err(|_| WalletError::Transaction)?;
        self.scan_outputs(keys, &transaction.preimage.outputs, binding)?;
        for note in &mut self.notes {
            if note.spent {
                continue;
            }
            let nullifier = note
                .plaintext
                .nullifier(keys.nullifier_key(), note.position);
            if transaction
                .preimage
                .spends
                .iter()
                .any(|spend| spend.nullifier == nullifier)
            {
                note.spent = true;
            }
        }
        Ok(())
    }

    pub fn scan_bridge(
        &mut self,
        keys: &FullViewingKey,
        bridge: &AuthorizedBridge,
    ) -> Result<(), WalletError> {
        if bridge.preimage.network_id != self.network_id {
            return Err(WalletError::WrongNetwork);
        }
        let binding = bridge
            .preimage
            .encryption_binding()
            .map_err(|_| WalletError::Transaction)?;
        self.scan_outputs(keys, std::slice::from_ref(&bridge.preimage.output), binding)
    }

    fn scan_outputs(
        &mut self,
        keys: &FullViewingKey,
        outputs: &[PublicOutput],
        binding: [u8; 32],
    ) -> Result<(), WalletError> {
        for (index, output) in outputs.iter().enumerate() {
            let position = self.tree.append(output.commitment)?;
            let encrypted = EncryptedNote {
                ephemeral_key: output.ephemeral_key,
                ciphertext: output.ciphertext.clone(),
                outgoing_ciphertext: output.outgoing_ciphertext.clone(),
            };
            if let Ok(plaintext) =
                keys.decrypt_received_note(&encrypted, output.commitment, binding, index as u32)
            {
                self.notes.push(WalletNote {
                    commitment: output.commitment,
                    position,
                    plaintext,
                    spent: false,
                });
            }
        }
        Ok(())
    }
}

fn bounded_count(value: u64, maximum: usize) -> Result<usize, WalletError> {
    if value > maximum as u64 {
        Err(WalletError::Snapshot)
    } else {
        Ok(value as usize)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::pasta::Fp;

    use crate::keys::{encrypt_note_with_ephemeral, MasterSeed};
    use crate::state::Nullifier;
    use crate::transaction::{PublicSpend, TransactionPreimage};
    use crate::types::{NotePlaintext, NATIVE_ASSET_ID, NETWORK_ID_BYTES};
    use crate::value_commitment_circuit::value_commitment_bytes;

    use super::*;

    #[test]
    fn scanner_tracks_all_leaves_recovers_notes_witnesses_and_spends() {
        let network = [9; NETWORK_ID_BYTES];
        let receiver = MasterSeed::new([2; 32]).derive(network).unwrap();
        let sender = MasterSeed::new([3; 32]).derive(network).unwrap();
        let receiver_view = receiver.full_viewing_key().unwrap();
        let sender_view = sender.full_viewing_key().unwrap();
        let address = receiver.address(0).unwrap();
        let note = NotePlaintext {
            network_id: network,
            program_id: [0; 32],
            asset_id: NATIVE_ASSET_ID,
            value: 25,
            diversifier: address.diversifier,
            transmission_key: address.transmission_key,
            spend_authority_key: address.spend_authority_key,
            rho: CanonicalField::from_field(Fp::from(6)),
            randomness: CanonicalField::from_field(Fp::from(7)),
            memo: b"wallet scan".to_vec(),
        };
        let commitment = note.commitment().unwrap();
        let mut output = PublicOutput {
            commitment,
            value_commitment: value_commitment_bytes(25, Fp::from(11)),
            ephemeral_key: [0; 32],
            ciphertext: vec![],
            outgoing_ciphertext: vec![],
        };
        let preimage = TransactionPreimage {
            network_id: network,
            anchor: CanonicalField::from_field(Fp::from(12)),
            expiry_height: 100,
            fee: 5,
            spends: vec![],
            outputs: vec![output.clone()],
            programs: vec![],
        };
        let binding = preimage.encryption_binding().unwrap();
        let encrypted = encrypt_note_with_ephemeral(
            &note,
            &address,
            &sender.outgoing_viewing_key(),
            [4; 32],
            binding,
            0,
        )
        .unwrap();
        output.ephemeral_key = encrypted.ephemeral_key;
        output.ciphertext = encrypted.ciphertext;
        output.outgoing_ciphertext = encrypted.outgoing_ciphertext;
        let transaction = AuthorizedTransaction {
            preimage: TransactionPreimage {
                outputs: vec![output],
                ..preimage
            },
            backend_id: "test".to_owned(),
            proof: vec![],
            spend_signatures: vec![],
            binding_signature: [0; 64],
        };

        let mut wallet = WalletState::<8>::new(network);
        wallet.scan_transfer(&receiver_view, &transaction).unwrap();
        assert_eq!(wallet.leaf_count(), 1);
        assert_eq!(wallet.notes().len(), 1);
        assert_eq!(wallet.notes()[0].plaintext, note);
        assert!(wallet
            .witness(0)
            .unwrap()
            .verify::<8>(commitment, wallet.root())
            .unwrap());
        let snapshot = wallet.encode_snapshot().unwrap();
        let restored = WalletState::<8>::decode_snapshot(&snapshot).unwrap();
        assert_eq!(restored.root(), wallet.root());
        assert_eq!(restored.notes(), wallet.notes());
        let mut trailing = snapshot.clone();
        trailing.push(0);
        assert_eq!(
            WalletState::<8>::decode_snapshot(&trailing).err(),
            Some(WalletError::Snapshot)
        );

        let mut address_bytes = [0u8; 91];
        assert_eq!(
            crate::onyx_wallet_address(
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                address_bytes.as_mut_ptr(),
            ),
            0
        );
        assert_eq!(&address_bytes[..16], &network);
        let encoded_transaction = transaction.encode().unwrap();
        let mut ffi_snapshot_ptr = std::ptr::null_mut();
        let mut ffi_snapshot_len = 0usize;
        let mut ffi_balance = 0u64;
        let mut ffi_note_count = 0usize;
        let mut ffi_root = [0u8; 32];
        assert_eq!(
            crate::onyx_wallet_scan(
                std::ptr::null(),
                0,
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                encoded_transaction.as_ptr(),
                encoded_transaction.len(),
                &mut ffi_snapshot_ptr,
                &mut ffi_snapshot_len,
                &mut ffi_balance,
                &mut ffi_note_count,
                ffi_root.as_mut_ptr(),
            ),
            1
        );
        assert_eq!((ffi_balance, ffi_note_count), (25, 1));
        assert!(!ffi_snapshot_ptr.is_null());
        crate::onyx_free(ffi_snapshot_ptr, ffi_snapshot_len);

        let mut viewing_bytes = [0u8; crate::keys::FULL_VIEWING_KEY_BYTES];
        assert_eq!(
            crate::onyx_full_viewing_key(
                [2u8; 32].as_ptr(),
                network.as_ptr(),
                viewing_bytes.as_mut_ptr(),
            ),
            0
        );
        ffi_snapshot_ptr = std::ptr::null_mut();
        ffi_snapshot_len = 0;
        ffi_balance = 0;
        ffi_note_count = 0;
        assert_eq!(
            crate::onyx_wallet_scan_viewing(
                std::ptr::null(),
                0,
                viewing_bytes.as_ptr(),
                viewing_bytes.len(),
                0,
                encoded_transaction.as_ptr(),
                encoded_transaction.len(),
                &mut ffi_snapshot_ptr,
                &mut ffi_snapshot_len,
                &mut ffi_balance,
                &mut ffi_note_count,
                ffi_root.as_mut_ptr(),
            ),
            1
        );
        assert_eq!((ffi_balance, ffi_note_count), (25, 1));
        crate::onyx_free(ffi_snapshot_ptr, ffi_snapshot_len);

        let mut unsigned_bridge_ptr = std::ptr::null_mut();
        let mut unsigned_bridge_len = 0usize;
        let mut ownership_sighash = [0u8; 32];
        assert_eq!(
            crate::onyx_wallet_create_bridge(
                [3u8; 32].as_ptr(),
                address_bytes.as_ptr(),
                100,
                5,
                30,
                42,
                [7u8; 32].as_ptr(),
                b"bridge memo".as_ptr(),
                b"bridge memo".len(),
                13,
                &mut unsigned_bridge_ptr,
                &mut unsigned_bridge_len,
                ownership_sighash.as_mut_ptr(),
            ),
            1
        );
        let unsigned_bridge =
            unsafe { std::slice::from_raw_parts(unsigned_bridge_ptr, unsigned_bridge_len) }
                .to_vec();
        crate::onyx_free(unsigned_bridge_ptr, unsigned_bridge_len);
        let bridge = AuthorizedBridge::decode(&unsigned_bridge).unwrap();
        crate::proof::verify_bridge_proof(13, &bridge).unwrap();
        assert_eq!(ownership_sighash, bridge.ownership_sighash().unwrap());
        let mut finalized_ptr = std::ptr::null_mut();
        let mut finalized_len = 0usize;
        assert_eq!(
            crate::onyx_wallet_finalize_bridge(
                unsigned_bridge.as_ptr(),
                unsigned_bridge.len(),
                [9u8; 64].as_ptr(),
                &mut finalized_ptr,
                &mut finalized_len,
            ),
            1
        );
        let finalized =
            unsafe { std::slice::from_raw_parts(finalized_ptr, finalized_len) }.to_vec();
        crate::onyx_free(finalized_ptr, finalized_len);
        assert_eq!(
            AuthorizedBridge::decode(&finalized)
                .unwrap()
                .ownership_signature,
            [9; 64]
        );

        let mut foreign = WalletState::<8>::new(network);
        foreign.scan_transfer(&sender_view, &transaction).unwrap();
        assert_eq!(foreign.leaf_count(), 1);
        assert!(foreign.notes().is_empty());

        let nullifier = note.nullifier(receiver.nullifier_key(), 0);
        let spend = AuthorizedTransaction {
            preimage: TransactionPreimage {
                network_id: network,
                anchor: wallet.root(),
                expiry_height: 101,
                fee: 1,
                spends: vec![PublicSpend {
                    nullifier,
                    value_commitment: value_commitment_bytes(25, Fp::from(11)),
                    randomized_key: [0; 32],
                }],
                outputs: vec![],
                programs: vec![],
            },
            backend_id: "test".to_owned(),
            proof: vec![],
            spend_signatures: vec![[0; 64]],
            binding_signature: [0; 64],
        };
        wallet.scan_transfer(&receiver_view, &spend).unwrap();
        assert!(wallet.notes()[0].spent);
        assert_ne!(nullifier, Nullifier([0; 32]));
        let rolled_back = WalletState::<8>::decode_snapshot(&snapshot).unwrap();
        assert!(!rolled_back.notes()[0].spent);
        assert_eq!(rolled_back.root(), restored.root());
    }
}
