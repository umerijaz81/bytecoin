//! Deterministic Onyx wallet scanning and witness state.

use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use halo2_proofs::pasta::Fp;
use pasta_curves::pallas;
use rand::RngCore;

use crate::authorization::{
    prepare_same_owner_spends, sign_binding_authorization, sign_prepared_spends,
};
use crate::bridge::{AuthorizedBridge, BridgePreimage};
use crate::keys::{EncryptedNote, FullViewingKey, KeyBundle, RecipientAddress};
use crate::note_commitment_circuit::NOTE_COMMITMENT_INPUTS;
use crate::proof::{
    create_bridge_proof, create_multi_transfer_proof, multi_transfer_backend_id, BridgeWitness,
    MultiSpendWitness, MultiTransferWitness, BRIDGE_BACKEND,
};
use crate::state::{CanonicalField, MerklePath, WitnessError, WitnessTree, ONYX_MERKLE_DEPTH};
use crate::transaction::{AuthorizedTransaction, PublicOutput, PublicSpend, TransactionPreimage};
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
    InsufficientFunds,
}

fn select_note_indices(
    notes: &[WalletNote],
    required: u64,
) -> Result<Vec<usize>, WalletBuildError> {
    let unspent = notes
        .iter()
        .enumerate()
        .filter(|(_, note)| !note.spent)
        .collect::<Vec<_>>();
    if let Some((index, _)) = unspent
        .iter()
        .copied()
        .find(|(_, note)| note.plaintext.value >= required)
    {
        return Ok(vec![index]);
    }
    for first in 0..unspent.len() {
        for second in (first + 1)..unspent.len() {
            let value = unspent[first]
                .1
                .plaintext
                .value
                .checked_add(unspent[second].1.plaintext.value)
                .ok_or(WalletBuildError::InvalidValue)?;
            if value >= required {
                return Ok(vec![unspent[first].0, unspent[second].0]);
            }
        }
    }
    Err(WalletBuildError::InsufficientFunds)
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
    rand::rngs::OsRng.fill_bytes(&mut rho_wide);
    rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
    let rho = CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide));
    let randomness = CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide));
    // Reuse the note randomness as the value-commitment trapdoor. Recipients recover it through
    // authenticated note encryption and therefore retain the opening required for a later spend.
    let value_randomness = randomness.field();
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

    pub fn build_transfer(
        &self,
        keys: &KeyBundle,
        recipient: &RecipientAddress,
        amount: u64,
        fee: u64,
        expiry_height: u64,
        memo: Vec<u8>,
        circuit_k: u32,
    ) -> Result<AuthorizedTransaction, WalletBuildError> {
        let required = amount
            .checked_add(fee)
            .filter(|value| amount != 0 && *value != 0)
            .ok_or(WalletBuildError::InvalidValue)?;
        let selected_indices = select_note_indices(&self.notes, required)?;
        let selected = selected_indices
            .iter()
            .map(|index| &self.notes[*index])
            .collect::<Vec<_>>();
        if recipient.network_id != self.network_id
            || selected
                .iter()
                .any(|note| note.plaintext.network_id != recipient.network_id)
        {
            return Err(WalletBuildError::InvalidRecipient);
        }
        let input_value = selected.iter().try_fold(0u64, |sum, note| {
            sum.checked_add(note.plaintext.value)
                .ok_or(WalletBuildError::InvalidValue)
        })?;
        let change = input_value - required;
        let mut recipients = vec![(recipient.clone(), amount, memo)];
        if change != 0 {
            recipients.push((
                keys.address(0).map_err(|_| WalletBuildError::Crypto)?,
                change,
                vec![],
            ));
        }

        let mut output_notes = Vec::with_capacity(recipients.len());
        let mut output_randomness = Vec::with_capacity(recipients.len());
        let mut output_commitments = Vec::with_capacity(recipients.len());
        let mut outputs = Vec::with_capacity(recipients.len());
        for (recipient, value, memo) in &recipients {
            let mut rho_wide = [0u8; 64];
            let mut randomness_wide = [0u8; 64];
            rand::rngs::OsRng.fill_bytes(&mut rho_wide);
            rand::rngs::OsRng.fill_bytes(&mut randomness_wide);
            let note = NotePlaintext {
                network_id: self.network_id,
                program_id: [0; 32],
                asset_id: NATIVE_ASSET_ID,
                value: *value,
                diversifier: recipient.diversifier,
                transmission_key: recipient.transmission_key,
                spend_authority_key: recipient.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from_uniform_bytes(&rho_wide)),
                randomness: CanonicalField::from_field(Fp::from_uniform_bytes(&randomness_wide)),
                memo: memo.clone(),
            };
            let randomness = note.randomness.field();
            let commitment = note.commitment().map_err(|_| WalletBuildError::Crypto)?;
            let commitment_bytes = value_commitment_bytes(*value, randomness);
            let commitment_point =
                Option::<pallas::Point>::from(pallas::Point::from_bytes(&commitment_bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
            output_notes.push(note);
            output_randomness.push(randomness);
            output_commitments.push(commitment_point);
            outputs.push(PublicOutput {
                commitment,
                value_commitment: commitment_bytes,
                ephemeral_key: [0; 32],
                ciphertext: vec![],
                outgoing_ciphertext: vec![],
            });
        }

        let input_randomness = selected
            .iter()
            .map(|note| note.plaintext.randomness.field())
            .collect::<Vec<_>>();
        let input_commitments = selected
            .iter()
            .zip(&input_randomness)
            .map(|(note, randomness)| {
                let bytes = value_commitment_bytes(note.plaintext.value, *randomness);
                let point = Option::<pallas::Point>::from(pallas::Point::from_bytes(&bytes))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                Ok((bytes, point))
            })
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let nullifiers = selected
            .iter()
            .map(|note| {
                note.plaintext
                    .nullifier(keys.nullifier_key(), note.position)
            })
            .collect::<Vec<_>>();
        let mut preimage = TransactionPreimage {
            network_id: self.network_id,
            anchor: self.root(),
            expiry_height,
            fee,
            spends: nullifiers
                .iter()
                .zip(&input_commitments)
                .map(|(nullifier, (value_commitment, _))| PublicSpend {
                    nullifier: *nullifier,
                    value_commitment: *value_commitment,
                    randomized_key: [0; 32],
                })
                .collect(),
            outputs,
            programs: vec![],
        };
        let prepared =
            prepare_same_owner_spends(keys, &mut preimage).map_err(|_| WalletBuildError::Crypto)?;
        let binding = preimage
            .encryption_binding()
            .map_err(|_| WalletBuildError::Crypto)?;
        for (index, (note, recipient)) in output_notes.iter().zip(&recipients).enumerate() {
            let encrypted = keys
                .encrypt_note(note, &recipient.0, binding, index as u32)
                .map_err(|_| WalletBuildError::Crypto)?;
            preimage.outputs[index].ephemeral_key = encrypted.ephemeral_key;
            preimage.outputs[index].ciphertext = encrypted.ciphertext;
            preimage.outputs[index].outgoing_ciphertext = encrypted.outgoing_ciphertext;
        }

        let spends = selected
            .iter()
            .zip(&selected_indices)
            .zip(&input_randomness)
            .zip(&input_commitments)
            .enumerate()
            .map(
                |(spend_index, (((input, note_index), randomness), (_, commitment)))| {
                    let path = self
                        .witness(*note_index)
                        .map_err(|_| WalletBuildError::Crypto)?;
                    let authority = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &input.plaintext.spend_authority_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    let randomized_key = Option::<pallas::Point>::from(pallas::Point::from_bytes(
                        &preimage.spends[spend_index].randomized_key,
                    ))
                    .ok_or(WalletBuildError::Crypto)?
                    .to_affine();
                    Ok(MultiSpendWitness {
                        commitment: input.commitment.field(),
                        input_note: input
                            .plaintext
                            .commitment_inputs()
                            .map_err(|_| WalletBuildError::Crypto)?,
                        authority_key: authority,
                        authorization_randomizer: prepared.randomizers()[spend_index],
                        randomized_key,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|sibling| sibling.field())
                            .collect(),
                        position: path.position,
                        nullifier_key: keys.nullifier_key().field(),
                        rho: input.plaintext.rho.field(),
                        value_randomness: *randomness,
                        value_commitment: *commitment,
                    })
                },
            )
            .collect::<Result<Vec<_>, WalletBuildError>>()?;
        let witness = MultiTransferWitness::<DEPTH> {
            input_values: selected.iter().map(|note| note.plaintext.value).collect(),
            output_values: recipients.iter().map(|recipient| recipient.1).collect(),
            spends,
            output_notes: output_notes
                .iter()
                .map(|note| {
                    note.commitment_inputs()
                        .map_err(|_| WalletBuildError::Crypto)
                })
                .collect::<Result<Vec<_>, _>>()?,
            output_value_randomness: output_randomness.clone(),
            output_value_commitments: output_commitments,
        };
        let backend_id = multi_transfer_backend_id(selected.len(), recipients.len());
        let nullifier_bytes = nullifiers
            .iter()
            .map(|nullifier| nullifier.0)
            .collect::<Vec<_>>();
        let proof = match (selected.len(), recipients.len()) {
            (1, 1) => create_multi_transfer_proof::<DEPTH, 1, 1>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (1, 2) => create_multi_transfer_proof::<DEPTH, 1, 2>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (2, 1) => create_multi_transfer_proof::<DEPTH, 2, 1>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            (2, 2) => create_multi_transfer_proof::<DEPTH, 2, 2>(
                circuit_k,
                &witness,
                fee,
                self.root(),
                &nullifier_bytes,
            ),
            _ => return Err(WalletBuildError::Crypto),
        }
        .map_err(|_| WalletBuildError::Crypto)?;
        let spend_signatures = sign_prepared_spends(&prepared, &preimage, &backend_id, &proof)
            .map_err(|_| WalletBuildError::Crypto)?;
        let binding_signature = sign_binding_authorization(
            &preimage,
            &backend_id,
            &proof,
            &input_randomness,
            &output_randomness,
        )
        .map_err(|_| WalletBuildError::Crypto)?;
        Ok(AuthorizedTransaction {
            preimage,
            backend_id,
            proof,
            spend_signatures,
            binding_signature,
        })
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

    fn funded_wallet<const DEPTH: usize>(
        keys: &KeyBundle,
        network: [u8; NETWORK_ID_BYTES],
        values: &[u64],
    ) -> WalletState<DEPTH> {
        let address = keys.address(0).unwrap();
        let mut wallet = WalletState::<DEPTH>::new(network);
        for (index, value) in values.iter().enumerate() {
            let note = NotePlaintext {
                network_id: network,
                program_id: [0; 32],
                asset_id: NATIVE_ASSET_ID,
                value: *value,
                diversifier: address.diversifier,
                transmission_key: address.transmission_key,
                spend_authority_key: address.spend_authority_key,
                rho: CanonicalField::from_field(Fp::from(100 + index as u64)),
                randomness: CanonicalField::from_field(Fp::from(200 + index as u64)),
                memo: vec![],
            };
            let commitment = note.commitment().unwrap();
            let position = wallet.tree.append(commitment).unwrap();
            wallet.notes.push(WalletNote {
                commitment,
                position,
                plaintext: note,
                spent: false,
            });
        }
        wallet
    }

    #[test]
    fn builder_combines_two_notes_for_exact_and_change_payments() {
        const DEPTH: usize = 2;
        const K: u32 = 16;
        let network = [8; NETWORK_ID_BYTES];
        let sender = MasterSeed::new([21; 32]).derive(network).unwrap();
        let recipient_keys = MasterSeed::new([22; 32]).derive(network).unwrap();
        let recipient = recipient_keys.address(0).unwrap();

        let exact_wallet = funded_wallet::<DEPTH>(&sender, network, &[10, 12]);
        let exact = exact_wallet
            .build_transfer(&sender, &recipient, 20, 2, 50, vec![], K)
            .unwrap();
        assert_eq!(
            (exact.preimage.spends.len(), exact.preimage.outputs.len()),
            (2, 1)
        );
        crate::proof::verify_authorized_multi_transfer::<DEPTH, 2, 1>(K, &exact).unwrap();

        let change_wallet = funded_wallet::<DEPTH>(&sender, network, &[10, 15]);
        let change = change_wallet
            .build_transfer(&sender, &recipient, 20, 2, 50, vec![], K)
            .unwrap();
        assert_eq!(
            (change.preimage.spends.len(), change.preimage.outputs.len()),
            (2, 2)
        );
        crate::proof::verify_authorized_multi_transfer::<DEPTH, 2, 2>(K, &change).unwrap();

        let mut recipient_wallet = WalletState::<DEPTH>::new(network);
        recipient_wallet
            .scan_transfer(&recipient_keys.full_viewing_key().unwrap(), &change)
            .unwrap();
        assert_eq!(recipient_wallet.unspent_balance().unwrap(), 20);
        let mut sender_wallet = WalletState::<DEPTH>::new(network);
        sender_wallet
            .scan_transfer(&sender.full_viewing_key().unwrap(), &change)
            .unwrap();
        assert_eq!(sender_wallet.unspent_balance().unwrap(), 3);
    }

    #[test]
    fn selector_prefers_one_note_then_first_sufficient_pair() {
        let network = [7; NETWORK_ID_BYTES];
        let keys = MasterSeed::new([23; 32]).derive(network).unwrap();
        let wallet = funded_wallet::<2>(&keys, network, &[4, 4, 6, 12]);
        assert_eq!(select_note_indices(wallet.notes(), 10).unwrap(), vec![3]);
        assert_eq!(select_note_indices(wallet.notes(), 13).unwrap(), vec![0, 3]);

        let pair_wallet = funded_wallet::<2>(&keys, network, &[4, 4, 6]);
        assert_eq!(
            select_note_indices(pair_wallet.notes(), 10).unwrap(),
            vec![0, 2]
        );
        assert!(matches!(
            select_note_indices(pair_wallet.notes(), 11),
            Err(WalletBuildError::InsufficientFunds)
        ));
    }

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

        // The public wallet FFI is fixed to the consensus tree depth. Build the
        // transfer snapshot at that depth rather than reusing the compact
        // depth-8 unit-test wallet above.
        let mut transfer_wallet = WalletState::<32>::new(network);
        transfer_wallet
            .scan_transfer(&receiver_view, &transaction)
            .unwrap();
        let wallet_snapshot = transfer_wallet.encode_snapshot().unwrap();
        let mut recipient_bytes = [0u8; 91];
        assert_eq!(
            crate::onyx_wallet_address(
                [3u8; 32].as_ptr(),
                network.as_ptr(),
                0,
                recipient_bytes.as_mut_ptr(),
            ),
            0
        );
        let mut payment_ptr = std::ptr::null_mut();
        let mut payment_len = 0usize;
        assert_eq!(
            crate::onyx_wallet_create_transfer(
                wallet_snapshot.as_ptr(),
                wallet_snapshot.len(),
                [2u8; 32].as_ptr(),
                recipient_bytes.as_ptr(),
                20,
                2,
                101,
                b"shielded payment".as_ptr(),
                b"shielded payment".len(),
                16,
                &mut payment_ptr,
                &mut payment_len,
            ),
            1
        );
        let payment_encoded =
            unsafe { std::slice::from_raw_parts(payment_ptr, payment_len) }.to_vec();
        crate::onyx_free(payment_ptr, payment_len);
        let payment = AuthorizedTransaction::decode(&payment_encoded).unwrap();
        assert_eq!(payment.preimage.outputs.len(), 2);
        crate::proof::verify_authorized_multi_transfer::<32, 1, 2>(16, &payment).unwrap();
        let mut recipient_wallet = WalletState::<8>::new(network);
        recipient_wallet
            .scan_transfer(&sender_view, &payment)
            .unwrap();
        assert_eq!(recipient_wallet.unspent_balance().unwrap(), 20);

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
