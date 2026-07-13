//! One-way legacy-to-Onyx bridge circuit.
//!
//! The disclosed legacy amount is a public input. This circuit range-checks it and the hidden note
//! value, proves `legacy_amount = note_value + fee`, constructs the native-asset note commitment,
//! and binds the same value to the output value commitment.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use pasta_curves::pallas;

use crate::note_commitment_circuit::{
    synthesize_note_commitment, NoteCommitmentCircuit, NoteCommitmentConfig, NOTE_COMMITMENT_INPUTS,
};
use crate::spend_auth_circuit::{
    configure_spend_authority, synthesize_value_commitment, SpendAuthConfig,
};
use crate::transfer_circuit::{synthesize_native_values, NativeValueCircuit, ValueConfig};

#[derive(Clone)]
pub struct BridgeConfig {
    values: ValueConfig,
    note: NoteCommitmentConfig,
    value_commitment: SpendAuthConfig,
}

#[derive(Clone)]
pub struct BridgeCircuit {
    values: NativeValueCircuit,
    note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
    value_randomness: Option<Fp>,
    value_commitment: Option<pallas::Affine>,
}

impl BridgeCircuit {
    pub fn new(
        legacy_amount: u64,
        note_value: u64,
        note: [Fp; NOTE_COMMITMENT_INPUTS],
        value_randomness: Fp,
        value_commitment: pallas::Affine,
    ) -> Result<Self, &'static str> {
        if note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] != Fp::from(note_value) {
            return Err("note value witness mismatch");
        }
        Ok(Self {
            values: NativeValueCircuit::new(&[legacy_amount], &[note_value])?,
            note: note.map(Some),
            value_randomness: Some(value_randomness),
            value_commitment: Some(value_commitment),
        })
    }
}

impl Circuit<Fp> for BridgeCircuit {
    type Config = BridgeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            values: self.values.without_witnesses(),
            note: [None; NOTE_COMMITMENT_INPUTS],
            value_randomness: None,
            value_commitment: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            values: NativeValueCircuit::configure(meta),
            note: NoteCommitmentCircuit::configure(meta),
            value_commitment: configure_spend_authority(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let values = synthesize_native_values(
            &self.values,
            &config.values,
            layouter.namespace(|| "bridge value conservation"),
        )?;
        layouter.constrain_instance(values.input_cells[0].cell(), config.values.instance, 1)?;

        let network = layouter.assign_region(
            || "bridge network",
            |mut region| {
                region.assign_advice_from_instance(
                    || "network",
                    config.note.instance,
                    1,
                    config.note.state[0],
                    0,
                )
            },
        )?;
        let value_commitment = synthesize_value_commitment(
            &config.value_commitment,
            layouter.namespace(|| "bridged value commitment"),
            &values.output_cells[0],
            self.value_randomness,
            self.value_commitment,
            true,
            0,
            1,
        )?;
        let commitment = synthesize_note_commitment(
            &config.note,
            layouter.namespace(|| "bridged note"),
            &self.note,
            Some(&values.output_cells[0]),
            Some(&network),
            None,
            Some(&value_commitment.randomness),
            true,
        )?;
        layouter.constrain_instance(commitment.cell(), config.note.instance, 0)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use group::{Curve, GroupEncoding};
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use pasta_curves::arithmetic::CurveAffine;

    use crate::bridge::{AuthorizedBridge, BridgePreimage};
    use crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX;
    use crate::proof::{create_bridge_proof, verify_bridge_proof, BridgeWitness, BRIDGE_BACKEND};
    use crate::spend_auth_circuit::{binding_generator, value_generator};
    use crate::state::CanonicalField;
    use crate::transaction::PublicOutput;
    use crate::types::{native_asset_fields, network_field, NETWORK_ID_BYTES};

    use super::*;

    #[test]
    fn bridge_binds_public_legacy_value_to_hidden_native_note() {
        let legacy_amount = 30;
        let fee = 5;
        let note_value = 25;
        let mut note = std::array::from_fn(|index| Fp::from(index as u64 + 40));
        note[1] = network_field(&[1; NETWORK_ID_BYTES]);
        note[2] = Fp::zero();
        note[3] = Fp::zero();
        note[4] = native_asset_fields()[0];
        note[5] = native_asset_fields()[1];
        note[NOTE_VALUE_INPUT_INDEX] = Fp::from(note_value);
        note[13] = Fp::from(17);
        let note_commitment =
            PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                .hash(note);
        let randomness = Fp::from(17);
        let value_commitment = (value_generator() * pallas::Scalar::from(note_value)
            + binding_generator() * pallas::Scalar::from(17))
        .to_affine();
        let coordinates = value_commitment.coordinates().unwrap();
        let circuit = BridgeCircuit::new(
            legacy_amount,
            note_value,
            note,
            randomness,
            value_commitment,
        )
        .unwrap();
        let public = vec![
            vec![Fp::from(fee), Fp::from(legacy_amount)],
            vec![note_commitment, network_field(&[1; NETWORK_ID_BYTES])],
            vec![*coordinates.x(), *coordinates.y()],
        ];
        MockProver::run(13, &circuit, public.clone())
            .unwrap()
            .assert_satisfied();

        let mut inflated = public;
        inflated[0][1] -= Fp::one();
        assert!(MockProver::run(13, &circuit, inflated)
            .unwrap()
            .verify()
            .is_err());

        let preimage = BridgePreimage {
            network_id: [1; NETWORK_ID_BYTES],
            expiry_height: 100,
            fee,
            legacy_amount,
            legacy_stack_index: 42,
            legacy_key_image: [7; 32],
            output: PublicOutput {
                commitment: CanonicalField::from_field(note_commitment),
                value_commitment: value_commitment.to_bytes(),
                ephemeral_key: [12; 32],
                ciphertext: vec![13; 48],
                outgoing_ciphertext: vec![14; 32],
            },
        };
        let proof = create_bridge_proof(
            13,
            &preimage,
            &BridgeWitness {
                output_note: note,
                output_value_randomness: randomness,
                output_value_commitment: value_commitment,
            },
        )
        .unwrap();
        let bridge = AuthorizedBridge {
            preimage,
            backend_id: BRIDGE_BACKEND.to_owned(),
            proof,
            ownership_signature: [0; 64],
        };
        verify_bridge_proof(13, &bridge).unwrap();
        let encoded = bridge.encode().unwrap();
        let initial_snapshot = crate::state::ShieldedState::<32>::new(100).encode_snapshot();
        let mut snapshot_ptr = std::ptr::null_mut();
        let mut snapshot_len = 0usize;
        let mut extracted_amount = 0u64;
        let mut extracted_index = 0u64;
        let mut extracted_key_image = [0u8; 32];
        let mut extracted_sighash = [0u8; 32];
        let mut extracted_signature = [0u8; 64];
        let mut extracted_fee = 0u64;
        assert_eq!(
            crate::onyx_verify_apply_bridge(
                initial_snapshot.as_ptr(),
                initial_snapshot.len(),
                100,
                encoded.as_ptr(),
                encoded.len(),
                13,
                [1u8; NETWORK_ID_BYTES].as_ptr(),
                1,
                &mut snapshot_ptr,
                &mut snapshot_len,
                &mut extracted_amount,
                &mut extracted_index,
                extracted_key_image.as_mut_ptr(),
                extracted_sighash.as_mut_ptr(),
                extracted_signature.as_mut_ptr(),
                &mut extracted_fee,
            ),
            1
        );
        let snapshot = unsafe { std::slice::from_raw_parts(snapshot_ptr, snapshot_len) }.to_vec();
        crate::onyx_free(snapshot_ptr, snapshot_len);
        assert_eq!(
            crate::state::ShieldedState::<32>::decode_snapshot(&snapshot)
                .unwrap()
                .leaf_count(),
            1
        );
        assert_eq!(
            (extracted_amount, extracted_index, extracted_fee),
            (30, 42, 5)
        );
        assert_eq!(extracted_key_image, [7; 32]);
        assert_eq!(extracted_sighash, bridge.ownership_sighash().unwrap());
        assert_eq!(extracted_signature, [0; 64]);
        let mut total_bridged = 0u64;
        let mut total_fees = 0u64;
        let mut circulating_supply = 0u64;
        let mut commitment_count = 0u64;
        let mut program_count = 0u64;
        let mut audit_root = [0u8; 32];
        assert_eq!(
            crate::onyx_state_supply_audit(
                snapshot.as_ptr(),
                snapshot.len(),
                &mut total_bridged,
                &mut total_fees,
                &mut circulating_supply,
                &mut commitment_count,
                &mut program_count,
                audit_root.as_mut_ptr(),
            ),
            1
        );
        assert_eq!(
            (
                total_bridged,
                total_fees,
                circulating_supply,
                commitment_count
            ),
            (30, 5, 25, 1)
        );
        assert_eq!(program_count, 0);
        assert_eq!(
            audit_root,
            crate::state::ShieldedState::<32>::decode_snapshot(&snapshot)
                .unwrap()
                .root()
                .bytes()
        );

        // Reorg rollback restores the prior serialized state. Reapplying the
        // same bridge to that exact snapshot must reproduce the same root and
        // bytes; active-chain replay protection is the legacy key-image set.
        let mut replay_ptr = std::ptr::null_mut();
        let mut replay_len = 0usize;
        assert_eq!(
            crate::onyx_verify_apply_bridge(
                initial_snapshot.as_ptr(),
                initial_snapshot.len(),
                100,
                encoded.as_ptr(),
                encoded.len(),
                13,
                [1u8; NETWORK_ID_BYTES].as_ptr(),
                1,
                &mut replay_ptr,
                &mut replay_len,
                &mut extracted_amount,
                &mut extracted_index,
                extracted_key_image.as_mut_ptr(),
                extracted_sighash.as_mut_ptr(),
                extracted_signature.as_mut_ptr(),
                &mut extracted_fee,
            ),
            1
        );
        let replay = unsafe { std::slice::from_raw_parts(replay_ptr, replay_len) }.to_vec();
        crate::onyx_free(replay_ptr, replay_len);
        assert_eq!(replay, snapshot);

        let mut inflated = bridge;
        inflated.preimage.legacy_amount += 1;
        assert!(verify_bridge_proof(13, &inflated).is_err());
    }
}
