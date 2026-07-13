//! Poseidon note-commitment circuit matching `NotePlaintext::commitment`.

use std::array;

use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};

pub const NOTE_COMMITMENT_INPUTS: usize = 14;
pub const NOTE_VALUE_INPUT_INDEX: usize = 6;

#[derive(Clone)]
pub struct NoteCommitmentConfig {
    pub(crate) poseidon: Pow5Config<Fp, 3, 2>,
    pub(crate) state: [Column<Advice>; 3],
    pub(crate) instance: Column<Instance>,
}

#[derive(Clone)]
pub struct NoteCommitmentCircuit {
    inputs: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
}

impl NoteCommitmentCircuit {
    pub fn new(inputs: [Fp; NOTE_COMMITMENT_INPUTS]) -> Self {
        Self {
            inputs: inputs.map(Some),
        }
    }
}

impl Circuit<Fp> for NoteCommitmentCircuit {
    type Config = NoteCommitmentConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: [None; NOTE_COMMITMENT_INPUTS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a = array::from_fn(|_| meta.fixed_column());
        let rc_b = array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Self::Config {
            poseidon,
            state,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let commitment = synthesize_note_commitment(
            &config,
            layouter.namespace(|| "note commitment"),
            &self.inputs,
            None,
            None,
            None,
            None,
            false,
        )?;
        layouter.constrain_instance(commitment.cell(), config.instance, 0)
    }
}

pub(crate) fn synthesize_note_commitment(
    config: &NoteCommitmentConfig,
    mut layouter: impl Layouter<Fp>,
    inputs: &[Option<Fp>; NOTE_COMMITMENT_INPUTS],
    external_value: Option<&AssignedCell<Fp, Fp>>,
    external_network: Option<&AssignedCell<Fp, Fp>>,
    external_authority: Option<(&AssignedCell<Fp, Fp>, &AssignedCell<Fp, Fp>)>,
    external_randomness: Option<&AssignedCell<Fp, Fp>>,
    enforce_native_asset: bool,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let message = layouter.assign_region(
        || "load note fields",
        |mut region| {
            let mut cells = Vec::with_capacity(NOTE_COMMITMENT_INPUTS);
            for (index, input) in inputs.iter().enumerate() {
                let cell = if index == 1 && external_network.is_some() {
                    external_network.unwrap().copy_advice(
                        || "linked transaction network",
                        &mut region,
                        config.state[0],
                        index,
                    )?
                } else if index == NOTE_VALUE_INPUT_INDEX {
                    if let Some(value) = external_value {
                        value.copy_advice(
                            || "linked note value",
                            &mut region,
                            config.state[0],
                            index,
                        )?
                    } else {
                        region.assign_advice(
                            || "note value",
                            config.state[0],
                            index,
                            || input.map_or(Value::unknown(), Value::known),
                        )?
                    }
                } else if enforce_native_asset && (index == 2 || index == 3) {
                    region.assign_advice_from_constant(
                        || "native program identifier",
                        config.state[0],
                        index,
                        Fp::zero(),
                    )?
                } else if enforce_native_asset && (index == 4 || index == 5) {
                    region.assign_advice_from_constant(
                        || "native asset identifier",
                        config.state[0],
                        index,
                        crate::types::native_asset_fields()[index - 4],
                    )?
                } else if index == 10 || index == 11 {
                    if let Some((x, y)) = external_authority {
                        let coordinate = if index == 10 { x } else { y };
                        coordinate.copy_advice(
                            || "linked spend-authority coordinate",
                            &mut region,
                            config.state[0],
                            index,
                        )?
                    } else {
                        region.assign_advice(
                            || "spend-authority coordinate",
                            config.state[0],
                            index,
                            || input.map_or(Value::unknown(), Value::known),
                        )?
                    }
                } else if index == 13 && external_randomness.is_some() {
                    external_randomness.unwrap().copy_advice(
                        || "linked value-commitment randomness",
                        &mut region,
                        config.state[0],
                        index,
                    )?
                } else {
                    region.assign_advice(
                        || "note field",
                        config.state[0],
                        index,
                        || input.map_or(Value::unknown(), Value::known),
                    )?
                };
                cells.push(cell);
            }
            Ok(cells.try_into().expect("fixed note input count"))
        },
    )?;
    Hash::<_, _, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init(
        Pow5Chip::construct(config.poseidon.clone()),
        layouter.namespace(|| "init note hash"),
    )?
    .hash(layouter.namespace(|| "hash note"), message)
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use halo2_proofs::dev::MockProver;

    use crate::state::CanonicalField;
    use crate::types::{NotePlaintext, DIVERSIFIER_BYTES, NETWORK_ID_BYTES};

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
            memo: b"not committed; authenticated by AEAD".to_vec(),
        }
    }

    #[test]
    fn note_commitment_circuit_matches_native_encoding() {
        let note = note();
        let commitment = Fp::from_repr(note.commitment().unwrap().bytes()).unwrap();
        let circuit = NoteCommitmentCircuit::new(note.commitment_inputs().unwrap());
        let prover = MockProver::run(11, &circuit, vec![vec![commitment]]).unwrap();
        prover.assert_satisfied();
        let bad = MockProver::run(11, &circuit, vec![vec![commitment + Fp::one()]]).unwrap();
        assert!(bad.verify().is_err());
    }
}
