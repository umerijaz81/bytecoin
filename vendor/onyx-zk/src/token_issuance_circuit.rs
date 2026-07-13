//! Fixed-shape private token issuance circuit.

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
use crate::transaction::MAX_OUTPUTS;
use crate::transfer_circuit::{synthesize_issued_values, NativeValueCircuit, ValueConfig};

#[derive(Clone)]
pub struct TokenIssuanceConfig {
    values: ValueConfig,
    notes: NoteCommitmentConfig,
    commitments: SpendAuthConfig,
}

#[derive(Clone)]
pub struct TokenIssuanceCircuit<const OUTPUTS: usize> {
    output_values: Vec<Option<u64>>,
    output_notes: Vec<[Option<Fp>; NOTE_COMMITMENT_INPUTS]>,
    output_randomness: Vec<Option<Fp>>,
    output_commitments: Vec<Option<pallas::Affine>>,
}

impl<const OUTPUTS: usize> TokenIssuanceCircuit<OUTPUTS> {
    pub fn new(
        output_values: &[u64],
        output_notes: Vec<[Fp; NOTE_COMMITMENT_INPUTS]>,
        output_randomness: Vec<Fp>,
        output_commitments: Vec<pallas::Affine>,
    ) -> Result<Self, &'static str> {
        if !(1..=2).contains(&OUTPUTS)
            || output_values.len() != OUTPUTS
            || output_notes.len() != OUTPUTS
            || output_randomness.len() != OUTPUTS
            || output_commitments.len() != OUTPUTS
        {
            return Err("issuance witness does not match circuit shape");
        }
        let mut values = vec![Some(0); MAX_OUTPUTS];
        for (slot, value) in values.iter_mut().zip(output_values) {
            *slot = Some(*value);
        }
        Ok(Self {
            output_values: values,
            output_notes: output_notes
                .into_iter()
                .map(|note| note.map(Some))
                .collect(),
            output_randomness: output_randomness.into_iter().map(Some).collect(),
            output_commitments: output_commitments.into_iter().map(Some).collect(),
        })
    }
}

impl<const OUTPUTS: usize> Circuit<Fp> for TokenIssuanceCircuit<OUTPUTS> {
    type Config = TokenIssuanceConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            output_values: vec![None; MAX_OUTPUTS],
            output_notes: vec![[None; NOTE_COMMITMENT_INPUTS]; OUTPUTS],
            output_randomness: vec![None; OUTPUTS],
            output_commitments: vec![None; OUTPUTS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            values: NativeValueCircuit::configure(meta),
            notes: NoteCommitmentCircuit::configure(meta),
            commitments: configure_spend_authority(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let values = synthesize_issued_values(
            &self.output_values,
            &config.values,
            layouter.namespace(|| "issued values"),
        )?;
        let network = layouter.assign_region(
            || "issuance network",
            |mut region| {
                region.assign_advice_from_instance(
                    || "network",
                    config.notes.instance,
                    OUTPUTS,
                    config.notes.state[0],
                    0,
                )
            },
        )?;
        let program = layouter.assign_region(
            || "issued program and asset",
            |mut region| {
                let low = region.assign_advice_from_instance(
                    || "program low limb",
                    config.notes.instance,
                    OUTPUTS + 1,
                    config.notes.state[0],
                    0,
                )?;
                let high = region.assign_advice_from_instance(
                    || "program high limb",
                    config.notes.instance,
                    OUTPUTS + 2,
                    config.notes.state[0],
                    1,
                )?;
                Ok([low, high])
            },
        )?;
        for index in 0..OUTPUTS {
            let commitment = synthesize_value_commitment(
                &config.commitments,
                layouter.namespace(|| format!("issued output {index} value commitment")),
                &values[index],
                self.output_randomness[index],
                self.output_commitments[index],
                index == 0,
                index * 2,
                index * 2 + 1,
            )?;
            let note = synthesize_note_commitment(
                &config.notes,
                layouter.namespace(|| format!("issued output {index} note")),
                &self.output_notes[index],
                Some(&values[index]),
                Some(&network),
                Some((&program[0], &program[1])),
                Some((&program[0], &program[1])),
                None,
                Some(&commitment.randomness),
                false,
            )?;
            layouter.constrain_instance(note.cell(), config.notes.instance, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use group::Curve;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use pasta_curves::arithmetic::CurveAffine;

    use super::*;

    #[test]
    fn issuance_binds_total_program_notes_and_value_commitments() {
        let program_id = [17u8; 32];
        let program = crate::types::pack_32(&program_id);
        let network = Fp::from(23);
        let values = [30u64, 12];
        let randomness = [Fp::from(31), Fp::from(32)];
        let mut notes = Vec::new();
        let mut note_public = Vec::new();
        let mut commitments = Vec::new();
        let mut commitment_public = Vec::new();
        for index in 0..2 {
            let mut note =
                std::array::from_fn(|field| Fp::from(100 + index as u64 * 20 + field as u64));
            note[1] = network;
            note[2] = program[0];
            note[3] = program[1];
            note[4] = program[0];
            note[5] = program[1];
            note[6] = Fp::from(values[index]);
            note[13] = randomness[index];
            note_public.push(
                Hash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
                    .hash(note),
            );
            notes.push(note);
            let commitment = (crate::spend_auth_circuit::value_generator()
                * pallas::Scalar::from(values[index])
                + crate::spend_auth_circuit::binding_generator()
                    * pallas::Scalar::from(31 + index as u64))
            .to_affine();
            let coordinates = commitment.coordinates().unwrap();
            commitment_public.extend([*coordinates.x(), *coordinates.y()]);
            commitments.push(commitment);
        }
        note_public.extend([network, program[0], program[1]]);
        let circuit =
            TokenIssuanceCircuit::<2>::new(&values, notes, randomness.to_vec(), commitments)
                .unwrap();
        MockProver::run(
            14,
            &circuit,
            vec![
                vec![Fp::from(42)],
                note_public.clone(),
                commitment_public.clone(),
            ],
        )
        .unwrap()
        .assert_satisfied();
        assert!(MockProver::run(
            14,
            &circuit,
            vec![vec![Fp::from(41)], note_public, commitment_public],
        )
        .unwrap()
        .verify()
        .is_err());
    }
}
