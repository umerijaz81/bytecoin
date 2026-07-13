//! Linked one-spend, one-output Onyx transfer circuit.
//!
//! This composition connects the private values used by balance conservation to the exact input
//! and output note commitments. The input commitment cell is passed privately into the
//! membership/nullifier component and is never exposed as a public transaction field.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use crate::membership_circuit::{synthesize_membership, MembershipCircuit, MembershipConfig};
use crate::note_commitment_circuit::{
    synthesize_note_commitment, NoteCommitmentConfig, NOTE_COMMITMENT_INPUTS,
};
use crate::spend_auth_circuit::{
    configure_spend_authority, synthesize_spend_authority, synthesize_value_commitment,
    SpendAuthCircuit, SpendAuthConfig,
};
use crate::transfer_circuit::{synthesize_native_values, NativeValueCircuit, ValueConfig};
use pasta_curves::pallas;

#[derive(Clone)]
pub struct LinkedTransferConfig {
    values: ValueConfig,
    membership: MembershipConfig,
    notes: NoteCommitmentConfig,
    authorization: SpendAuthConfig,
}

#[derive(Clone)]
pub struct LinkedTransferCircuit<const DEPTH: usize> {
    values: NativeValueCircuit,
    membership: MembershipCircuit<DEPTH>,
    input_note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
    output_note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
    authorization: SpendAuthCircuit,
    input_value_randomness: Option<Fp>,
    input_value_commitment: Option<pallas::Affine>,
    output_value_randomness: Option<Fp>,
    output_value_commitment: Option<pallas::Affine>,
}

impl<const DEPTH: usize> LinkedTransferCircuit<DEPTH> {
    pub fn new(
        input_value: u64,
        output_value: u64,
        membership: MembershipCircuit<DEPTH>,
        input_note: [Fp; NOTE_COMMITMENT_INPUTS],
        output_note: [Fp; NOTE_COMMITMENT_INPUTS],
        authorization: SpendAuthCircuit,
        input_value_randomness: Fp,
        input_value_commitment: pallas::Affine,
        output_value_randomness: Fp,
        output_value_commitment: pallas::Affine,
    ) -> Self {
        Self {
            values: NativeValueCircuit::new(&[input_value], &[output_value])
                .expect("one input and output fit fixed capacity"),
            membership,
            input_note: input_note.map(Some),
            output_note: output_note.map(Some),
            authorization,
            input_value_randomness: Some(input_value_randomness),
            input_value_commitment: Some(input_value_commitment),
            output_value_randomness: Some(output_value_randomness),
            output_value_commitment: Some(output_value_commitment),
        }
    }
}

impl<const DEPTH: usize> Circuit<Fp> for LinkedTransferCircuit<DEPTH> {
    type Config = LinkedTransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            values: self.values.without_witnesses(),
            membership: self.membership.without_witnesses(),
            input_note: [None; NOTE_COMMITMENT_INPUTS],
            output_note: [None; NOTE_COMMITMENT_INPUTS],
            authorization: self.authorization.without_witnesses(),
            input_value_randomness: None,
            input_value_commitment: None,
            output_value_randomness: None,
            output_value_commitment: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            values: NativeValueCircuit::configure(meta),
            membership: MembershipCircuit::<DEPTH>::configure(meta),
            notes: crate::note_commitment_circuit::NoteCommitmentCircuit::configure(meta),
            authorization: configure_spend_authority(meta),
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
            layouter.namespace(|| "native values"),
        )?;
        let network = layouter.assign_region(
            || "transaction network",
            |mut region| {
                region.assign_advice_from_instance(
                    || "network",
                    config.notes.instance,
                    1,
                    config.notes.state[0],
                    0,
                )
            },
        )?;
        let authority = synthesize_spend_authority(
            &self.authorization,
            &config.authorization,
            layouter.namespace(|| "spend authorization"),
            true,
            0,
            1,
        )?;
        let input_value_commitment = synthesize_value_commitment(
            &config.authorization,
            layouter.namespace(|| "input value commitment"),
            &values.input_cells[0],
            self.input_value_randomness,
            self.input_value_commitment,
            false,
            2,
            3,
        )?;
        let output_value_commitment = synthesize_value_commitment(
            &config.authorization,
            layouter.namespace(|| "output value commitment"),
            &values.output_cells[0],
            self.output_value_randomness,
            self.output_value_commitment,
            false,
            4,
            5,
        )?;
        let input_commitment = synthesize_note_commitment(
            &config.notes,
            layouter.namespace(|| "input note"),
            &self.input_note,
            Some(&values.input_cells[0]),
            Some(&network),
            Some((&authority.x, &authority.y)),
            Some(&input_value_commitment.randomness),
            true,
        )?;
        let output_commitment = synthesize_note_commitment(
            &config.notes,
            layouter.namespace(|| "output note"),
            &self.output_note,
            Some(&values.output_cells[0]),
            Some(&network),
            None,
            Some(&output_value_commitment.randomness),
            true,
        )?;
        layouter.constrain_instance(output_commitment.cell(), config.notes.instance, 0)?;
        synthesize_membership(
            &self.membership,
            &config.membership,
            layouter.namespace(|| "membership and nullifier"),
            &input_commitment,
            0,
            1,
        )
    }
}

#[cfg(test)]
mod tests {
    use group::Curve;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use pasta_curves::{arithmetic::CurveAffine, pallas};

    use super::*;

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    fn note(mut seed: u64, value: u64) -> [Fp; NOTE_COMMITMENT_INPUTS] {
        let mut inputs = std::array::from_fn(|_| {
            seed += 1;
            Fp::from(seed)
        });
        inputs[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(value);
        inputs[1] = Fp::from(9);
        inputs[4] = crate::types::native_asset_fields()[0];
        inputs[5] = crate::types::native_asset_fields()[1];
        inputs
    }

    fn commitment(inputs: [Fp; NOTE_COMMITMENT_INPUTS]) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
            .hash(inputs)
    }

    #[test]
    fn links_balanced_values_to_input_and_output_notes() {
        const DEPTH: usize = 4;
        let generator = crate::spend_auth_circuit::spend_auth_generator();
        let authority_key = (generator * pallas::Scalar::from(17)).to_affine();
        let randomizer = Fp::from(23);
        let randomized_key = (authority_key + generator * pallas::Scalar::from(23)).to_affine();
        let authority_coordinates = authority_key.coordinates().unwrap();
        let randomized_coordinates = randomized_key.coordinates().unwrap();
        let mut input_note = note(10, 30);
        input_note[13] = Fp::from(51);
        input_note[10] = *authority_coordinates.x();
        input_note[11] = *authority_coordinates.y();
        let mut output_note = note(100, 25);
        output_note[13] = Fp::from(52);
        let input_commitment = commitment(input_note);
        let output_commitment = commitment(output_note);
        let siblings = [Fp::from(31), Fp::from(32), Fp::from(33), Fp::from(34)];
        let position = 5u64;
        let mut root = hash2(Fp::from(1), input_commitment);
        for (level, sibling) in siblings.iter().enumerate() {
            let pair = if ((position >> level) & 1) == 0 {
                hash2(root, *sibling)
            } else {
                hash2(*sibling, root)
            };
            root = hash2(Fp::from(2), pair);
        }
        let nullifier_key = Fp::from(41);
        let rho = Fp::from(42);
        let nullifier = hash2(
            Fp::from(3),
            hash2(hash2(nullifier_key, rho), Fp::from(position)),
        );
        let membership = MembershipCircuit::<DEPTH>::new(
            input_commitment,
            &siblings,
            position,
            nullifier_key,
            rho,
        )
        .unwrap();
        let input_value_randomness = Fp::from(51);
        let output_value_randomness = Fp::from(52);
        let input_value_commitment = (crate::spend_auth_circuit::value_generator()
            * pallas::Scalar::from(30)
            + crate::spend_auth_circuit::binding_generator() * pallas::Scalar::from(51))
        .to_affine();
        let output_value_commitment = (crate::spend_auth_circuit::value_generator()
            * pallas::Scalar::from(25)
            + crate::spend_auth_circuit::binding_generator() * pallas::Scalar::from(52))
        .to_affine();
        let circuit = LinkedTransferCircuit::new(
            30,
            25,
            membership,
            input_note,
            output_note,
            SpendAuthCircuit::new(authority_key, randomizer, randomized_key),
            input_value_randomness,
            input_value_commitment,
            output_value_randomness,
            output_value_commitment,
        );
        let input_value_coordinates = input_value_commitment.coordinates().unwrap();
        let output_value_coordinates = output_value_commitment.coordinates().unwrap();
        let instances = vec![
            vec![Fp::from(5)],
            vec![root, nullifier],
            vec![output_commitment, Fp::from(9)],
            vec![
                *randomized_coordinates.x(),
                *randomized_coordinates.y(),
                *input_value_coordinates.x(),
                *input_value_coordinates.y(),
                *output_value_coordinates.x(),
                *output_value_coordinates.y(),
            ],
        ];
        MockProver::run(15, &circuit, instances.clone())
            .unwrap()
            .assert_satisfied();

        let mut wrong_root = instances.clone();
        wrong_root[1][0] += Fp::one();
        assert!(MockProver::run(15, &circuit, wrong_root)
            .unwrap()
            .verify()
            .is_err());

        let mut foreign_output_note = output_note;
        foreign_output_note[4] += Fp::one();
        let mut wrong_output = instances;
        wrong_output[2][0] = commitment(foreign_output_note);
        assert!(MockProver::run(15, &circuit, wrong_output)
            .unwrap()
            .verify()
            .is_err());
    }
}
