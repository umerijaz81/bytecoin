//! Linked one-spend, one-output Onyx transfer circuit.
//!
//! This composition connects the private values used by balance conservation to the exact input
//! and output note commitments. The input commitment is also the public leaf consumed by the
//! membership/nullifier component.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use crate::membership_circuit::{MembershipCircuit, MembershipConfig};
use crate::note_commitment_circuit::{
    synthesize_note_commitment, NoteCommitmentConfig, NOTE_COMMITMENT_INPUTS,
};
use crate::transfer_circuit::{synthesize_native_values, NativeValueCircuit, ValueConfig};

#[derive(Clone)]
pub struct LinkedTransferConfig {
    values: ValueConfig,
    membership: MembershipConfig,
    notes: NoteCommitmentConfig,
}

#[derive(Clone)]
pub struct LinkedTransferCircuit<const DEPTH: usize> {
    values: NativeValueCircuit,
    membership: MembershipCircuit<DEPTH>,
    input_note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
    output_note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
}

impl<const DEPTH: usize> LinkedTransferCircuit<DEPTH> {
    pub fn new(
        input_value: u64,
        output_value: u64,
        membership: MembershipCircuit<DEPTH>,
        input_note: [Fp; NOTE_COMMITMENT_INPUTS],
        output_note: [Fp; NOTE_COMMITMENT_INPUTS],
    ) -> Self {
        Self {
            values: NativeValueCircuit::new(&[input_value], &[output_value])
                .expect("one input and output fit fixed capacity"),
            membership,
            input_note: input_note.map(Some),
            output_note: output_note.map(Some),
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
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            values: NativeValueCircuit::configure(meta),
            membership: MembershipCircuit::<DEPTH>::configure(meta),
            notes: crate::note_commitment_circuit::NoteCommitmentCircuit::configure(meta),
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
        let input_commitment = synthesize_note_commitment(
            &config.notes,
            layouter.namespace(|| "input note"),
            &self.input_note,
            Some(&values.input_cells[0]),
        )?;
        let output_commitment = synthesize_note_commitment(
            &config.notes,
            layouter.namespace(|| "output note"),
            &self.output_note,
            Some(&values.output_cells[0]),
        )?;
        layouter.constrain_instance(input_commitment.cell(), config.notes.instance, 0)?;
        layouter.constrain_instance(output_commitment.cell(), config.notes.instance, 1)?;
        self.membership.synthesize(
            config.membership,
            layouter.namespace(|| "membership and nullifier"),
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;

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
        inputs
    }

    fn commitment(inputs: [Fp; NOTE_COMMITMENT_INPUTS]) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init()
            .hash(inputs)
    }

    #[test]
    fn links_balanced_values_to_input_and_output_notes() {
        const DEPTH: usize = 4;
        let input_note = note(10, 30);
        let output_note = note(100, 25);
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
        let circuit = LinkedTransferCircuit::new(30, 25, membership, input_note, output_note);
        let instances = vec![
            vec![Fp::from(5)],
            vec![root, nullifier, input_commitment],
            vec![input_commitment, output_commitment],
        ];
        MockProver::run(15, &circuit, instances)
            .unwrap()
            .assert_satisfied();
    }
}
