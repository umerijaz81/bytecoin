//! Const-shaped multi-spend/multi-output transfer circuit family.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use crate::membership_circuit::{synthesize_membership, MembershipCircuit, MembershipConfig};
use crate::note_commitment_circuit::{
    synthesize_note_commitment, NoteCommitmentCircuit, NoteCommitmentConfig, NOTE_COMMITMENT_INPUTS,
};
use crate::spend_auth_circuit::{
    configure_spend_authority, synthesize_spend_authority, synthesize_value_commitment,
    SpendAuthCircuit, SpendAuthConfig,
};
use crate::transaction::{MAX_OUTPUTS, MAX_SPENDS};
use crate::transfer_circuit::{synthesize_native_values, NativeValueCircuit, ValueConfig};
use pasta_curves::pallas;

#[derive(Clone)]
pub struct LinkedSpend<const DEPTH: usize> {
    membership: MembershipCircuit<DEPTH>,
    note: [Option<Fp>; NOTE_COMMITMENT_INPUTS],
    authorization: SpendAuthCircuit,
    value_randomness: Option<Fp>,
    value_commitment: Option<pallas::Affine>,
}

impl<const DEPTH: usize> LinkedSpend<DEPTH> {
    pub fn new(
        membership: MembershipCircuit<DEPTH>,
        note: [Fp; NOTE_COMMITMENT_INPUTS],
        authorization: SpendAuthCircuit,
        value_randomness: Fp,
        value_commitment: pallas::Affine,
    ) -> Self {
        Self {
            membership,
            note: note.map(Some),
            authorization,
            value_randomness: Some(value_randomness),
            value_commitment: Some(value_commitment),
        }
    }

    fn without_witnesses(&self) -> Self {
        Self {
            membership: self.membership.without_witnesses(),
            note: [None; NOTE_COMMITMENT_INPUTS],
            authorization: self.authorization.without_witnesses(),
            value_randomness: None,
            value_commitment: None,
        }
    }
}

#[derive(Clone)]
pub struct MultiTransferConfig {
    values: ValueConfig,
    membership: MembershipConfig,
    notes: NoteCommitmentConfig,
    authorization: SpendAuthConfig,
}

#[derive(Clone)]
pub struct MultiTransferCircuit<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize> {
    values: NativeValueCircuit,
    spends: Vec<LinkedSpend<DEPTH>>,
    outputs: Vec<[Option<Fp>; NOTE_COMMITMENT_INPUTS]>,
    output_value_randomness: Vec<Option<Fp>>,
    output_value_commitments: Vec<Option<pallas::Affine>>,
}

impl<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize>
    MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>
{
    pub fn new(
        input_values: &[u64],
        output_values: &[u64],
        spends: Vec<LinkedSpend<DEPTH>>,
        outputs: Vec<[Fp; NOTE_COMMITMENT_INPUTS]>,
        output_value_randomness: Vec<Fp>,
        output_value_commitments: Vec<pallas::Affine>,
    ) -> Result<Self, &'static str> {
        if SPENDS == 0
            || OUTPUTS == 0
            || SPENDS > MAX_SPENDS
            || OUTPUTS > MAX_OUTPUTS
            || input_values.len() != SPENDS
            || output_values.len() != OUTPUTS
            || spends.len() != SPENDS
            || outputs.len() != OUTPUTS
            || output_value_randomness.len() != OUTPUTS
            || output_value_commitments.len() != OUTPUTS
        {
            return Err("witness does not match circuit-family shape");
        }
        Ok(Self {
            values: NativeValueCircuit::new(input_values, output_values)?,
            spends,
            outputs: outputs.into_iter().map(|note| note.map(Some)).collect(),
            output_value_randomness: output_value_randomness.into_iter().map(Some).collect(),
            output_value_commitments: output_value_commitments.into_iter().map(Some).collect(),
        })
    }
}

impl<const DEPTH: usize, const SPENDS: usize, const OUTPUTS: usize> Circuit<Fp>
    for MultiTransferCircuit<DEPTH, SPENDS, OUTPUTS>
{
    type Config = MultiTransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            values: self.values.without_witnesses(),
            spends: self
                .spends
                .iter()
                .map(LinkedSpend::without_witnesses)
                .collect(),
            outputs: vec![[None; NOTE_COMMITMENT_INPUTS]; OUTPUTS],
            output_value_randomness: vec![None; OUTPUTS],
            output_value_commitments: vec![None; OUTPUTS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            values: NativeValueCircuit::configure(meta),
            membership: MembershipCircuit::<DEPTH>::configure(meta),
            notes: NoteCommitmentCircuit::configure(meta),
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
            layouter.namespace(|| "all native values"),
        )?;
        let network = layouter.assign_region(
            || "transaction network",
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

        for (index, spend) in self.spends.iter().enumerate() {
            let authority = synthesize_spend_authority(
                &spend.authorization,
                &config.authorization,
                layouter.namespace(|| format!("spend {index} authorization")),
                index == 0,
                index * 2,
                index * 2 + 1,
            )?;
            let value_commitment = synthesize_value_commitment(
                &config.authorization,
                layouter.namespace(|| format!("spend {index} value commitment")),
                &values.input_cells[index],
                spend.value_randomness,
                spend.value_commitment,
                false,
                SPENDS * 2 + index * 2,
                SPENDS * 2 + index * 2 + 1,
            )?;
            let commitment = synthesize_note_commitment(
                &config.notes,
                layouter.namespace(|| format!("spend {index} note")),
                &spend.note,
                Some(&values.input_cells[index]),
                Some(&network),
                Some((&authority.x, &authority.y)),
                Some(&value_commitment.randomness),
                true,
            )?;
            synthesize_membership(
                &spend.membership,
                &config.membership,
                layouter.namespace(|| format!("spend {index} membership")),
                &commitment,
                0,
                index + 1,
            )?;
        }

        for (index, note) in self.outputs.iter().enumerate() {
            let value_commitment = synthesize_value_commitment(
                &config.authorization,
                layouter.namespace(|| format!("output {index} value commitment")),
                &values.output_cells[index],
                self.output_value_randomness[index],
                self.output_value_commitments[index],
                false,
                SPENDS * 4 + index * 2,
                SPENDS * 4 + index * 2 + 1,
            )?;
            let commitment = synthesize_note_commitment(
                &config.notes,
                layouter.namespace(|| format!("output {index} note")),
                note,
                Some(&values.output_cells[index]),
                Some(&network),
                None,
                Some(&value_commitment.randomness),
                true,
            )?;
            layouter.constrain_instance(commitment.cell(), config.notes.instance, index)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use group::Curve;
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use pasta_curves::{arithmetic::CurveAffine, pallas};

    use super::*;

    fn hash2(a: Fp, b: Fp) -> Fp {
        Hash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
    }

    fn note(seed: u64, value: u64) -> [Fp; NOTE_COMMITMENT_INPUTS] {
        let mut note = std::array::from_fn(|i| Fp::from(seed + i as u64));
        note[crate::note_commitment_circuit::NOTE_VALUE_INPUT_INDEX] = Fp::from(value);
        note[1] = Fp::from(9);
        note[4] = crate::types::native_asset_fields()[0];
        note[5] = crate::types::native_asset_fields()[1];
        note
    }

    fn commitment(note: [Fp; NOTE_COMMITMENT_INPUTS]) -> Fp {
        Hash::<Fp, P128Pow5T3, ConstantLength<NOTE_COMMITMENT_INPUTS>, 3, 2>::init().hash(note)
    }

    #[test]
    fn two_spends_and_outputs_share_ordered_public_inputs() {
        const DEPTH: usize = 2;
        let generator = crate::spend_auth_circuit::spend_auth_generator();
        let mut input_notes = [note(10, 30), note(40, 20)];
        let mut spends = Vec::new();
        let authorities: Vec<_> = [7u64, 11]
            .into_iter()
            .map(|secret| (generator * pallas::Scalar::from(secret)).to_affine())
            .collect();
        for (note, authority) in input_notes.iter_mut().zip(&authorities) {
            let coordinates = authority.coordinates().unwrap();
            note[10] = *coordinates.x();
            note[11] = *coordinates.y();
        }
        input_notes[0][13] = Fp::from(50);
        input_notes[1][13] = Fp::from(51);
        let commitments = input_notes.map(commitment);
        let leaves = commitments.map(|cm| hash2(Fp::from(1), cm));
        let parent = hash2(Fp::from(2), hash2(leaves[0], leaves[1]));
        let other = Fp::from(91);
        let root = hash2(Fp::from(2), hash2(parent, other));
        let keys = [Fp::from(61), Fp::from(62)];
        let rhos = [Fp::from(71), Fp::from(72)];
        let mut nullifiers = Vec::new();
        let mut randomized_public = Vec::new();
        let mut input_value_public = Vec::new();
        for index in 0..2 {
            let position = index as u64;
            let siblings = [leaves[1 - index], other];
            let membership = MembershipCircuit::<DEPTH>::new(
                commitments[index],
                &siblings,
                position,
                keys[index],
                rhos[index],
            )
            .unwrap();
            nullifiers.push(hash2(
                Fp::from(3),
                hash2(hash2(keys[index], rhos[index]), Fp::from(position)),
            ));
            let randomizer = Fp::from(20 + index as u64);
            let randomized = (authorities[index]
                + generator * pallas::Scalar::from(20 + index as u64))
            .to_affine();
            let coordinates = randomized.coordinates().unwrap();
            randomized_public.extend([*coordinates.x(), *coordinates.y()]);
            let value_randomness = Fp::from(50 + index as u64);
            let value_commitment = (crate::spend_auth_circuit::value_generator()
                * pallas::Scalar::from([30, 20][index])
                + crate::spend_auth_circuit::binding_generator()
                    * pallas::Scalar::from(50 + index as u64))
            .to_affine();
            let value_coordinates = value_commitment.coordinates().unwrap();
            input_value_public.extend([*value_coordinates.x(), *value_coordinates.y()]);
            spends.push(LinkedSpend::new(
                membership,
                input_notes[index],
                SpendAuthCircuit::new(authorities[index], randomizer, randomized),
                value_randomness,
                value_commitment,
            ));
        }
        let mut outputs = vec![note(100, 25), note(130, 20)];
        outputs[0][13] = Fp::from(60);
        outputs[1][13] = Fp::from(61);
        let output_commitments: Vec<_> = outputs.iter().copied().map(commitment).collect();
        let output_value_randomness = vec![Fp::from(60), Fp::from(61)];
        let output_value_commitments = [25u64, 20]
            .into_iter()
            .zip([60u64, 61])
            .map(|(value, randomness)| {
                (crate::spend_auth_circuit::value_generator() * pallas::Scalar::from(value)
                    + crate::spend_auth_circuit::binding_generator()
                        * pallas::Scalar::from(randomness))
                .to_affine()
            })
            .collect::<Vec<_>>();
        let mut value_public = input_value_public;
        for commitment in &output_value_commitments {
            let coordinates = commitment.coordinates().unwrap();
            value_public.extend([*coordinates.x(), *coordinates.y()]);
        }
        randomized_public.extend(value_public);
        let circuit = MultiTransferCircuit::<DEPTH, 2, 2>::new(
            &[30, 20],
            &[25, 20],
            spends,
            outputs,
            output_value_randomness,
            output_value_commitments,
        )
        .unwrap();
        let instances = vec![
            vec![Fp::from(5)],
            vec![root, nullifiers[0], nullifiers[1]],
            {
                let mut commitments = output_commitments;
                commitments.push(Fp::from(9));
                commitments
            },
            randomized_public,
        ];
        MockProver::run(16, &circuit, instances.clone())
            .unwrap()
            .assert_satisfied();

        let mut reordered = instances;
        reordered[1].swap(1, 2);
        assert!(MockProver::run(16, &circuit, reordered)
            .unwrap()
            .verify()
            .is_err());
    }

    #[test]
    fn circuit_family_rejects_empty_mismatched_and_oversized_shapes() {
        assert!(
            MultiTransferCircuit::<2, 0, 0>::new(&[], &[], vec![], vec![], vec![], vec![]).is_err()
        );
        assert!(
            MultiTransferCircuit::<2, 1, 1>::new(&[], &[], vec![], vec![], vec![], vec![]).is_err()
        );
        assert!(
            MultiTransferCircuit::<2, 17, 1>::new(&[], &[], vec![], vec![], vec![], vec![])
                .is_err()
        );
    }
}
