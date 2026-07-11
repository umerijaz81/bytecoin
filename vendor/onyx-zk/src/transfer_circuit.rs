//! Onyx O2 native-value conservation circuit component.
//!
//! This is the first production-shaped circuit building block. It range-constrains every fixed
//! input/output slot to 64 bits and proves native inputs = outputs + public fee. Membership,
//! nullifier, commitment, and authorization gadgets are composed in subsequent O2 slices.

use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

use crate::transaction::{MAX_OUTPUTS, MAX_SPENDS};

#[derive(Clone)]
pub struct ValueConfig {
    item: Column<Advice>,
    accumulator: Column<Advice>,
    auxiliary: Column<Advice>,
    instance: Column<Instance>,
    range_selector: Selector,
    sum_selector: Selector,
    balance_selector: Selector,
}

#[derive(Clone)]
pub struct NativeValueCircuit {
    inputs: Vec<Option<u64>>,
    outputs: Vec<Option<u64>>,
}

impl NativeValueCircuit {
    pub fn new(inputs: &[u64], outputs: &[u64]) -> Result<Self, &'static str> {
        if inputs.len() > MAX_SPENDS || outputs.len() > MAX_OUTPUTS {
            return Err("value witness exceeds fixed circuit capacity");
        }
        let mut input_slots = vec![Some(0); MAX_SPENDS];
        let mut output_slots = vec![Some(0); MAX_OUTPUTS];
        for (slot, value) in input_slots.iter_mut().zip(inputs) {
            *slot = Some(*value);
        }
        for (slot, value) in output_slots.iter_mut().zip(outputs) {
            *slot = Some(*value);
        }
        Ok(Self {
            inputs: input_slots,
            outputs: output_slots,
        })
    }

    fn unknown() -> Self {
        Self {
            inputs: vec![None; MAX_SPENDS],
            outputs: vec![None; MAX_OUTPUTS],
        }
    }
}

impl Circuit<Fp> for NativeValueCircuit {
    type Config = ValueConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::unknown()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let item = meta.advice_column();
        let accumulator = meta.advice_column();
        let auxiliary = meta.advice_column();
        let instance = meta.instance_column();
        for column in [item, accumulator, auxiliary] {
            meta.enable_equality(column);
        }
        meta.enable_equality(instance);

        let range_selector = meta.selector();
        meta.create_gate("64-bit decomposition", |meta| {
            let enabled = meta.query_selector(range_selector);
            let bit = meta.query_advice(item, Rotation::cur());
            let accumulator_now = meta.query_advice(accumulator, Rotation::cur());
            let accumulator_next = meta.query_advice(accumulator, Rotation::next());
            vec![
                enabled.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fp::one())),
                enabled * (accumulator_next - accumulator_now * Fp::from(2) - bit),
            ]
        });

        let sum_selector = meta.selector();
        meta.create_gate("running sum", |meta| {
            let enabled = meta.query_selector(sum_selector);
            let value = meta.query_advice(item, Rotation::cur());
            let sum_now = meta.query_advice(accumulator, Rotation::cur());
            let sum_next = meta.query_advice(accumulator, Rotation::next());
            vec![enabled * (sum_next - sum_now - value)]
        });

        let balance_selector = meta.selector();
        meta.create_gate("native value balance", |meta| {
            let enabled = meta.query_selector(balance_selector);
            let inputs = meta.query_advice(item, Rotation::cur());
            let outputs = meta.query_advice(accumulator, Rotation::cur());
            let fee = meta.query_advice(auxiliary, Rotation::cur());
            vec![enabled * (inputs - outputs - fee)]
        });

        ValueConfig {
            item,
            accumulator,
            auxiliary,
            instance,
            range_selector,
            sum_selector,
            balance_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut input_cells = Vec::with_capacity(MAX_SPENDS);
        for (index, value) in self.inputs.iter().enumerate() {
            input_cells.push(assign_u64(
                layouter.namespace(|| format!("input {index}")),
                &config,
                *value,
            )?);
        }
        let mut output_cells = Vec::with_capacity(MAX_OUTPUTS);
        for (index, value) in self.outputs.iter().enumerate() {
            output_cells.push(assign_u64(
                layouter.namespace(|| format!("output {index}")),
                &config,
                *value,
            )?);
        }
        let input_total = assign_sum(layouter.namespace(|| "input total"), &config, &input_cells)?;
        let output_total = assign_sum(
            layouter.namespace(|| "output total"),
            &config,
            &output_cells,
        )?;

        layouter.assign_region(
            || "balance",
            |mut region| {
                config.balance_selector.enable(&mut region, 0)?;
                input_total.copy_advice(|| "inputs", &mut region, config.item, 0)?;
                output_total.copy_advice(|| "outputs", &mut region, config.accumulator, 0)?;
                region.assign_advice_from_instance(
                    || "fee",
                    config.instance,
                    0,
                    config.auxiliary,
                    0,
                )?;
                Ok(())
            },
        )
    }
}

fn assign_u64(
    mut layouter: impl Layouter<Fp>,
    config: &ValueConfig,
    witness: Option<u64>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || "range-constrained value",
        |mut region| {
            let mut accumulator_value = witness.map(|_| 0u64);
            region.assign_advice(
                || "accumulator 0",
                config.accumulator,
                0,
                || {
                    accumulator_value
                        .map(Fp::from)
                        .map_or(Value::unknown(), Value::known)
                },
            )?;
            let mut final_cell = None;
            for row in 0..64 {
                config.range_selector.enable(&mut region, row)?;
                let bit_index = 63 - row;
                let bit = witness.map(|value| (value >> bit_index) & 1);
                region.assign_advice(
                    || "bit",
                    config.item,
                    row,
                    || bit.map(Fp::from).map_or(Value::unknown(), Value::known),
                )?;
                accumulator_value = match (accumulator_value, bit) {
                    (Some(accumulator), Some(bit)) => Some(accumulator * 2 + bit),
                    _ => None,
                };
                final_cell = Some(region.assign_advice(
                    || "next accumulator",
                    config.accumulator,
                    row + 1,
                    || {
                        accumulator_value
                            .map(Fp::from)
                            .map_or(Value::unknown(), Value::known)
                    },
                )?);
            }
            Ok(final_cell.expect("64 rows always assigned"))
        },
    )
}

fn assign_sum(
    mut layouter: impl Layouter<Fp>,
    config: &ValueConfig,
    values: &[AssignedCell<Fp, Fp>],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || "sum",
        |mut region| {
            let mut sum = Value::known(Fp::zero());
            region.assign_advice(|| "sum 0", config.accumulator, 0, || sum)?;
            let mut final_cell = None;
            for (row, value) in values.iter().enumerate() {
                config.sum_selector.enable(&mut region, row)?;
                value.copy_advice(|| "item", &mut region, config.item, row)?;
                sum = sum + value.value().copied();
                final_cell = Some(region.assign_advice(
                    || "next sum",
                    config.accumulator,
                    row + 1,
                    || sum,
                )?);
            }
            Ok(final_cell.expect("fixed-capacity list is nonempty"))
        },
    )
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::EqAffine;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

    use super::*;

    const K: u32 = 13;

    #[test]
    fn native_value_balance_accepts_valid_transfer() {
        let circuit = NativeValueCircuit::new(&[10, 20], &[7, 18]).unwrap();
        let prover = MockProver::run(K, &circuit, vec![vec![Fp::from(5)]]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn native_value_balance_rejects_inflation_and_wrong_fee() {
        let circuit = NativeValueCircuit::new(&[10], &[10]).unwrap();
        let inflation = MockProver::run(K, &circuit, vec![vec![Fp::from(1)]]).unwrap();
        assert!(inflation.verify().is_err());

        let circuit = NativeValueCircuit::new(&[10], &[8]).unwrap();
        let wrong_fee = MockProver::run(K, &circuit, vec![vec![Fp::from(1)]]).unwrap();
        assert!(wrong_fee.verify().is_err());
    }

    #[test]
    fn native_value_circuit_enforces_capacity() {
        assert!(NativeValueCircuit::new(&vec![1; MAX_SPENDS + 1], &[]).is_err());
        assert!(NativeValueCircuit::new(&[], &vec![1; MAX_OUTPUTS + 1]).is_err());
    }

    #[test]
    fn native_value_proof_round_trip_binds_public_fee() {
        let params: Params<EqAffine> = Params::new(K);
        let circuit = NativeValueCircuit::new(&[10, 20], &[7, 18]).unwrap();
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
        let fee = Fp::from(5);
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
        create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&[fee]]],
            rand::rngs::OsRng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);
        assert!(verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
            &params,
            &vk,
            SingleVerifier::new(&params),
            &[&[&[fee]]],
            &mut reader,
        )
        .is_ok());

        let wrong_fee = Fp::from(4);
        let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);
        assert!(verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
            &params,
            &vk,
            SingleVerifier::new(&params),
            &[&[&[wrong_fee]]],
            &mut reader,
        )
        .is_err());
    }
}
