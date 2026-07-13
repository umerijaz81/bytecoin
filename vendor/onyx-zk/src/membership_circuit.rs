//! Onyx O2 Merkle-membership and nullifier-correctness circuit component.

use std::array;

use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3};
use halo2_gadgets::poseidon::{Hash, Pow5Chip, Pow5Config};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
};
use halo2_proofs::poly::Rotation;

const LEAF_TAG: u64 = 1;
const NODE_TAG: u64 = 2;
const NULLIFIER_TAG: u64 = 3;

#[derive(Clone)]
pub struct MembershipConfig {
    poseidon: Pow5Config<Fp, 3, 2>,
    poseidon_state: [Column<Advice>; 3],
    select: [Column<Advice>; 5],
    instance: Column<Instance>,
    select_selector: Selector,
    position_selector: Selector,
}

#[derive(Clone)]
pub struct MembershipCircuit<const DEPTH: usize> {
    commitment: Option<Fp>,
    siblings: Vec<Option<Fp>>,
    position: Option<u64>,
    nullifier_key: Option<Fp>,
    rho: Option<Fp>,
}

impl<const DEPTH: usize> MembershipCircuit<DEPTH> {
    pub fn new(
        commitment: Fp,
        siblings: &[Fp],
        position: u64,
        nullifier_key: Fp,
        rho: Fp,
    ) -> Result<Self, &'static str> {
        if DEPTH == 0 || DEPTH >= 64 || siblings.len() != DEPTH || position >= (1u64 << DEPTH) {
            return Err("invalid membership witness shape");
        }
        Ok(Self {
            commitment: Some(commitment),
            siblings: siblings.iter().copied().map(Some).collect(),
            position: Some(position),
            nullifier_key: Some(nullifier_key),
            rho: Some(rho),
        })
    }

    fn unknown() -> Self {
        Self {
            commitment: None,
            siblings: vec![None; DEPTH],
            position: None,
            nullifier_key: None,
            rho: None,
        }
    }
}

impl<const DEPTH: usize> Circuit<Fp> for MembershipCircuit<DEPTH> {
    type Config = MembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::unknown()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a = array::from_fn(|_| meta.fixed_column());
        let rc_b = array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        let select = array::from_fn(|_| meta.advice_column());
        for column in select {
            meta.enable_equality(column);
        }
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let select_selector = meta.selector();
        meta.create_gate("conditional Merkle ordering", |meta| {
            let enabled = meta.query_selector(select_selector);
            let left = meta.query_advice(select[0], Rotation::cur());
            let right = meta.query_advice(select[1], Rotation::cur());
            let bit = meta.query_advice(select[2], Rotation::cur());
            let ordered_left = meta.query_advice(select[3], Rotation::cur());
            let ordered_right = meta.query_advice(select[4], Rotation::cur());
            vec![
                enabled.clone() * bit.clone() * (bit.clone() - Expression::Constant(Fp::one())),
                enabled.clone()
                    * (ordered_left
                        - (left.clone() + bit.clone() * (right.clone() - left.clone()))),
                enabled * (ordered_right - (right.clone() + bit * (left - right))),
            ]
        });

        let position_selector = meta.selector();
        meta.create_gate("position from path bits", |meta| {
            let enabled = meta.query_selector(position_selector);
            let bit = meta.query_advice(select[0], Rotation::cur());
            let current = meta.query_advice(select[1], Rotation::cur());
            let next = meta.query_advice(select[1], Rotation::next());
            vec![enabled * (next - current * Fp::from(2) - bit)]
        });

        MembershipConfig {
            poseidon,
            poseidon_state: state,
            select,
            instance,
            select_selector,
            position_selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let commitment = assign_value(
            layouter.namespace(|| "commitment"),
            config.poseidon_state[0],
            self.commitment,
        )?;
        layouter.constrain_instance(commitment.cell(), config.instance, 2)?;
        synthesize_membership(self, &config, layouter, &commitment, 0, 1)
    }
}

pub(crate) fn synthesize_membership<const DEPTH: usize>(
    circuit: &MembershipCircuit<DEPTH>,
    config: &MembershipConfig,
    mut layouter: impl Layouter<Fp>,
    commitment: &AssignedCell<Fp, Fp>,
    anchor_row: usize,
    nullifier_row: usize,
) -> Result<(), Error> {
    let leaf_tag = assign_constant(
        layouter.namespace(|| "leaf tag"),
        config.poseidon_state[0],
        Fp::from(LEAF_TAG),
    )?;
    let mut node = hash2(
        &config.poseidon,
        &config.poseidon_state,
        layouter.namespace(|| "leaf hash"),
        &leaf_tag,
        &commitment,
    )?;
    let mut path_bits = Vec::with_capacity(DEPTH);
    for level in 0..DEPTH {
        let sibling = assign_value(
            layouter.namespace(|| format!("sibling {level}")),
            config.poseidon_state[0],
            circuit.siblings[level],
        )?;
        let bit = circuit
            .position
            .map(|position| Fp::from((position >> level) & 1));
        let (left, right, bit_cell) = order_pair(
            layouter.namespace(|| format!("path order {level}")),
            &config,
            &node,
            &sibling,
            bit,
        )?;
        path_bits.push(bit_cell);
        let inner = hash2(
            &config.poseidon,
            &config.poseidon_state,
            layouter.namespace(|| format!("node pair {level}")),
            &left,
            &right,
        )?;
        let node_tag = assign_constant(
            layouter.namespace(|| format!("node tag {level}")),
            config.poseidon_state[0],
            Fp::from(NODE_TAG),
        )?;
        node = hash2(
            &config.poseidon,
            &config.poseidon_state,
            layouter.namespace(|| format!("node hash {level}")),
            &node_tag,
            &inner,
        )?;
    }
    layouter.constrain_instance(node.cell(), config.instance, anchor_row)?;

    let position = compose_position(
        layouter.namespace(|| "compose position"),
        &config,
        &path_bits,
    )?;
    let nullifier_key = assign_value(
        layouter.namespace(|| "nullifier key"),
        config.poseidon_state[0],
        circuit.nullifier_key,
    )?;
    let rho = assign_value(
        layouter.namespace(|| "rho"),
        config.poseidon_state[0],
        circuit.rho,
    )?;
    let inner = hash2(
        &config.poseidon,
        &config.poseidon_state,
        layouter.namespace(|| "nullifier key and rho"),
        &nullifier_key,
        &rho,
    )?;
    let positioned = hash2(
        &config.poseidon,
        &config.poseidon_state,
        layouter.namespace(|| "nullifier position"),
        &inner,
        &position,
    )?;
    let nullifier_tag = assign_constant(
        layouter.namespace(|| "nullifier tag"),
        config.poseidon_state[0],
        Fp::from(NULLIFIER_TAG),
    )?;
    let nullifier = hash2(
        &config.poseidon,
        &config.poseidon_state,
        layouter.namespace(|| "nullifier hash"),
        &nullifier_tag,
        &positioned,
    )?;
    layouter.constrain_instance(nullifier.cell(), config.instance, nullifier_row)
}

fn assign_value(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    value: Option<Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || "load value",
        |mut region| {
            region.assign_advice(
                || "value",
                column,
                0,
                || value.map_or(Value::unknown(), Value::known),
            )
        },
    )
}

fn assign_constant(
    mut layouter: impl Layouter<Fp>,
    column: Column<Advice>,
    value: Fp,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || "load constant",
        |mut region| region.assign_advice_from_constant(|| "constant", column, 0, value),
    )
}

fn hash2(
    poseidon: &Pow5Config<Fp, 3, 2>,
    state: &[Column<Advice>; 3],
    mut layouter: impl Layouter<Fp>,
    first: &AssignedCell<Fp, Fp>,
    second: &AssignedCell<Fp, Fp>,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let message = layouter.assign_region(
        || "load hash message",
        |mut region| {
            Ok([
                first.copy_advice(|| "first", &mut region, state[0], 0)?,
                second.copy_advice(|| "second", &mut region, state[1], 0)?,
            ])
        },
    )?;
    Hash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
        Pow5Chip::construct(poseidon.clone()),
        layouter.namespace(|| "init hash"),
    )?
    .hash(layouter.namespace(|| "hash"), message)
}

fn order_pair(
    mut layouter: impl Layouter<Fp>,
    config: &MembershipConfig,
    node: &AssignedCell<Fp, Fp>,
    sibling: &AssignedCell<Fp, Fp>,
    bit: Option<Fp>,
) -> Result<
    (
        AssignedCell<Fp, Fp>,
        AssignedCell<Fp, Fp>,
        AssignedCell<Fp, Fp>,
    ),
    Error,
> {
    layouter.assign_region(
        || "order pair",
        |mut region| {
            config.select_selector.enable(&mut region, 0)?;
            node.copy_advice(|| "node", &mut region, config.select[0], 0)?;
            sibling.copy_advice(|| "sibling", &mut region, config.select[1], 0)?;
            let bit_cell = region.assign_advice(
                || "path bit",
                config.select[2],
                0,
                || bit.map_or(Value::unknown(), Value::known),
            )?;
            let left_value = node
                .value()
                .zip(sibling.value())
                .zip(bit_cell.value())
                .map(|((node, sibling), bit)| *node + *bit * (*sibling - *node));
            let right_value = node
                .value()
                .zip(sibling.value())
                .zip(bit_cell.value())
                .map(|((node, sibling), bit)| *sibling + *bit * (*node - *sibling));
            let left = region.assign_advice(|| "left", config.select[3], 0, || left_value)?;
            let right = region.assign_advice(|| "right", config.select[4], 0, || right_value)?;
            Ok((left, right, bit_cell))
        },
    )
}

fn compose_position(
    mut layouter: impl Layouter<Fp>,
    config: &MembershipConfig,
    little_endian_bits: &[AssignedCell<Fp, Fp>],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    layouter.assign_region(
        || "position accumulator",
        |mut region| {
            let mut accumulator = Value::known(Fp::zero());
            region.assign_advice(|| "position 0", config.select[1], 0, || accumulator)?;
            let mut result = None;
            for (row, bit) in little_endian_bits.iter().rev().enumerate() {
                config.position_selector.enable(&mut region, row)?;
                bit.copy_advice(|| "bit", &mut region, config.select[0], row)?;
                accumulator = accumulator * Value::known(Fp::from(2)) + bit.value().copied();
                result = Some(region.assign_advice(
                    || "next position",
                    config.select[1],
                    row + 1,
                    || accumulator,
                )?);
            }
            Ok(result.expect("membership depth is nonzero"))
        },
    )
}

#[cfg(test)]
mod tests {
    use halo2_gadgets::poseidon::primitives::{Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::EqAffine;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

    use super::*;

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    fn leaf(commitment: Fp) -> Fp {
        hash2(Fp::from(LEAF_TAG), commitment)
    }

    fn node(left: Fp, right: Fp) -> Fp {
        hash2(Fp::from(NODE_TAG), hash2(left, right))
    }

    fn nullifier(key: Fp, rho: Fp, position: u64) -> Fp {
        hash2(
            Fp::from(NULLIFIER_TAG),
            hash2(hash2(key, rho), Fp::from(position)),
        )
    }

    #[test]
    fn membership_and_nullifier_constraints_match_native_primitives() {
        const DEPTH: usize = 4;
        let commitment = Fp::from(7);
        let siblings = [Fp::from(11), Fp::from(12), Fp::from(13), Fp::from(14)];
        let position = 5u64;
        let mut root = leaf(commitment);
        for (level, sibling) in siblings.iter().enumerate() {
            root = if ((position >> level) & 1) == 0 {
                node(root, *sibling)
            } else {
                node(*sibling, root)
            };
        }
        let key = Fp::from(21);
        let rho = Fp::from(22);
        let nf = nullifier(key, rho, position);
        let circuit =
            MembershipCircuit::<DEPTH>::new(commitment, &siblings, position, key, rho).unwrap();
        let prover = MockProver::run(12, &circuit, vec![vec![root, nf, commitment]]).unwrap();
        prover.assert_satisfied();

        let bad_root =
            MockProver::run(12, &circuit, vec![vec![root + Fp::one(), nf, commitment]]).unwrap();
        assert!(bad_root.verify().is_err());
        let bad_nf =
            MockProver::run(12, &circuit, vec![vec![root, nf + Fp::one(), commitment]]).unwrap();
        assert!(bad_nf.verify().is_err());
    }

    #[test]
    fn membership_proof_round_trip_binds_anchor_and_nullifier() {
        const DEPTH: usize = 4;
        const K: u32 = 12;
        let commitment = Fp::from(31);
        let siblings = [Fp::from(32), Fp::from(33), Fp::from(34), Fp::from(35)];
        let position = 6u64;
        let mut root = leaf(commitment);
        for (level, sibling) in siblings.iter().enumerate() {
            root = if ((position >> level) & 1) == 0 {
                node(root, *sibling)
            } else {
                node(*sibling, root)
            };
        }
        let nf = nullifier(Fp::from(36), Fp::from(37), position);
        let circuit = MembershipCircuit::<DEPTH>::new(
            commitment,
            &siblings,
            position,
            Fp::from(36),
            Fp::from(37),
        )
        .unwrap();
        let params: Params<EqAffine> = Params::new(K);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
        create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&[root, nf, commitment]]],
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
            &[&[&[root, nf, commitment]]],
            &mut reader,
        )
        .is_ok());
        let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);
        assert!(verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
            &params,
            &vk,
            SingleVerifier::new(&params),
            &[&[&[root + Fp::one(), nf]]],
            &mut reader,
        )
        .is_err());
    }
}
