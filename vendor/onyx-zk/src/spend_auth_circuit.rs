//! In-circuit RedPallas randomized spend-authority key linkage.
//!
//! This proves `rk = ak + [alpha] SpendAuthG`, exposes only `rk`, and returns the private `ak`
//! coordinates so the transfer circuit can copy them directly into the input-note commitment.

use group::{Curve, GroupEncoding};
use halo2_gadgets::ecc::chip::{
    BaseFieldElem, CircuitVersion, EccChip, EccConfig, FixedPoint as FixedPointInstructions,
    FullScalar, ShortScalar,
};
use halo2_gadgets::ecc::{FixedPoints, NonIdentityPoint, Point, ScalarVar};
use halo2_gadgets::utilities::lookup_range_check::{
    LookupRangeCheck, PallasLookupRangeCheckConfig,
};
use halo2_gadgets::utilities::UtilitiesInstructions;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::TableColumn;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance};
use pasta_curves::{arithmetic::CurveExt, pallas};

pub const SPEND_AUTH_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];
pub const BINDING_BASEPOINT_BYTES: [u8; 32] = [
    145, 90, 60, 136, 104, 198, 195, 14, 47, 128, 144, 238, 69, 215, 110, 64, 72, 32, 141, 234, 91,
    35, 102, 79, 187, 9, 164, 15, 85, 68, 244, 7,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnusedFixedBases;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnusedFull;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnusedShort;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnusedBase;

pub(crate) fn spend_auth_generator() -> pallas::Affine {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(&SPEND_AUTH_BASEPOINT_BYTES))
        .expect("frozen RedPallas SpendAuth basepoint is canonical")
        .to_affine()
}

pub(crate) fn value_generator() -> pallas::Affine {
    pallas::Point::hash_to_curve("bytecoin.onyx.v6.value-commitment")(b"v").to_affine()
}

pub(crate) fn binding_generator() -> pallas::Affine {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(&BINDING_BASEPOINT_BYTES))
        .expect("frozen RedPallas Binding basepoint is canonical")
        .to_affine()
}

macro_rules! unused_fixed_point {
    ($point:ty, $kind:ty) => {
        impl FixedPointInstructions<pallas::Affine> for $point {
            type FixedScalarKind = $kind;

            fn generator(&self) -> pallas::Affine {
                spend_auth_generator()
            }

            fn u(&self) -> Vec<[[u8; 32]; 8]> {
                Vec::new()
            }

            fn z(&self) -> Vec<u64> {
                Vec::new()
            }
        }
    };
}

unused_fixed_point!(UnusedFull, FullScalar);
unused_fixed_point!(UnusedShort, ShortScalar);
unused_fixed_point!(UnusedBase, BaseFieldElem);

impl FixedPoints<pallas::Affine> for UnusedFixedBases {
    type FullScalar = UnusedFull;
    type ShortScalar = UnusedShort;
    type Base = UnusedBase;
}

type AuthEccChip = EccChip<UnusedFixedBases>;

#[derive(Clone)]
pub struct SpendAuthConfig {
    ecc: EccConfig<UnusedFixedBases>,
    lookup_table: TableColumn,
    instance: Column<Instance>,
}

#[derive(Clone)]
pub struct SpendAuthCircuit {
    authority_key: Option<pallas::Affine>,
    randomizer: Option<Fp>,
    randomized_key: Option<pallas::Affine>,
}

pub(crate) struct AssignedSpendAuthority {
    pub x: AssignedCell<Fp, Fp>,
    pub y: AssignedCell<Fp, Fp>,
}

#[allow(dead_code)]
pub(crate) struct AssignedValueCommitment {
    pub x: AssignedCell<Fp, Fp>,
    pub y: AssignedCell<Fp, Fp>,
}

fn load_range_table(
    config: &SpendAuthConfig,
    layouter: &mut impl Layouter<Fp>,
) -> Result<(), Error> {
    layouter.assign_table(
        || "10-bit range table",
        |mut table| {
            for value in 0..1024 {
                table.assign_cell(
                    || "range value",
                    config.lookup_table,
                    value,
                    || Value::known(Fp::from(value as u64)),
                )?;
            }
            Ok(())
        },
    )
}

fn bound_generator(
    chip: &AuthEccChip,
    mut layouter: impl Layouter<Fp>,
    point: pallas::Affine,
    name: &'static str,
) -> Result<NonIdentityPoint<pallas::Affine, AuthEccChip>, Error> {
    let witness = NonIdentityPoint::new(
        chip.clone(),
        layouter.namespace(|| format!("{name} witness")),
        Value::known(point),
    )?;
    let constant = Point::new_from_constant(
        chip.clone(),
        layouter.namespace(|| format!("{name} constant")),
        point,
    )?;
    witness.constrain_equal(layouter.namespace(|| format!("bind {name}")), &constant)?;
    Ok(witness)
}

impl SpendAuthCircuit {
    pub fn new(
        authority_key: pallas::Affine,
        randomizer: Fp,
        randomized_key: pallas::Affine,
    ) -> Self {
        Self {
            authority_key: Some(authority_key),
            randomizer: Some(randomizer),
            randomized_key: Some(randomized_key),
        }
    }

    fn unknown() -> Self {
        Self {
            authority_key: None,
            randomizer: None,
            randomized_key: None,
        }
    }
}

impl Circuit<Fp> for SpendAuthCircuit {
    type Config = SpendAuthConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::unknown()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        configure_spend_authority(meta)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        synthesize_spend_authority(self, &config, layouter, true, 0, 1).map(|_| ())
    }
}

pub(crate) fn configure_spend_authority(meta: &mut ConstraintSystem<Fp>) -> SpendAuthConfig {
    let advices: [Column<Advice>; 10] = std::array::from_fn(|_| meta.advice_column());
    let lagrange_coeffs: [Column<Fixed>; 8] = std::array::from_fn(|_| meta.fixed_column());
    let constants = meta.fixed_column();
    meta.enable_constant(constants);
    let lookup_table = meta.lookup_table_column();
    let range_check = PallasLookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
    let ecc = AuthEccChip::configure(meta, advices, lagrange_coeffs, range_check);
    let instance = meta.instance_column();
    meta.enable_equality(instance);
    SpendAuthConfig {
        ecc,
        lookup_table,
        instance,
    }
}

pub(crate) fn synthesize_spend_authority(
    circuit: &SpendAuthCircuit,
    config: &SpendAuthConfig,
    mut layouter: impl Layouter<Fp>,
    load_range_table: bool,
    randomized_x_row: usize,
    randomized_y_row: usize,
) -> Result<AssignedSpendAuthority, Error> {
    if load_range_table {
        self::load_range_table(config, &mut layouter)?;
    }

    let chip = AuthEccChip::construct(config.ecc.clone(), CircuitVersion::AnchoredBase);
    let generator = spend_auth_generator();
    let generator_witness = NonIdentityPoint::new(
        chip.clone(),
        layouter.namespace(|| "SpendAuth generator witness"),
        circuit
            .randomizer
            .map(|_| generator)
            .map_or(Value::unknown(), Value::known),
    )?;
    let generator_constant = Point::new_from_constant(
        chip.clone(),
        layouter.namespace(|| "SpendAuth generator constant"),
        generator,
    )?;
    generator_witness.constrain_equal(
        layouter.namespace(|| "bind SpendAuth generator"),
        &generator_constant,
    )?;

    let randomizer = chip.load_private(
        layouter.namespace(|| "authorization randomizer"),
        config.ecc.advices[0],
        circuit.randomizer.map_or(Value::unknown(), Value::known),
    )?;
    let randomizer = ScalarVar::from_base(
        chip.clone(),
        layouter.namespace(|| "authorization randomizer scalar"),
        &randomizer,
    )?;
    let (randomized_generator, _) = generator_witness.mul(
        layouter.namespace(|| "randomizer times SpendAuth generator"),
        randomizer,
    )?;
    let authority_key = NonIdentityPoint::new(
        chip.clone(),
        layouter.namespace(|| "authority key"),
        circuit.authority_key.map_or(Value::unknown(), Value::known),
    )?;
    let calculated = authority_key.add(
        layouter.namespace(|| "randomized authority key"),
        &randomized_generator,
    )?;
    let expected = NonIdentityPoint::new(
        chip,
        layouter.namespace(|| "public randomized key"),
        circuit
            .randomized_key
            .map_or(Value::unknown(), Value::known),
    )?;
    calculated.constrain_equal(layouter.namespace(|| "bind randomized key"), &expected)?;
    layouter.constrain_instance(
        expected.inner().x().cell(),
        config.instance,
        randomized_x_row,
    )?;
    layouter.constrain_instance(
        expected.inner().y().cell(),
        config.instance,
        randomized_y_row,
    )?;

    Ok(AssignedSpendAuthority {
        x: authority_key.inner().x(),
        y: authority_key.inner().y(),
    })
}

pub(crate) fn synthesize_value_commitment(
    config: &SpendAuthConfig,
    mut layouter: impl Layouter<Fp>,
    value: &AssignedCell<Fp, Fp>,
    randomness: Option<Fp>,
    expected: Option<pallas::Affine>,
    load_table: bool,
    x_row: usize,
    y_row: usize,
) -> Result<AssignedValueCommitment, Error> {
    if load_table {
        load_range_table(config, &mut layouter)?;
    }
    let chip = AuthEccChip::construct(config.ecc.clone(), CircuitVersion::AnchoredBase);
    let value_base = bound_generator(
        &chip,
        layouter.namespace(|| "bind value generator"),
        value_generator(),
        "value generator",
    )?;
    let randomness_base = bound_generator(
        &chip,
        layouter.namespace(|| "bind randomness generator"),
        binding_generator(),
        "randomness generator",
    )?;
    let value_scalar =
        ScalarVar::from_base(chip.clone(), layouter.namespace(|| "value scalar"), value)?;
    let (value_point, _) =
        value_base.mul(layouter.namespace(|| "value times generator"), value_scalar)?;
    let randomness_cell = chip.load_private(
        layouter.namespace(|| "commitment randomness"),
        config.ecc.advices[0],
        randomness.map_or(Value::unknown(), Value::known),
    )?;
    let randomness_scalar = ScalarVar::from_base(
        chip.clone(),
        layouter.namespace(|| "commitment randomness scalar"),
        &randomness_cell,
    )?;
    let (randomness_point, _) = randomness_base.mul(
        layouter.namespace(|| "randomness times generator"),
        randomness_scalar,
    )?;
    let calculated = value_point.add(
        layouter.namespace(|| "value commitment sum"),
        &randomness_point,
    )?;
    let expected = NonIdentityPoint::new(
        chip,
        layouter.namespace(|| "public value commitment"),
        expected.map_or(Value::unknown(), Value::known),
    )?;
    calculated.constrain_equal(layouter.namespace(|| "bind value commitment"), &expected)?;
    layouter.constrain_instance(expected.inner().x().cell(), config.instance, x_row)?;
    layouter.constrain_instance(expected.inner().y().cell(), config.instance, y_row)?;
    Ok(AssignedValueCommitment {
        x: expected.inner().x(),
        y: expected.inner().y(),
    })
}

#[cfg(test)]
mod tests {
    use group::Group;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::arithmetic::CurveAffine;

    use super::*;

    #[test]
    fn randomized_authority_key_is_constrained() {
        let generator = spend_auth_generator();
        let secret = pallas::Scalar::from(17);
        let randomizer = Fp::from(23);
        let randomizer_scalar = pallas::Scalar::from(23);
        let authority_key = (generator * secret).to_affine();
        let randomized_key = (authority_key + generator * randomizer_scalar).to_affine();
        let coordinates = randomized_key.coordinates().unwrap();
        let circuit = SpendAuthCircuit::new(authority_key, randomizer, randomized_key);
        MockProver::run(12, &circuit, vec![vec![*coordinates.x(), *coordinates.y()]])
            .unwrap()
            .assert_satisfied();

        let wrong = randomized_key + pallas::Point::generator();
        let wrong = wrong.to_affine();
        let wrong_coordinates = wrong.coordinates().unwrap();
        assert!(MockProver::run(
            12,
            &circuit,
            vec![vec![*wrong_coordinates.x(), *wrong_coordinates.y()]],
        )
        .unwrap()
        .verify()
        .is_err());
    }
}
