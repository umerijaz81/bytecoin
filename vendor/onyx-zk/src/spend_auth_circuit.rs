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
use pasta_curves::pallas;

pub const SPEND_AUTH_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
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
        synthesize_spend_authority(self, &config, layouter).map(|_| ())
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
) -> Result<AssignedSpendAuthority, Error> {
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
    )?;

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
    layouter.constrain_instance(expected.inner().x().cell(), config.instance, 0)?;
    layouter.constrain_instance(expected.inner().y().cell(), config.instance, 1)?;

    Ok(AssignedSpendAuthority {
        x: authority_key.inner().x(),
        y: authority_key.inner().y(),
    })
}

#[cfg(test)]
mod tests {
    use group::Group;
    use halo2_proofs::dev::MockProver;

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
