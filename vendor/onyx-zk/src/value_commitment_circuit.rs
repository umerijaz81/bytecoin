//! Value-commitment circuit component: `cv = [value]V + [rcv]R`.

use ff::PrimeField;
use group::{Curve, GroupEncoding};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};
use pasta_curves::pallas;

use crate::spend_auth_circuit::{
    binding_generator, configure_spend_authority, synthesize_value_commitment, value_generator,
    SpendAuthConfig,
};

pub fn value_commitment_bytes(value: u64, randomness: Fp) -> [u8; 32] {
    let randomness =
        Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(randomness.to_repr()))
            .expect("every Pallas base element is canonical in its scalar field");
    (value_generator() * pallas::Scalar::from(value) + binding_generator() * randomness)
        .to_affine()
        .to_bytes()
}

#[derive(Clone)]
pub struct ValueCommitmentConfig {
    value: Column<Advice>,
    ecc: SpendAuthConfig,
}

#[derive(Clone)]
pub struct ValueCommitmentCircuit {
    value: Option<u64>,
    randomness: Option<Fp>,
    commitment: Option<pallas::Affine>,
}

impl ValueCommitmentCircuit {
    pub fn new(value: u64, randomness: Fp, commitment: pallas::Affine) -> Self {
        Self {
            value: Some(value),
            randomness: Some(randomness),
            commitment: Some(commitment),
        }
    }
}

impl Circuit<Fp> for ValueCommitmentCircuit {
    type Config = ValueCommitmentConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            value: None,
            randomness: None,
            commitment: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let value = meta.advice_column();
        meta.enable_equality(value);
        Self::Config {
            value,
            ecc: configure_spend_authority(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let value = layouter.assign_region(
            || "value",
            |mut region| {
                region.assign_advice(
                    || "value",
                    config.value,
                    0,
                    || {
                        self.value
                            .map(Fp::from)
                            .map_or(Value::unknown(), Value::known)
                    },
                )
            },
        )?;
        synthesize_value_commitment(
            &config.ecc,
            layouter.namespace(|| "value commitment"),
            &value,
            self.randomness,
            self.commitment,
            true,
            0,
            1,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use group::Curve;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::arithmetic::CurveAffine;

    use crate::spend_auth_circuit::{binding_generator, value_generator};

    use super::*;

    #[test]
    fn value_and_randomness_are_bound_to_public_commitment() {
        let value = 42;
        let randomness = Fp::from(17);
        let commitment = (value_generator() * pallas::Scalar::from(value)
            + binding_generator() * pallas::Scalar::from(17))
        .to_affine();
        let coordinates = commitment.coordinates().unwrap();
        let circuit = ValueCommitmentCircuit::new(value, randomness, commitment);
        let public = vec![vec![*coordinates.x(), *coordinates.y()]];
        MockProver::run(13, &circuit, public.clone())
            .unwrap()
            .assert_satisfied();
        let mut wrong = public;
        wrong[0][0] += Fp::one();
        assert!(MockProver::run(13, &circuit, wrong)
            .unwrap()
            .verify()
            .is_err());
    }
}
