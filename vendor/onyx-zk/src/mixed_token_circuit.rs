//! Atomic private-token transfer plus native-fee circuit composition.
//!
//! The token and native lanes share one proof but retain independent value-balance and note-domain
//! constraints. Canonical transaction ordering is token spends followed by native spends, then token
//! outputs followed by one native change output.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use crate::multi_transfer_circuit::{MultiTransferCircuit, MultiTransferConfig};

#[derive(Clone)]
pub struct MixedTokenConfig {
    token: MultiTransferConfig,
    native: MultiTransferConfig,
}

#[derive(Clone)]
pub struct MixedTokenCircuit<
    const DEPTH: usize,
    const TOKEN_SPENDS: usize,
    const TOKEN_OUTPUTS: usize,
    const NATIVE_SPENDS: usize,
> {
    token: MultiTransferCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS>,
    native: MultiTransferCircuit<DEPTH, NATIVE_SPENDS, 1>,
}

impl<
        const DEPTH: usize,
        const TOKEN_SPENDS: usize,
        const TOKEN_OUTPUTS: usize,
        const NATIVE_SPENDS: usize,
    > MixedTokenCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>
{
    pub fn new(
        token: MultiTransferCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS>,
        native: MultiTransferCircuit<DEPTH, NATIVE_SPENDS, 1>,
    ) -> Result<Self, &'static str> {
        if !(1..=2).contains(&TOKEN_SPENDS)
            || !(1..=2).contains(&TOKEN_OUTPUTS)
            || !(1..=2).contains(&NATIVE_SPENDS)
        {
            return Err("mixed token circuit shape is unsupported");
        }
        Ok(Self { token, native })
    }
}

impl<
        const DEPTH: usize,
        const TOKEN_SPENDS: usize,
        const TOKEN_OUTPUTS: usize,
        const NATIVE_SPENDS: usize,
    > Circuit<Fp> for MixedTokenCircuit<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS, NATIVE_SPENDS>
{
    type Config = MixedTokenConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            token: self.token.without_witnesses(),
            native: self.native.without_witnesses(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::Config {
            token: MultiTransferCircuit::<DEPTH, TOKEN_SPENDS, TOKEN_OUTPUTS>::configure(meta),
            native: MultiTransferCircuit::<DEPTH, NATIVE_SPENDS, 1>::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        self.token
            .synthesize(config.token, layouter.namespace(|| "private token lane"))?;
        self.native
            .synthesize(config.native, layouter.namespace(|| "native fee lane"))
    }
}
