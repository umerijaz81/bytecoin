//! Composition envelope for Onyx transfer circuit components.
//!
//! This proves value conservation and one spend's membership/nullifier statement in a single Halo2
//! proof. It is not yet consensus-complete: O2 still must link the private value to its note
//! commitment, add spend authorization, and scale/aggregate all fixed spend slots.

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use crate::membership_circuit::{MembershipCircuit, MembershipConfig};
use crate::transfer_circuit::{NativeValueCircuit, ValueConfig};

#[derive(Clone)]
pub struct BundleConfig {
    values: ValueConfig,
    membership: MembershipConfig,
}

#[derive(Clone)]
pub struct TransferBundleCircuit<const DEPTH: usize> {
    values: NativeValueCircuit,
    membership: MembershipCircuit<DEPTH>,
}

impl<const DEPTH: usize> TransferBundleCircuit<DEPTH> {
    pub fn new(values: NativeValueCircuit, membership: MembershipCircuit<DEPTH>) -> Self {
        Self { values, membership }
    }
}

impl<const DEPTH: usize> Circuit<Fp> for TransferBundleCircuit<DEPTH> {
    type Config = BundleConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            values: self.values.without_witnesses(),
            membership: self.membership.without_witnesses(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        BundleConfig {
            values: NativeValueCircuit::configure(meta),
            membership: MembershipCircuit::<DEPTH>::configure(meta),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        self.values.synthesize(
            config.values,
            layouter.namespace(|| "native value conservation"),
        )?;
        self.membership.synthesize(
            config.membership,
            layouter.namespace(|| "membership and nullifier"),
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PrimitiveHash, P128Pow5T3};
    use halo2_proofs::pasta::EqAffine;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::poly::commitment::Params;
    use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

    use super::*;

    fn hash2(first: Fp, second: Fp) -> Fp {
        PrimitiveHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([first, second])
    }

    fn node(left: Fp, right: Fp) -> Fp {
        hash2(Fp::from(2), hash2(left, right))
    }

    #[test]
    fn composed_transfer_components_share_one_proof() {
        const DEPTH: usize = 4;
        const K: u32 = 14;
        let commitment = Fp::from(7);
        let siblings = [Fp::from(11), Fp::from(12), Fp::from(13), Fp::from(14)];
        let position = 5u64;
        let mut root = hash2(Fp::from(1), commitment);
        for (level, sibling) in siblings.iter().enumerate() {
            root = if ((position >> level) & 1) == 0 {
                node(root, *sibling)
            } else {
                node(*sibling, root)
            };
        }
        let key = Fp::from(21);
        let rho = Fp::from(22);
        let nullifier = hash2(Fp::from(3), hash2(hash2(key, rho), Fp::from(position)));
        let circuit = TransferBundleCircuit::new(
            NativeValueCircuit::new(&[30], &[25]).unwrap(),
            MembershipCircuit::<DEPTH>::new(commitment, &siblings, position, key, rho).unwrap(),
        );
        let fee = Fp::from(5);
        let params: Params<EqAffine> = Params::new(K);
        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
        create_proof::<EqAffine, Challenge255<EqAffine>, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[&[&[fee], &[root, nullifier, commitment]]],
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
            &[&[&[fee], &[root, nullifier, commitment]]],
            &mut reader,
        )
        .is_ok());

        let mut reader = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&proof[..]);
        assert!(verify_proof::<EqAffine, Challenge255<EqAffine>, _, _>(
            &params,
            &vk,
            SingleVerifier::new(&params),
            &[&[&[Fp::from(4)], &[root, nullifier, commitment]]],
            &mut reader,
        )
        .is_err());
    }
}
