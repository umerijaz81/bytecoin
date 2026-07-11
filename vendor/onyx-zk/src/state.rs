//! Onyx O1 shielded-state primitives.
//!
//! These types are deterministic state machinery, not a proof circuit. Consensus integration is
//! deferred until their encodings, vectors, persistence, and rollback behavior are independently
//! reviewed.

use std::collections::HashSet;

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_proofs::pasta::Fp;

pub const ONYX_MERKLE_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalField([u8; 32]);

impl CanonicalField {
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::<Fp>::from(Fp::from_repr(bytes)).map(|_| Self(bytes))
    }

    pub fn from_field(value: Fp) -> Self {
        Self(value.to_repr())
    }

    pub fn bytes(self) -> [u8; 32] {
        self.0
    }

    fn field(self) -> Fp {
        // Construction proves canonicality.
        Option::<Fp>::from(Fp::from_repr(self.0)).expect("CanonicalField invariant")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Nullifier(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateError {
    TreeFull,
    DuplicateNullifier,
}

// Numeric tags are the frozen field encodings of the protocol's leaf/node domain separation.
const LEAF_TAG: u64 = 1;
const NODE_TAG: u64 = 2;

fn poseidon2(a: Fp, b: Fp) -> Fp {
    PoseidonHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

fn hash_leaf(value: Fp) -> Fp {
    poseidon2(Fp::from(LEAF_TAG), value)
}

fn hash_node(left: Fp, right: Fp) -> Fp {
    poseidon2(Fp::from(NODE_TAG), poseidon2(left, right))
}

#[derive(Clone)]
pub struct IncrementalMerkleTree<const DEPTH: usize = ONYX_MERKLE_DEPTH> {
    leaf_count: u64,
    frontier: [Option<Fp>; DEPTH],
    empty: Vec<Fp>,
    full_root: Option<Fp>,
}

impl<const DEPTH: usize> Default for IncrementalMerkleTree<DEPTH> {
    fn default() -> Self {
        assert!(DEPTH > 0 && DEPTH < 64, "Merkle depth must be in 1..64");
        let mut empty = Vec::with_capacity(DEPTH + 1);
        empty.push(hash_leaf(Fp::zero()));
        for level in 0..DEPTH {
            empty.push(hash_node(empty[level], empty[level]));
        }
        Self {
            leaf_count: 0,
            frontier: [None; DEPTH],
            empty,
            full_root: None,
        }
    }
}

impl<const DEPTH: usize> IncrementalMerkleTree<DEPTH> {
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn root(&self) -> CanonicalField {
        if let Some(root) = self.full_root {
            return CanonicalField::from_field(root);
        }
        let mut node = self.empty[0];
        for level in 0..DEPTH {
            node = if ((self.leaf_count >> level) & 1) == 1 {
                hash_node(self.frontier[level].expect("frontier invariant"), node)
            } else {
                hash_node(node, self.empty[level])
            };
        }
        CanonicalField::from_field(node)
    }

    pub fn append(&mut self, commitment: CanonicalField) -> Result<u64, StateError> {
        if self.leaf_count == (1u64 << DEPTH) {
            return Err(StateError::TreeFull);
        }

        let position = self.leaf_count;
        let mut index = position;
        let mut node = hash_leaf(commitment.field());
        for level in 0..DEPTH {
            if (index & 1) == 0 {
                self.frontier[level] = Some(node);
                self.leaf_count += 1;
                return Ok(position);
            }
            node = hash_node(
                self.frontier[level].take().expect("frontier invariant"),
                node,
            );
            index >>= 1;
        }
        // The last available leaf merges through every frontier level and directly produces the
        // root of a completely full tree.
        self.full_root = Some(node);
        self.leaf_count += 1;
        Ok(position)
    }
}

#[derive(Clone, Default)]
pub struct NullifierSet {
    values: HashSet<Nullifier>,
}

impl NullifierSet {
    pub fn contains(&self, nullifier: &Nullifier) -> bool {
        self.values.contains(nullifier)
    }

    pub fn apply<'a>(
        &mut self,
        nullifiers: impl IntoIterator<Item = &'a Nullifier>,
    ) -> Result<NullifierDelta, StateError> {
        let mut staged = HashSet::new();
        for nullifier in nullifiers {
            if self.values.contains(nullifier) || !staged.insert(*nullifier) {
                return Err(StateError::DuplicateNullifier);
            }
        }
        for nullifier in &staged {
            self.values.insert(*nullifier);
        }
        Ok(NullifierDelta {
            inserted: staged.into_iter().collect(),
        })
    }

    pub fn rollback(&mut self, delta: NullifierDelta) {
        for nullifier in delta.inserted {
            assert!(
                self.values.remove(&nullifier),
                "nullifier rollback invariant"
            );
        }
    }
}

pub struct NullifierDelta {
    inserted: Vec<Nullifier>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u64) -> CanonicalField {
        CanonicalField::from_field(Fp::from(value))
    }

    #[test]
    fn canonical_field_rejects_modulus() {
        assert!(CanonicalField::from_bytes([0xff; 32]).is_none());
        assert!(CanonicalField::from_bytes(Fp::from(7).to_repr()).is_some());
    }

    #[test]
    fn incremental_roots_are_deterministic_and_rollback_by_snapshot() {
        let mut tree = IncrementalMerkleTree::<4>::default();
        let empty = tree.root();
        let snapshot = tree.clone();
        assert_eq!(tree.append(field(7)), Ok(0));
        let one = tree.root();
        assert_ne!(empty, one);
        assert_eq!(tree.append(field(8)), Ok(1));
        assert_ne!(one, tree.root());
        tree = snapshot;
        assert_eq!(tree.root(), empty);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn tree_rejects_overflow() {
        let mut tree = IncrementalMerkleTree::<2>::default();
        for value in 0..4 {
            assert_eq!(tree.append(field(value)), Ok(value));
        }
        assert_eq!(tree.append(field(5)), Err(StateError::TreeFull));
    }

    #[test]
    fn nullifier_batch_is_atomic_and_reversible() {
        let mut set = NullifierSet::default();
        let a = Nullifier([1; 32]);
        let b = Nullifier([2; 32]);
        let delta = set.apply([&a, &b]).unwrap();
        assert!(set.contains(&a));
        assert!(matches!(
            set.apply([&b]),
            Err(StateError::DuplicateNullifier)
        ));
        let c = Nullifier([3; 32]);
        assert!(matches!(
            set.apply([&c, &c]),
            Err(StateError::DuplicateNullifier)
        ));
        assert!(!set.contains(&c));
        set.rollback(delta);
        assert!(!set.contains(&a));
        assert!(!set.contains(&b));
    }
}
