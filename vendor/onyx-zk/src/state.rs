//! Onyx O1 shielded-state primitives.
//!
//! These types are deterministic state machinery, not a proof circuit. Consensus integration is
//! deferred until their encodings, vectors, persistence, and rollback behavior are independently
//! reviewed.

use std::collections::HashSet;

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_proofs::pasta::Fp;

use crate::transaction::TransactionPreimage;

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

    pub(crate) fn field(self) -> Fp {
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
    UnknownAnchor,
    InvalidTransaction,
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

#[derive(Clone)]
pub struct ShieldedState<const DEPTH: usize = ONYX_MERKLE_DEPTH> {
    tree: IncrementalMerkleTree<DEPTH>,
    nullifiers: NullifierSet,
    anchors: Vec<CanonicalField>,
    max_anchors: usize,
}

pub struct ShieldedStateDelta<const DEPTH: usize> {
    previous_tree: IncrementalMerkleTree<DEPTH>,
    nullifiers: NullifierDelta,
    previous_anchors: Vec<CanonicalField>,
}

impl<const DEPTH: usize> ShieldedState<DEPTH> {
    pub fn new(max_anchors: usize) -> Self {
        assert!(max_anchors > 0, "at least one anchor must be retained");
        let tree = IncrementalMerkleTree::default();
        Self {
            anchors: vec![tree.root()],
            tree,
            nullifiers: NullifierSet::default(),
            max_anchors,
        }
    }

    pub fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn knows_anchor(&self, anchor: CanonicalField) -> bool {
        self.anchors.contains(&anchor)
    }

    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn apply_transaction(
        &mut self,
        transaction: &TransactionPreimage,
    ) -> Result<ShieldedStateDelta<DEPTH>, StateError> {
        // Encoding performs all structural and resource-limit validation before state work.
        transaction
            .encode()
            .map_err(|_| StateError::InvalidTransaction)?;
        if !self.knows_anchor(transaction.anchor) {
            return Err(StateError::UnknownAnchor);
        }

        let previous_tree = self.tree.clone();
        let previous_anchors = self.anchors.clone();
        let nullifier_values: Vec<_> = transaction
            .spends
            .iter()
            .map(|spend| &spend.nullifier)
            .collect();
        let nullifiers = self.nullifiers.apply(nullifier_values)?;

        for output in &transaction.outputs {
            if let Err(error) = self.tree.append(output.commitment) {
                self.tree = previous_tree;
                self.nullifiers.rollback(nullifiers);
                return Err(error);
            }
        }

        let root = self.tree.root();
        if self.anchors.last() != Some(&root) {
            self.anchors.push(root);
            if self.anchors.len() > self.max_anchors {
                self.anchors.remove(0);
            }
        }
        Ok(ShieldedStateDelta {
            previous_tree,
            nullifiers,
            previous_anchors,
        })
    }

    pub fn rollback(&mut self, delta: ShieldedStateDelta<DEPTH>) {
        self.tree = delta.previous_tree;
        self.nullifiers.rollback(delta.nullifiers);
        self.anchors = delta.previous_anchors;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{PublicOutput, PublicSpend, TransactionPreimage};
    use crate::types::NETWORK_ID_BYTES;

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
        assert_eq!(
            hex(&empty.bytes()),
            "97af549e78f1c639c7c98cc6bf841df536c5678a9730c786add771a45bf4f028"
        );
        assert_eq!(
            hex(&one.bytes()),
            "a116a31f82e58dfaf0332ad57847c747ddda9eb339b2f1e5bfcbcf63dbaeda22"
        );
        assert_ne!(empty, one);
        assert_eq!(tree.append(field(8)), Ok(1));
        assert_ne!(one, tree.root());
        tree = snapshot;
        assert_eq!(tree.root(), empty);
        assert_eq!(tree.leaf_count(), 0);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

    fn transaction(anchor: CanonicalField, nullifier: u8, commitment: u64) -> TransactionPreimage {
        TransactionPreimage {
            network_id: [1; NETWORK_ID_BYTES],
            anchor,
            expiry_height: 10,
            fee: 1,
            spends: vec![PublicSpend {
                nullifier: Nullifier([nullifier; 32]),
                randomized_key: field(20),
            }],
            outputs: vec![PublicOutput {
                commitment: field(commitment),
                ephemeral_key: field(21),
                ciphertext: vec![1, 2, 3],
                outgoing_ciphertext: vec![4, 5],
            }],
            programs: vec![],
        }
    }

    #[test]
    fn shielded_state_applies_and_rolls_back_atomically() {
        let mut state = ShieldedState::<4>::new(3);
        let initial = state.root();
        let tx = transaction(initial, 1, 30);
        let delta = state.apply_transaction(&tx).unwrap();
        assert_ne!(state.root(), initial);
        assert_eq!(state.leaf_count(), 1);
        assert!(state.is_spent(&Nullifier([1; 32])));
        state.rollback(delta);
        assert_eq!(state.root(), initial);
        assert_eq!(state.leaf_count(), 0);
        assert!(!state.is_spent(&Nullifier([1; 32])));
    }

    #[test]
    fn shielded_state_rejects_stale_or_duplicate_spends() {
        let mut state = ShieldedState::<4>::new(2);
        let unknown = field(999);
        assert!(matches!(
            state.apply_transaction(&transaction(unknown, 1, 30)),
            Err(StateError::UnknownAnchor)
        ));

        let first = transaction(state.root(), 1, 30);
        state.apply_transaction(&first).unwrap();
        let root_before = state.root();
        assert!(matches!(
            state.apply_transaction(&transaction(root_before, 1, 31)),
            Err(StateError::DuplicateNullifier)
        ));
        assert_eq!(state.root(), root_before);
        assert_eq!(state.leaf_count(), 1);
    }
}
