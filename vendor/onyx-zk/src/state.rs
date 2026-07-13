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
use crate::types::{write_varint, DecodeError, Reader};

pub const ONYX_MERKLE_DEPTH: usize = 32;
const SNAPSHOT_VERSION: u8 = 1;
const MAX_SNAPSHOT_NULLIFIERS: usize = 1_000_000;
const MAX_SNAPSHOT_ANCHORS: usize = 1_000_000;

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
    HeightRegression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    Decode(DecodeError),
    WrongVersion,
    WrongDepth,
    InvalidLeafCount,
    InvalidFrontier,
    InvalidFullRoot,
    TooManyNullifiers,
    TooManyAnchors,
    DuplicateNullifier,
    InvalidAnchorHistory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessError {
    TreeFull,
    PositionMissing,
    WrongPathLength,
}

impl From<DecodeError> for SnapshotError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
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
    anchors: Vec<Anchor>,
    anchor_window_blocks: u64,
    current_height: u64,
}

#[derive(Clone, Copy)]
struct Anchor {
    root: CanonicalField,
    height: u64,
}

pub struct ShieldedStateDelta<const DEPTH: usize> {
    previous_tree: IncrementalMerkleTree<DEPTH>,
    nullifiers: NullifierDelta,
    previous_anchors: Vec<Anchor>,
    previous_height: u64,
}

impl<const DEPTH: usize> ShieldedState<DEPTH> {
    pub fn new(anchor_window_blocks: u64) -> Self {
        assert!(anchor_window_blocks > 0, "anchor window must be nonzero");
        let tree = IncrementalMerkleTree::default();
        Self {
            anchors: vec![Anchor {
                root: tree.root(),
                height: 0,
            }],
            tree,
            nullifiers: NullifierSet::default(),
            anchor_window_blocks,
            current_height: 0,
        }
    }

    pub fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn knows_anchor(&self, anchor: CanonicalField) -> bool {
        self.anchors.iter().any(|entry| entry.root == anchor)
    }

    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.nullifiers.contains(nullifier)
    }

    pub fn apply_transaction(
        &mut self,
        transaction: &TransactionPreimage,
        block_height: u64,
    ) -> Result<ShieldedStateDelta<DEPTH>, StateError> {
        // Encoding performs all structural and resource-limit validation before state work.
        transaction
            .encode()
            .map_err(|_| StateError::InvalidTransaction)?;
        if !self.knows_anchor(transaction.anchor) {
            return Err(StateError::UnknownAnchor);
        }
        if block_height < self.current_height {
            return Err(StateError::HeightRegression);
        }

        let previous_tree = self.tree.clone();
        let previous_anchors = self.anchors.clone();
        let previous_height = self.current_height;
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
        self.current_height = block_height;
        if self.anchors.last().map(|entry| entry.root) != Some(root) {
            self.anchors.push(Anchor {
                root,
                height: block_height,
            });
        }
        let oldest_height = block_height.saturating_sub(self.anchor_window_blocks - 1);
        self.anchors.retain(|entry| entry.height >= oldest_height);
        Ok(ShieldedStateDelta {
            previous_tree,
            nullifiers,
            previous_anchors,
            previous_height,
        })
    }

    pub fn rollback(&mut self, delta: ShieldedStateDelta<DEPTH>) {
        self.tree = delta.previous_tree;
        self.nullifiers.rollback(delta.nullifiers);
        self.anchors = delta.previous_anchors;
        self.current_height = delta.previous_height;
    }

    pub fn encode_snapshot(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SNAPSHOT_VERSION);
        out.push(DEPTH as u8);
        write_varint(self.tree.leaf_count, &mut out);
        let frontier_bitmap = self
            .tree
            .frontier
            .iter()
            .enumerate()
            .fold(0u64, |bits, (level, value)| {
                bits | (u64::from(value.is_some()) << level)
            });
        write_varint(frontier_bitmap, &mut out);
        for value in self.tree.frontier.iter().flatten() {
            out.extend_from_slice(&value.to_repr());
        }
        match self.tree.full_root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root.to_repr());
            }
            None => out.push(0),
        }

        write_varint(self.current_height, &mut out);
        write_varint(self.anchor_window_blocks, &mut out);
        write_varint(self.anchors.len() as u64, &mut out);
        for anchor in &self.anchors {
            out.extend_from_slice(&anchor.root.bytes());
            write_varint(anchor.height, &mut out);
        }

        let mut nullifiers: Vec<_> = self.nullifiers.values.iter().copied().collect();
        nullifiers.sort_unstable_by_key(|nullifier| nullifier.0);
        write_varint(nullifiers.len() as u64, &mut out);
        for nullifier in nullifiers {
            out.extend_from_slice(&nullifier.0);
        }
        out
    }

    pub fn decode_snapshot(input: &[u8]) -> Result<Self, SnapshotError> {
        if DEPTH == 0 || DEPTH >= 64 {
            return Err(SnapshotError::WrongDepth);
        }
        let mut reader = Reader::new(input);
        if reader.byte()? != SNAPSHOT_VERSION {
            return Err(SnapshotError::WrongVersion);
        }
        if usize::from(reader.byte()?) != DEPTH {
            return Err(SnapshotError::WrongDepth);
        }
        let leaf_count = reader.varint()?;
        let capacity = 1u64 << DEPTH;
        if leaf_count > capacity {
            return Err(SnapshotError::InvalidLeafCount);
        }
        let frontier_bitmap = reader.varint()?;
        let expected_bitmap = if leaf_count == capacity {
            0
        } else {
            leaf_count
        };
        if frontier_bitmap != expected_bitmap {
            return Err(SnapshotError::InvalidFrontier);
        }

        let mut tree = IncrementalMerkleTree::<DEPTH>::default();
        tree.leaf_count = leaf_count;
        for level in 0..DEPTH {
            if ((frontier_bitmap >> level) & 1) == 1 {
                tree.frontier[level] = Some(reader.field()?.field());
            }
        }
        match reader.byte()? {
            0 if leaf_count != capacity => {}
            1 if leaf_count == capacity => tree.full_root = Some(reader.field()?.field()),
            _ => return Err(SnapshotError::InvalidFullRoot),
        }

        let current_height = reader.varint()?;
        let anchor_window_blocks = reader.varint()?;
        if anchor_window_blocks == 0 {
            return Err(SnapshotError::InvalidAnchorHistory);
        }
        let anchor_count = bounded_snapshot_count(
            reader.varint()?,
            MAX_SNAPSHOT_ANCHORS,
            SnapshotError::TooManyAnchors,
        )?;
        if anchor_count == 0 {
            return Err(SnapshotError::InvalidAnchorHistory);
        }
        let mut anchors = Vec::with_capacity(anchor_count);
        let mut previous_height = 0;
        for index in 0..anchor_count {
            let root = reader.field()?;
            let height = reader.varint()?;
            if height > current_height || (index != 0 && height < previous_height) {
                return Err(SnapshotError::InvalidAnchorHistory);
            }
            previous_height = height;
            anchors.push(Anchor { root, height });
        }
        if anchors.last().map(|anchor| anchor.root) != Some(tree.root()) {
            return Err(SnapshotError::InvalidAnchorHistory);
        }
        let oldest_height = current_height.saturating_sub(anchor_window_blocks - 1);
        if anchors.iter().any(|anchor| anchor.height < oldest_height) {
            return Err(SnapshotError::InvalidAnchorHistory);
        }

        let nullifier_count = bounded_snapshot_count(
            reader.varint()?,
            MAX_SNAPSHOT_NULLIFIERS,
            SnapshotError::TooManyNullifiers,
        )?;
        let mut values = HashSet::with_capacity(nullifier_count);
        let mut previous: Option<[u8; 32]> = None;
        for _ in 0..nullifier_count {
            let bytes = reader.array()?;
            if previous.is_some_and(|value| value >= bytes) {
                return Err(SnapshotError::DuplicateNullifier);
            }
            previous = Some(bytes);
            values.insert(Nullifier(bytes));
        }
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        Ok(Self {
            tree,
            nullifiers: NullifierSet { values },
            anchors,
            anchor_window_blocks,
            current_height,
        })
    }
}

fn bounded_snapshot_count(
    count: u64,
    limit: usize,
    error: SnapshotError,
) -> Result<usize, SnapshotError> {
    if count > limit as u64 {
        Err(error)
    } else {
        Ok(count as usize)
    }
}

#[derive(Clone)]
pub struct WitnessTree<const DEPTH: usize = ONYX_MERKLE_DEPTH> {
    leaves: Vec<CanonicalField>,
    empty: Vec<Fp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerklePath {
    pub position: u64,
    pub siblings: Vec<CanonicalField>,
}

impl<const DEPTH: usize> Default for WitnessTree<DEPTH> {
    fn default() -> Self {
        let tree = IncrementalMerkleTree::<DEPTH>::default();
        Self {
            leaves: Vec::new(),
            empty: tree.empty,
        }
    }
}

impl<const DEPTH: usize> WitnessTree<DEPTH> {
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn commitments(&self) -> &[CanonicalField] {
        &self.leaves
    }

    pub fn append(&mut self, commitment: CanonicalField) -> Result<u64, WitnessError> {
        if self.leaves.len() as u64 == (1u64 << DEPTH) {
            return Err(WitnessError::TreeFull);
        }
        let position = self.leaves.len() as u64;
        self.leaves.push(commitment);
        Ok(position)
    }

    pub fn root(&self) -> CanonicalField {
        if self.leaves.is_empty() {
            return CanonicalField::from_field(self.empty[DEPTH]);
        }
        let mut layer: Vec<Fp> = self
            .leaves
            .iter()
            .map(|commitment| hash_leaf(commitment.field()))
            .collect();
        for level in 0..DEPTH {
            layer = parent_layer(&layer, self.empty[level]);
        }
        CanonicalField::from_field(layer[0])
    }

    pub fn witness(&self, position: u64) -> Result<MerklePath, WitnessError> {
        if position >= self.leaves.len() as u64 {
            return Err(WitnessError::PositionMissing);
        }
        let mut index = position as usize;
        let mut layer: Vec<Fp> = self
            .leaves
            .iter()
            .map(|commitment| hash_leaf(commitment.field()))
            .collect();
        let mut siblings = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let sibling_index = index ^ 1;
            siblings.push(CanonicalField::from_field(
                layer
                    .get(sibling_index)
                    .copied()
                    .unwrap_or(self.empty[level]),
            ));
            layer = parent_layer(&layer, self.empty[level]);
            index >>= 1;
        }
        Ok(MerklePath { position, siblings })
    }
}

impl MerklePath {
    pub fn verify<const DEPTH: usize>(
        &self,
        commitment: CanonicalField,
        expected_root: CanonicalField,
    ) -> Result<bool, WitnessError> {
        if self.siblings.len() != DEPTH {
            return Err(WitnessError::WrongPathLength);
        }
        if DEPTH >= 64 || self.position >= (1u64 << DEPTH) {
            return Err(WitnessError::PositionMissing);
        }
        let mut node = hash_leaf(commitment.field());
        for (level, sibling) in self.siblings.iter().enumerate() {
            node = if ((self.position >> level) & 1) == 0 {
                hash_node(node, sibling.field())
            } else {
                hash_node(sibling.field(), node)
            };
        }
        Ok(CanonicalField::from_field(node) == expected_root)
    }
}

fn parent_layer(layer: &[Fp], empty: Fp) -> Vec<Fp> {
    layer
        .chunks(2)
        .map(|pair| hash_node(pair[0], pair.get(1).copied().unwrap_or(empty)))
        .collect()
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
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    Fp::from(2),
                ),
                randomized_key: [20; 32],
            }],
            outputs: vec![PublicOutput {
                commitment: field(commitment),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    Fp::from(3),
                ),
                ephemeral_key: [21; 32],
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
        let delta = state.apply_transaction(&tx, 1).unwrap();
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
            state.apply_transaction(&transaction(unknown, 1, 30), 1),
            Err(StateError::UnknownAnchor)
        ));

        let first = transaction(state.root(), 1, 30);
        state.apply_transaction(&first, 1).unwrap();
        let root_before = state.root();
        assert!(matches!(
            state.apply_transaction(&transaction(root_before, 1, 31), 1),
            Err(StateError::DuplicateNullifier)
        ));
        assert_eq!(state.root(), root_before);
        assert_eq!(state.leaf_count(), 1);
    }

    #[test]
    fn anchor_window_is_measured_in_blocks_not_transactions() {
        let mut state = ShieldedState::<8>::new(2);
        let genesis = state.root();
        let first = transaction(genesis, 1, 30);
        state.apply_transaction(&first, 1).unwrap();
        let first_root = state.root();
        let second = transaction(first_root, 2, 31);
        state.apply_transaction(&second, 1).unwrap();
        assert!(state.knows_anchor(first_root));

        let third = transaction(state.root(), 3, 32);
        state.apply_transaction(&third, 2).unwrap();
        assert!(state.knows_anchor(first_root));

        let fourth = transaction(state.root(), 4, 33);
        state.apply_transaction(&fourth, 3).unwrap();
        assert!(!state.knows_anchor(first_root));
        assert!(matches!(
            state.apply_transaction(&transaction(state.root(), 5, 34), 2),
            Err(StateError::HeightRegression)
        ));
    }

    #[test]
    fn snapshot_round_trip_is_deterministic() {
        let mut state = ShieldedState::<8>::new(3);
        state
            .apply_transaction(&transaction(state.root(), 2, 40), 1)
            .unwrap();
        state
            .apply_transaction(&transaction(state.root(), 1, 41), 2)
            .unwrap();
        let encoded = state.encode_snapshot();
        let restored = ShieldedState::<8>::decode_snapshot(&encoded).unwrap();
        assert_eq!(restored.encode_snapshot(), encoded);
        assert_eq!(restored.root(), state.root());
        assert!(restored.is_spent(&Nullifier([1; 32])));
        assert!(restored.is_spent(&Nullifier([2; 32])));
    }

    #[test]
    fn snapshot_rejects_corruption_and_wrong_depth() {
        let state = ShieldedState::<8>::new(3);
        let encoded = state.encode_snapshot();
        assert_eq!(
            ShieldedState::<7>::decode_snapshot(&encoded).err(),
            Some(SnapshotError::WrongDepth)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            ShieldedState::<8>::decode_snapshot(&trailing).err(),
            Some(SnapshotError::Decode(DecodeError::TrailingData))
        );
        let mut bad_version = encoded;
        bad_version[0] += 1;
        assert_eq!(
            ShieldedState::<8>::decode_snapshot(&bad_version).err(),
            Some(SnapshotError::WrongVersion)
        );
    }

    #[test]
    fn wallet_witnesses_match_consensus_root() {
        let mut consensus = IncrementalMerkleTree::<4>::default();
        let mut wallet = WitnessTree::<4>::default();
        for value in 1..=5 {
            consensus.append(field(value)).unwrap();
            wallet.append(field(value)).unwrap();
        }
        let root = consensus.root();
        assert_eq!(wallet.root(), root);
        for position in 0..5 {
            let path = wallet.witness(position).unwrap();
            assert_eq!(path.verify::<4>(field(position + 1), root), Ok(true));
            assert_eq!(path.verify::<4>(field(position + 2), root), Ok(false));
        }
        assert_eq!(wallet.witness(5), Err(WitnessError::PositionMissing));
    }
}
