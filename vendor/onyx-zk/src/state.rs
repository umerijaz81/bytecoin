//! Onyx O1 shielded-state primitives.
//!
//! These types are deterministic state machinery, not a proof circuit. Consensus integration is
//! deferred until their encodings, vectors, persistence, and rollback behavior are independently
//! reviewed.

use std::collections::{BTreeMap, HashSet};

use ff::PrimeField;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

use crate::program::{ProgramDelta, ProgramEntry, ProgramRegistry};
use crate::program_context::ProgramContext;
use crate::standard_programs::{kind_for_schema, StandardApplication};
use crate::token_program::{
    issuance_function_id, issuance_policy_from_entry, issuance_public_data_hash,
};
use crate::transaction::TransactionPreimage;
use crate::types::{write_varint, DecodeError, Reader};

pub const ONYX_MERKLE_DEPTH: usize = 32;
const SNAPSHOT_VERSION: u8 = 7;
const PRE_BRIDGE_REPLAY_SNAPSHOT_VERSION: u8 = 6;
const ISSUANCE_SNAPSHOT_VERSION: u8 = 5;
const PROGRAM_COST_SNAPSHOT_VERSION: u8 = 4;
const PROGRAM_REGISTRY_SNAPSHOT_VERSION: u8 = 3;
const ACCOUNTING_SNAPSHOT_VERSION: u8 = 2;
const LEGACY_SNAPSHOT_VERSION: u8 = 1;
const MAX_TRANSACTION_PROGRAM_COST: u64 = 10_000_000;
const MAX_BLOCK_PROGRAM_COST: u64 = 20_000_000;
const MAX_SNAPSHOT_NULLIFIERS: usize = 1_000_000;
const MAX_SNAPSHOT_ANCHORS: usize = 1_000_000;
const MAX_SNAPSHOT_PROGRAM_STATES: usize = 1_000_000;
const BRIDGE_REPLAY_DOMAIN: &[u8] = b"bytecoin.onyx.v6.bridge-replay";

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
    SupplyOverflow,
    SupplyUnderflow,
    InvalidProgram,
    InvalidProgramContext,
    ProgramCostLimit,
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
    InvalidSupply,
    InvalidRegistry,
    InvalidProgramCost,
    InvalidIssuanceLedger,
    InvalidProgramState,
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
    total_bridged: u64,
    total_fees: u64,
    circulating_supply: u64,
    programs: ProgramRegistry,
    current_block_program_cost: u64,
    issuance: BTreeMap<[u8; 32], TokenIssuanceState>,
    program_states: BTreeMap<[u8; 32], CanonicalField>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TokenIssuanceState {
    issued_supply: u64,
    next_sequence: u64,
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
    previous_total_bridged: u64,
    previous_total_fees: u64,
    previous_circulating_supply: u64,
    previous_block_program_cost: u64,
    previous_program_states: BTreeMap<[u8; 32], CanonicalField>,
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
            total_bridged: 0,
            total_fees: 0,
            circulating_supply: 0,
            programs: ProgramRegistry::default(),
            current_block_program_cost: 0,
            issuance: BTreeMap::new(),
            program_states: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    pub fn leaf_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn total_bridged(&self) -> u64 {
        self.total_bridged
    }

    pub fn total_fees(&self) -> u64 {
        self.total_fees
    }

    pub fn circulating_supply(&self) -> u64 {
        self.circulating_supply
    }

    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    pub fn program_registry(&self) -> &ProgramRegistry {
        &self.programs
    }

    pub fn current_block_program_cost(&self) -> u64 {
        self.current_block_program_cost
    }

    pub fn token_issued_supply(&self, program_id: &[u8; 32]) -> u64 {
        self.issuance
            .get(program_id)
            .map(|state| state.issued_supply)
            .unwrap_or(0)
    }

    pub fn token_next_issuance_sequence(&self, program_id: &[u8; 32]) -> u64 {
        self.issuance
            .get(program_id)
            .map(|state| state.next_sequence)
            .unwrap_or(0)
    }

    pub fn register_program(&mut self, entry: ProgramEntry) -> Result<ProgramDelta, StateError> {
        self.programs
            .register(entry)
            .map_err(|_| StateError::InvalidProgram)
    }

    pub fn rollback_program(&mut self, delta: ProgramDelta) {
        self.programs.rollback(delta);
    }

    pub fn apply_program_deployment(
        &mut self,
        funding: &TransactionPreimage,
        entry: ProgramEntry,
        deployment_cost: u64,
        block_height: u64,
    ) -> Result<(), StateError> {
        if !funding.programs.is_empty() || deployment_cost > MAX_TRANSACTION_PROGRAM_COST {
            return Err(StateError::InvalidProgram);
        }
        let next_block_program_cost =
            self.next_block_program_cost(block_height, deployment_cost)?;
        let mut next = self.clone();
        next.apply_transfer(funding, block_height)?;
        next.current_block_program_cost = next_block_program_cost;
        next.register_program(entry)?;
        *self = next;
        Ok(())
    }

    pub fn apply_token_issuance(
        &mut self,
        transaction: &TransactionPreimage,
        sequence: u64,
        issued_amount: u64,
        block_height: u64,
    ) -> Result<(), StateError> {
        if issued_amount == 0
            || !transaction.spends.is_empty()
            || !(1..=2).contains(&transaction.outputs.len())
            || transaction.fee != 0
            || transaction.programs.len() != 1
        {
            return Err(StateError::InvalidProgram);
        }
        let call = &transaction.programs[0];
        if call.function_id != issuance_function_id(transaction.outputs.len()).unwrap()
            || call.public_data_hash != issuance_public_data_hash(sequence, issued_amount)
        {
            return Err(StateError::InvalidProgram);
        }
        let entry = self
            .programs
            .get(&call.program_id)
            .ok_or(StateError::InvalidProgram)?;
        let (depth, _, policy) =
            issuance_policy_from_entry(entry).map_err(|_| StateError::InvalidProgram)?;
        if depth != DEPTH {
            return Err(StateError::InvalidProgram);
        }
        let current = self
            .issuance
            .get(&call.program_id)
            .copied()
            .unwrap_or_default();
        if sequence != current.next_sequence {
            return Err(StateError::InvalidProgram);
        }
        let issued_supply = current
            .issued_supply
            .checked_add(issued_amount)
            .filter(|supply| *supply <= policy.max_supply)
            .ok_or(StateError::SupplyOverflow)?;
        let next_sequence = sequence.checked_add(1).ok_or(StateError::SupplyOverflow)?;
        let mut next = self.clone();
        next.apply_transaction(transaction, block_height)?;
        next.issuance.insert(
            call.program_id,
            TokenIssuanceState {
                issued_supply,
                next_sequence,
            },
        );
        *self = next;
        Ok(())
    }

    pub fn apply_transfer(
        &mut self,
        transaction: &TransactionPreimage,
        block_height: u64,
    ) -> Result<ShieldedStateDelta<DEPTH>, StateError> {
        let next_fees = self
            .total_fees
            .checked_add(transaction.fee)
            .ok_or(StateError::SupplyOverflow)?;
        let next_supply = self
            .circulating_supply
            .checked_sub(transaction.fee)
            .ok_or(StateError::SupplyUnderflow)?;
        let delta = self.apply_transaction(transaction, block_height)?;
        self.total_fees = next_fees;
        self.circulating_supply = next_supply;
        Ok(delta)
    }

    pub fn apply_bridge(
        &mut self,
        transaction: &TransactionPreimage,
        legacy_key_image: [u8; 32],
        legacy_amount: u64,
        fee: u64,
        block_height: u64,
    ) -> Result<ShieldedStateDelta<DEPTH>, StateError> {
        let minted = legacy_amount
            .checked_sub(fee)
            .ok_or(StateError::SupplyUnderflow)?;
        let next_bridged = self
            .total_bridged
            .checked_add(legacy_amount)
            .ok_or(StateError::SupplyOverflow)?;
        let next_fees = self
            .total_fees
            .checked_add(fee)
            .ok_or(StateError::SupplyOverflow)?;
        let next_supply = self
            .circulating_supply
            .checked_add(minted)
            .ok_or(StateError::SupplyOverflow)?;
        let mut hash = Sha256::new();
        hash.update(BRIDGE_REPLAY_DOMAIN);
        hash.update(legacy_key_image);
        let replay_nullifier = Nullifier(hash.finalize().into());
        let replay_delta = self.nullifiers.apply([&replay_nullifier])?;
        let mut delta = match self.apply_transaction(transaction, block_height) {
            Ok(delta) => delta,
            Err(error) => {
                self.nullifiers.rollback(replay_delta);
                return Err(error);
            }
        };
        delta.nullifiers.inserted.extend(replay_delta.inserted);
        self.total_bridged = next_bridged;
        self.total_fees = next_fees;
        self.circulating_supply = next_supply;
        Ok(delta)
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
        let transaction_program_cost = self
            .programs
            .validate_calls(
                &transaction.programs,
                block_height,
                MAX_TRANSACTION_PROGRAM_COST,
            )
            .map_err(|_| StateError::InvalidProgram)?;
        if !self.knows_anchor(transaction.anchor) {
            return Err(StateError::UnknownAnchor);
        }
        if block_height < self.current_height {
            return Err(StateError::HeightRegression);
        }
        let next_block_program_cost =
            self.next_block_program_cost(block_height, transaction_program_cost)?;

        let previous_tree = self.tree.clone();
        let previous_anchors = self.anchors.clone();
        let previous_height = self.current_height;
        let previous_total_bridged = self.total_bridged;
        let previous_total_fees = self.total_fees;
        let previous_circulating_supply = self.circulating_supply;
        let previous_block_program_cost = self.current_block_program_cost;
        let previous_program_states = self.program_states.clone();
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
        self.current_block_program_cost = next_block_program_cost;
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
            previous_total_bridged,
            previous_total_fees,
            previous_circulating_supply,
            previous_block_program_cost,
            previous_program_states,
        })
    }

    /// Applies a generic program transaction only after every ordered call context has been
    /// reconstructed and bound to the inclusion height. Validation is complete before the ordinary
    /// rollback-safe state transition can insert a nullifier or append a commitment.
    pub fn apply_contextual_transaction(
        &mut self,
        transaction: &TransactionPreimage,
        block_height: u64,
        contexts: &[ProgramContext],
    ) -> Result<ShieldedStateDelta<DEPTH>, StateError> {
        if transaction.programs.is_empty()
            || contexts.len() != transaction.programs.len()
            || contexts.iter().enumerate().any(|(index, context)| {
                usize::from(context.call_index) != index
                    || context.validate_binding(transaction, block_height).is_err()
            })
        {
            return Err(StateError::InvalidProgramContext);
        }
        let mut next_program_states = self.program_states.clone();
        for (call, context) in transaction.programs.iter().zip(contexts) {
            let (_, function) = self
                .programs
                .active_function(&call.program_id, call.function_id, block_height)
                .map_err(|_| StateError::InvalidProgram)?;
            let Some(kind) = kind_for_schema(&function.public_input_schema_hash) else {
                continue;
            };
            let application = StandardApplication::decode(&context.application_data)
                .map_err(|_| StateError::InvalidProgramContext)?;
            if application.kind() != kind || application.validate_context(context).is_err() {
                return Err(StateError::InvalidProgramContext);
            }
            let transition = context
                .state
                .as_ref()
                .ok_or(StateError::InvalidProgramContext)?;
            let prior = CanonicalField::from_bytes(transition.prior)
                .ok_or(StateError::InvalidProgramContext)?;
            let next = CanonicalField::from_bytes(transition.next)
                .ok_or(StateError::InvalidProgramContext)?;
            let state_key = application
                .state_key(&call.program_id)
                .map_err(|_| StateError::InvalidProgramContext)?;
            if next_program_states
                .get(&state_key)
                .is_some_and(|current| *current != prior)
            {
                return Err(StateError::InvalidProgramContext);
            }
            next_program_states.insert(state_key, next);
        }
        let delta = self.apply_transaction(transaction, block_height)?;
        self.program_states = next_program_states;
        Ok(delta)
    }

    pub fn standard_program_state(
        &self,
        program_id: &[u8; 32],
        application: &StandardApplication,
    ) -> Result<Option<CanonicalField>, StateError> {
        let key = application
            .state_key(program_id)
            .map_err(|_| StateError::InvalidProgramContext)?;
        Ok(self.program_states.get(&key).copied())
    }

    fn next_block_program_cost(
        &self,
        block_height: u64,
        additional_cost: u64,
    ) -> Result<u64, StateError> {
        if block_height < self.current_height {
            return Err(StateError::HeightRegression);
        }
        let next = if block_height == self.current_height {
            self.current_block_program_cost
                .checked_add(additional_cost)
                .ok_or(StateError::ProgramCostLimit)?
        } else {
            additional_cost
        };
        if next > MAX_BLOCK_PROGRAM_COST {
            Err(StateError::ProgramCostLimit)
        } else {
            Ok(next)
        }
    }

    pub fn rollback(&mut self, delta: ShieldedStateDelta<DEPTH>) {
        self.tree = delta.previous_tree;
        self.nullifiers.rollback(delta.nullifiers);
        self.anchors = delta.previous_anchors;
        self.current_height = delta.previous_height;
        self.total_bridged = delta.previous_total_bridged;
        self.total_fees = delta.previous_total_fees;
        self.circulating_supply = delta.previous_circulating_supply;
        self.current_block_program_cost = delta.previous_block_program_cost;
        self.program_states = delta.previous_program_states;
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
        write_varint(self.total_bridged, &mut out);
        write_varint(self.total_fees, &mut out);
        write_varint(self.circulating_supply, &mut out);
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
        let programs = self.programs.encode();
        write_varint(programs.len() as u64, &mut out);
        out.extend_from_slice(&programs);
        write_varint(self.current_block_program_cost, &mut out);
        write_varint(self.issuance.len() as u64, &mut out);
        for (program_id, issuance) in &self.issuance {
            out.extend_from_slice(program_id);
            write_varint(issuance.issued_supply, &mut out);
            write_varint(issuance.next_sequence, &mut out);
        }
        write_varint(self.program_states.len() as u64, &mut out);
        for (state_key, value) in &self.program_states {
            out.extend_from_slice(state_key);
            out.extend_from_slice(&value.bytes());
        }
        out
    }

    pub fn decode_snapshot(input: &[u8]) -> Result<Self, SnapshotError> {
        if DEPTH == 0 || DEPTH >= 64 {
            return Err(SnapshotError::WrongDepth);
        }
        let mut reader = Reader::new(input);
        let version = reader.byte()?;
        if version != SNAPSHOT_VERSION
            && version != PRE_BRIDGE_REPLAY_SNAPSHOT_VERSION
            && version != ISSUANCE_SNAPSHOT_VERSION
            && version != ACCOUNTING_SNAPSHOT_VERSION
            && version != PROGRAM_REGISTRY_SNAPSHOT_VERSION
            && version != PROGRAM_COST_SNAPSHOT_VERSION
            && version != LEGACY_SNAPSHOT_VERSION
        {
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
        let (total_bridged, total_fees, circulating_supply) =
            if version >= ACCOUNTING_SNAPSHOT_VERSION {
                let total_bridged = reader.varint()?;
                let total_fees = reader.varint()?;
                let circulating_supply = reader.varint()?;
                if total_bridged.checked_sub(total_fees) != Some(circulating_supply) {
                    return Err(SnapshotError::InvalidSupply);
                }
                (total_bridged, total_fees, circulating_supply)
            } else {
                (0, 0, 0)
            };
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
        if version == LEGACY_SNAPSHOT_VERSION && (leaf_count != 0 || !values.is_empty()) {
            return Err(SnapshotError::InvalidSupply);
        }
        let programs = if version >= PROGRAM_REGISTRY_SNAPSHOT_VERSION {
            let length = bounded_snapshot_count(
                reader.varint()?,
                crate::program::MAX_REGISTRY_BYTES,
                SnapshotError::InvalidRegistry,
            )?;
            ProgramRegistry::decode(reader.take(length)?)
                .map_err(|_| SnapshotError::InvalidRegistry)?
        } else {
            ProgramRegistry::default()
        };
        let current_block_program_cost = if version >= PROGRAM_COST_SNAPSHOT_VERSION {
            let cost = reader.varint()?;
            if cost > MAX_BLOCK_PROGRAM_COST {
                return Err(SnapshotError::InvalidProgramCost);
            }
            cost
        } else {
            0
        };
        let issuance = if version >= ISSUANCE_SNAPSHOT_VERSION {
            let count = bounded_snapshot_count(
                reader.varint()?,
                crate::program::MAX_REGISTERED_PROGRAMS,
                SnapshotError::InvalidIssuanceLedger,
            )?;
            let mut issuance = BTreeMap::new();
            let mut previous = None;
            for _ in 0..count {
                let program_id: [u8; 32] = reader.array()?;
                if previous.is_some_and(|id| id >= program_id)
                    || programs.get(&program_id).is_none()
                {
                    return Err(SnapshotError::InvalidIssuanceLedger);
                }
                previous = Some(program_id);
                let issued_supply = reader.varint()?;
                let next_sequence = reader.varint()?;
                let entry = programs
                    .get(&program_id)
                    .ok_or(SnapshotError::InvalidIssuanceLedger)?;
                let (_, _, policy) = issuance_policy_from_entry(entry)
                    .map_err(|_| SnapshotError::InvalidIssuanceLedger)?;
                if issued_supply == 0 || issued_supply > policy.max_supply || next_sequence == 0 {
                    return Err(SnapshotError::InvalidIssuanceLedger);
                }
                issuance.insert(
                    program_id,
                    TokenIssuanceState {
                        issued_supply,
                        next_sequence,
                    },
                );
            }
            issuance
        } else {
            BTreeMap::new()
        };
        let program_states = if version == SNAPSHOT_VERSION {
            let count = bounded_snapshot_count(
                reader.varint()?,
                MAX_SNAPSHOT_PROGRAM_STATES,
                SnapshotError::InvalidProgramState,
            )?;
            let mut states = BTreeMap::new();
            let mut previous = None;
            for _ in 0..count {
                let state_key: [u8; 32] = reader.array()?;
                if previous.is_some_and(|key| key >= state_key) {
                    return Err(SnapshotError::InvalidProgramState);
                }
                previous = Some(state_key);
                states.insert(state_key, reader.field()?);
            }
            states
        } else {
            BTreeMap::new()
        };
        if !reader.is_empty() {
            return Err(DecodeError::TrailingData.into());
        }
        Ok(Self {
            tree,
            nullifiers: NullifierSet { values },
            anchors,
            anchor_window_blocks,
            current_height,
            total_bridged,
            total_fees,
            circulating_supply,
            programs,
            current_block_program_cost,
            issuance,
            program_states,
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
    fn supply_audit_tracks_bridges_fees_snapshots_and_rollback() {
        let mut state = ShieldedState::<4>::new(3);
        let mut bridge = transaction(state.root(), 1, 30);
        bridge.fee = 0;
        bridge.spends.clear();
        let bridge_delta = state.apply_bridge(&bridge, [1; 32], 30, 5, 1).unwrap();
        assert_eq!(
            state.apply_bridge(&bridge, [1; 32], 30, 5, 1).err(),
            Some(StateError::DuplicateNullifier)
        );
        assert_eq!(
            (
                state.total_bridged(),
                state.total_fees(),
                state.circulating_supply()
            ),
            (30, 5, 25)
        );

        let mut transfer = transaction(state.root(), 2, 31);
        transfer.fee = 2;
        let transfer_delta = state.apply_transfer(&transfer, 2).unwrap();
        assert_eq!(
            (
                state.total_bridged(),
                state.total_fees(),
                state.circulating_supply()
            ),
            (30, 7, 23)
        );
        state.rollback(transfer_delta);
        assert_eq!((state.total_fees(), state.circulating_supply()), (5, 25));

        let encoded = state.encode_snapshot();
        let restored = ShieldedState::<4>::decode_snapshot(&encoded).unwrap();
        assert_eq!(restored.encode_snapshot(), encoded);
        let counters = encoded
            .windows(3)
            .position(|bytes| bytes == [30, 5, 25])
            .unwrap();
        let mut corrupted = encoded.clone();
        corrupted[counters + 2] = 24;
        assert_eq!(
            ShieldedState::<4>::decode_snapshot(&corrupted).err(),
            Some(SnapshotError::InvalidSupply)
        );

        let mut nonempty_legacy = encoded;
        nonempty_legacy[0] = LEGACY_SNAPSHOT_VERSION;
        nonempty_legacy.drain(counters..counters + 3);
        assert_eq!(
            ShieldedState::<4>::decode_snapshot(&nonempty_legacy).err(),
            Some(SnapshotError::InvalidSupply)
        );

        let mut legacy = ShieldedState::<4>::new(3).encode_snapshot();
        legacy[0] = LEGACY_SNAPSHOT_VERSION;
        legacy.drain(6..9);
        legacy.truncate(legacy.len() - 6);
        let migrated = ShieldedState::<4>::decode_snapshot(&legacy).unwrap();
        assert_eq!(
            (
                migrated.total_bridged(),
                migrated.total_fees(),
                migrated.circulating_supply()
            ),
            (0, 0, 0)
        );

        let mut accounting_v2 = state.encode_snapshot();
        accounting_v2[0] = ACCOUNTING_SNAPSHOT_VERSION;
        accounting_v2.truncate(accounting_v2.len() - 6);
        let migrated_v2 = ShieldedState::<4>::decode_snapshot(&accounting_v2).unwrap();
        assert_eq!(
            (
                migrated_v2.total_bridged(),
                migrated_v2.total_fees(),
                migrated_v2.circulating_supply(),
                migrated_v2.program_count()
            ),
            (30, 5, 25, 0)
        );

        state.rollback(bridge_delta);
        assert_eq!(
            (
                state.total_bridged(),
                state.total_fees(),
                state.circulating_supply()
            ),
            (0, 0, 0)
        );
        let reapplied = state.apply_bridge(&bridge, [1; 32], 30, 5, 1).unwrap();
        state.rollback(reapplied);
    }

    #[test]
    fn program_registry_is_snapshot_bound_and_calls_fail_closed() {
        use crate::program::{ProgramEntry, ProgramFunction};
        use crate::transaction::ProgramCall;

        let entry = ProgramEntry {
            manifest: b"onyx.test.registry/v1".to_vec(),
            backend: "halo2-ipa-pasta".to_owned(),
            activation_height: 10,
            deactivation_height: Some(20),
            functions: vec![ProgramFunction {
                function_id: 7,
                verifying_key: vec![1, 2, 3],
                public_input_schema_hash: [4; 32],
                max_cost: 9_000_000,
            }],
        };
        let program_id = entry.id().unwrap();
        let mut state = ShieldedState::<4>::new(3);
        let registry_delta = state.register_program(entry).unwrap();
        assert_eq!(state.program_count(), 1);
        let snapshot = state.encode_snapshot();
        assert_eq!(
            ShieldedState::<4>::decode_snapshot(&snapshot)
                .unwrap()
                .program_count(),
            1
        );
        let mut registry_v3 = snapshot.clone();
        registry_v3[0] = PROGRAM_REGISTRY_SNAPSHOT_VERSION;
        registry_v3.truncate(registry_v3.len() - 3);
        let migrated_v3 = ShieldedState::<4>::decode_snapshot(&registry_v3).unwrap();
        assert_eq!(migrated_v3.program_count(), 1);
        assert_eq!(migrated_v3.current_block_program_cost(), 0);

        let mut unknown = transaction(state.root(), 1, 40);
        unknown.programs.push(ProgramCall {
            program_id: [9; 32],
            function_id: 7,
            public_data_hash: [5; 32],
        });
        assert_eq!(
            state.apply_transaction(&unknown, 10).err(),
            Some(StateError::InvalidProgram)
        );
        assert_eq!(state.leaf_count(), 0);

        let mut registered = transaction(state.root(), 1, 40);
        registered.programs.push(ProgramCall {
            program_id,
            function_id: 7,
            public_data_hash: [5; 32],
        });
        let tx_delta = state.apply_transaction(&registered, 10).unwrap();
        assert_eq!(state.current_block_program_cost(), 9_000_000);
        let mut second = transaction(state.root(), 2, 41);
        second.programs.push(ProgramCall {
            program_id,
            function_id: 7,
            public_data_hash: [6; 32],
        });
        let second_delta = state.apply_transaction(&second, 10).unwrap();
        assert_eq!(state.current_block_program_cost(), 18_000_000);
        let mut third = transaction(state.root(), 3, 42);
        third.programs.push(ProgramCall {
            program_id,
            function_id: 7,
            public_data_hash: [7; 32],
        });
        assert_eq!(
            state.apply_transaction(&third, 10).err(),
            Some(StateError::ProgramCostLimit)
        );
        let third_delta = state.apply_transaction(&third, 11).unwrap();
        assert_eq!(state.current_block_program_cost(), 9_000_000);
        state.rollback(third_delta);
        assert_eq!(state.current_block_program_cost(), 18_000_000);
        state.rollback(second_delta);
        state.rollback(tx_delta);
        assert_eq!(state.current_block_program_cost(), 0);
        state.rollback_program(registry_delta);
        assert_eq!(state.program_count(), 0);
    }

    #[test]
    fn contextual_program_calls_fail_before_state_mutation() {
        use crate::program::{ProgramEntry, ProgramFunction};
        use crate::program_context::{ProgramContext, ProgramStateTransition};
        use crate::transaction::ProgramCall;

        let entry = ProgramEntry {
            manifest: b"onyx.test.context/v1".to_vec(),
            backend: "halo2-ipa-pasta".to_owned(),
            activation_height: 10,
            deactivation_height: None,
            functions: vec![ProgramFunction {
                function_id: 7,
                verifying_key: vec![1, 2, 3],
                public_input_schema_hash: [4; 32],
                max_cost: 100,
            }],
        };
        let program_id = entry.id().unwrap();
        let mut state = ShieldedState::<4>::new(3);
        state.register_program(entry).unwrap();
        let empty = transaction(state.root(), 1, 40);
        assert_eq!(
            state.apply_contextual_transaction(&empty, 10, &[]).err(),
            Some(StateError::InvalidProgramContext)
        );
        let mut transaction = transaction(state.root(), 1, 40);
        transaction.programs.push(ProgramCall {
            program_id,
            function_id: 7,
            public_data_hash: [0; 32],
        });
        let context = ProgramContext::from_transaction(
            &transaction,
            0,
            10,
            Some(ProgramStateTransition {
                prior: [5; 32],
                next: [6; 32],
            }),
            b"context-test".to_vec(),
        )
        .unwrap();
        transaction.programs[0].public_data_hash = context.hash().unwrap();
        let before = state.encode_snapshot();
        assert_eq!(
            state
                .apply_contextual_transaction(&transaction, 10, &[])
                .err(),
            Some(StateError::InvalidProgramContext)
        );
        let mut altered = context.clone();
        altered.application_data[0] ^= 1;
        assert_eq!(
            state
                .apply_contextual_transaction(&transaction, 10, &[altered])
                .err(),
            Some(StateError::InvalidProgramContext)
        );
        assert_eq!(state.encode_snapshot(), before);
        let delta = state
            .apply_contextual_transaction(&transaction, 10, &[context])
            .unwrap();
        assert_eq!(state.leaf_count(), 1);
        state.rollback(delta);
        assert_eq!(state.encode_snapshot(), before);
    }

    #[test]
    fn standard_contextual_state_rejects_forks_and_survives_snapshot_rollback() {
        use crate::program_context::{ProgramContext, ProgramStateTransition};
        use crate::standard_programs::{
            standard_program_entry, StandardApplication, StandardProgramKind, STANDARD_FUNCTION_ID,
        };
        use crate::transaction::ProgramCall;

        fn bind(
            mut transaction: TransactionPreimage,
            application: &StandardApplication,
            prior: CanonicalField,
            next: CanonicalField,
        ) -> (TransactionPreimage, ProgramContext) {
            let context = ProgramContext::from_transaction(
                &transaction,
                0,
                10,
                Some(ProgramStateTransition {
                    prior: prior.bytes(),
                    next: next.bytes(),
                }),
                application.encode().unwrap(),
            )
            .unwrap();
            transaction.programs[0].public_data_hash = context.hash().unwrap();
            (transaction, context)
        }

        let entry = standard_program_entry(StandardProgramKind::Nft, 10, None).unwrap();
        let program_id = entry.id().unwrap();
        let mut state = ShieldedState::<4>::new(20);
        state.register_program(entry).unwrap();
        let application = StandardApplication::Nft {
            collection_id: [1; 32],
            token_id: [2; 32],
            serial: 7,
            transfer_nonce: 1,
        };
        let prior = field(41);
        let first_next = field(42);
        let mut first = transaction(state.root(), 1, 50);
        first.programs.push(ProgramCall {
            program_id,
            function_id: STANDARD_FUNCTION_ID,
            public_data_hash: [0; 32],
        });
        let (first, first_context) = bind(first, &application, prior, first_next);
        let before = state.encode_snapshot();
        let mut issuance_v5 = before.clone();
        issuance_v5[0] = ISSUANCE_SNAPSHOT_VERSION;
        issuance_v5.truncate(issuance_v5.len() - 1);
        let migrated_v5 = ShieldedState::<4>::decode_snapshot(&issuance_v5).unwrap();
        assert_eq!(
            migrated_v5
                .standard_program_state(&program_id, &application)
                .unwrap(),
            None
        );
        let first_delta = state
            .apply_contextual_transaction(&first, 10, &[first_context])
            .unwrap();
        assert_eq!(
            state
                .standard_program_state(&program_id, &application)
                .unwrap(),
            Some(first_next)
        );
        let restored = ShieldedState::<4>::decode_snapshot(&state.encode_snapshot()).unwrap();
        assert_eq!(
            restored
                .standard_program_state(&program_id, &application)
                .unwrap(),
            Some(first_next)
        );

        let competing_application = StandardApplication::Nft {
            collection_id: [1; 32],
            token_id: [2; 32],
            serial: 7,
            transfer_nonce: 2,
        };
        let mut competing = transaction(state.root(), 2, 51);
        competing.programs.push(ProgramCall {
            program_id,
            function_id: STANDARD_FUNCTION_ID,
            public_data_hash: [0; 32],
        });
        let (competing, competing_context) =
            bind(competing, &competing_application, prior, field(43));
        let after_first = state.encode_snapshot();
        assert_eq!(
            state
                .apply_contextual_transaction(&competing, 10, &[competing_context])
                .err(),
            Some(StateError::InvalidProgramContext)
        );
        assert_eq!(state.encode_snapshot(), after_first);

        let mut chained = transaction(state.root(), 3, 52);
        chained.programs.push(ProgramCall {
            program_id,
            function_id: STANDARD_FUNCTION_ID,
            public_data_hash: [0; 32],
        });
        let chained_next = field(44);
        let (chained, chained_context) =
            bind(chained, &competing_application, first_next, chained_next);
        let chained_delta = state
            .apply_contextual_transaction(&chained, 10, &[chained_context])
            .unwrap();
        assert_eq!(
            state
                .standard_program_state(&program_id, &competing_application)
                .unwrap(),
            Some(chained_next)
        );
        state.rollback(chained_delta);
        assert_eq!(state.encode_snapshot(), after_first);
        state.rollback(first_delta);
        assert_eq!(state.encode_snapshot(), before);
    }

    #[test]
    fn token_issuance_ledger_enforces_sequence_cap_and_snapshot_binding() {
        use crate::token_program::{
            issuance_function_id, issuance_public_data_hash, standard_token_program,
            TokenIssuancePolicy,
        };
        use crate::transaction::ProgramCall;
        use group::GroupEncoding;

        let issuer = (crate::spend_auth_circuit::spend_auth_generator()
            * pasta_curves::pallas::Scalar::from(77))
        .to_bytes();
        let manifest = TokenIssuancePolicy {
            issuer,
            max_supply: 100,
            metadata: b"symbol=CAP".to_vec(),
        }
        .encode()
        .unwrap();
        let entry = standard_token_program::<4>(14, &manifest, 1, None).unwrap();
        let program_id = entry.id().unwrap();
        let mut state = ShieldedState::<4>::new(3);
        state.register_program(entry).unwrap();

        let issuance = |anchor, sequence, amount, commitment| {
            let mut tx = transaction(anchor, 1, commitment);
            tx.fee = 0;
            tx.spends.clear();
            tx.programs.push(ProgramCall {
                program_id,
                function_id: issuance_function_id(1).unwrap(),
                public_data_hash: issuance_public_data_hash(sequence, amount),
            });
            tx
        };
        let first = issuance(state.root(), 0, 60, 70);
        state.apply_token_issuance(&first, 0, 60, 1).unwrap();
        assert_eq!(state.token_issued_supply(&program_id), 60);
        assert_eq!(state.token_next_issuance_sequence(&program_id), 1);
        let after_first = state.encode_snapshot();

        let wrong_sequence = issuance(state.root(), 0, 40, 71);
        assert_eq!(
            state.apply_token_issuance(&wrong_sequence, 0, 40, 2).err(),
            Some(StateError::InvalidProgram)
        );
        assert_eq!(state.encode_snapshot(), after_first);

        let overflow = issuance(state.root(), 1, 41, 72);
        assert_eq!(
            state.apply_token_issuance(&overflow, 1, 41, 2).err(),
            Some(StateError::SupplyOverflow)
        );
        assert_eq!(state.encode_snapshot(), after_first);

        let final_issuance = issuance(state.root(), 1, 40, 73);
        state
            .apply_token_issuance(&final_issuance, 1, 40, 2)
            .unwrap();
        assert_eq!(state.token_issued_supply(&program_id), 100);
        assert_eq!(state.token_next_issuance_sequence(&program_id), 2);
        let snapshot = state.encode_snapshot();
        let restored = ShieldedState::<4>::decode_snapshot(&snapshot).unwrap();
        assert_eq!(restored.encode_snapshot(), snapshot);
        assert_eq!(restored.token_issued_supply(&program_id), 100);
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
