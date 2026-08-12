//! Deterministic differential campaigns for the rollback-safe Onyx state engine.
//!
//! The reference ledger intentionally does not call `ShieldedState` transition helpers. It uses
//! separate containers and independently recomputes Poseidon Merkle roots, admission state, supply,
//! program costs, issuance, and standard-program state. A failure reports its seed and the shortest
//! operation prefix observed to diverge.

use std::collections::{BTreeMap, BTreeSet};

use ff::PrimeField;
use group::GroupEncoding;
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash as PoseidonHash, P128Pow5T3};
use halo2_proofs::pasta::Fp;
use sha2::{Digest, Sha256};

use crate::program::{ProgramEntry, ProgramFunction};
use crate::program_context::{ProgramContext, ProgramStateTransition};
use crate::spend_auth_circuit::spend_auth_generator;
use crate::standard_programs::{
    standard_program_entry, StandardApplication, StandardProgramKind, STANDARD_FUNCTION_ID,
};
use crate::state::{CanonicalField, Nullifier, ShieldedState, SnapshotError};
use crate::token_program::{
    issuance_function_id, issuance_public_data_hash, issuance_schema_hash, TokenIssuancePolicy,
    TOKEN_MANIFEST_PREFIX, TOKEN_PROGRAM_BACKEND,
};
use crate::transaction::{ProgramCall, PublicOutput, PublicSpend, TransactionPreimage};
use crate::types::NETWORK_ID_BYTES;

const DEPTH: usize = 8;
const ANCHOR_WINDOW: u64 = 4;
const MAX_BLOCK_PROGRAM_COST: u64 = 20_000_000;
const BRIDGE_REPLAY_DOMAIN: &[u8] = b"bytecoin.onyx.v6.bridge-replay";

#[derive(Clone, Debug)]
struct ReferenceProgram {
    activation_height: u64,
    deactivation_height: Option<u64>,
    functions: BTreeMap<u32, u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReferenceIssuance {
    issued_supply: u64,
    next_sequence: u64,
}

#[derive(Clone, Debug)]
struct ReferenceTree {
    leaf_count: usize,
    frontier: [Option<Fp>; DEPTH],
    empty: Vec<Fp>,
    full_root: Option<Fp>,
}

impl ReferenceTree {
    fn new() -> Self {
        let mut empty = Vec::with_capacity(DEPTH + 1);
        empty.push(reference_leaf(Fp::zero()));
        for level in 0..DEPTH {
            empty.push(reference_node(empty[level], empty[level]));
        }
        Self {
            leaf_count: 0,
            frontier: [None; DEPTH],
            empty,
            full_root: None,
        }
    }

    fn root(&self) -> CanonicalField {
        if let Some(root) = self.full_root {
            return CanonicalField::from_field(root);
        }
        let mut node = self.empty[0];
        for level in 0..DEPTH {
            node = if ((self.leaf_count >> level) & 1) == 1 {
                reference_node(self.frontier[level].expect("reference frontier"), node)
            } else {
                reference_node(node, self.empty[level])
            };
        }
        CanonicalField::from_field(node)
    }

    fn append(&mut self, commitment: CanonicalField) -> Result<(), &'static str> {
        if self.leaf_count == (1usize << DEPTH) {
            return Err("tree full");
        }
        let mut index = self.leaf_count;
        let value = Option::<Fp>::from(Fp::from_repr(commitment.bytes()))
            .ok_or("noncanonical commitment")?;
        let mut node = reference_leaf(value);
        for level in 0..DEPTH {
            if (index & 1) == 0 {
                self.frontier[level] = Some(node);
                self.leaf_count += 1;
                return Ok(());
            }
            node = reference_node(
                self.frontier[level].take().ok_or("reference frontier")?,
                node,
            );
            index >>= 1;
        }
        self.full_root = Some(node);
        self.leaf_count += 1;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ReferenceState {
    tree: ReferenceTree,
    nullifiers: BTreeSet<[u8; 32]>,
    anchors: Vec<(CanonicalField, u64)>,
    current_height: u64,
    total_bridged: u64,
    total_fees: u64,
    circulating_supply: u64,
    programs: BTreeMap<[u8; 32], ReferenceProgram>,
    current_block_program_cost: u64,
    issuance: BTreeMap<[u8; 32], ReferenceIssuance>,
    program_states: BTreeMap<[u8; 32], CanonicalField>,
}

impl ReferenceState {
    fn new() -> Self {
        let tree = ReferenceTree::new();
        let root = tree.root();
        Self {
            tree,
            nullifiers: BTreeSet::new(),
            anchors: vec![(root, 0)],
            current_height: 0,
            total_bridged: 0,
            total_fees: 0,
            circulating_supply: 0,
            programs: BTreeMap::new(),
            current_block_program_cost: 0,
            issuance: BTreeMap::new(),
            program_states: BTreeMap::new(),
        }
    }

    fn root(&self) -> CanonicalField {
        self.tree.root()
    }

    fn knows_anchor(&self, root: CanonicalField) -> bool {
        self.anchors.iter().any(|(candidate, _)| *candidate == root)
    }

    fn function_cost(
        &self,
        program_id: &[u8; 32],
        function_id: u32,
        height: u64,
    ) -> Result<u64, &'static str> {
        let program = self.programs.get(program_id).ok_or("unknown program")?;
        if height < program.activation_height
            || program
                .deactivation_height
                .is_some_and(|deactivation| height >= deactivation)
        {
            return Err("inactive program");
        }
        program
            .functions
            .get(&function_id)
            .copied()
            .ok_or("unknown function")
    }

    fn apply_base(
        &mut self,
        transaction: &TransactionPreimage,
        block_height: u64,
        explicit_program_cost: Option<u64>,
    ) -> Result<(), &'static str> {
        if block_height < self.current_height {
            return Err("height regression");
        }
        if !self.knows_anchor(transaction.anchor) {
            return Err("unknown anchor");
        }
        if self.tree.leaf_count + transaction.outputs.len() > (1usize << DEPTH) {
            return Err("tree full");
        }
        let mut staged = BTreeSet::new();
        for spend in &transaction.spends {
            if self.nullifiers.contains(&spend.nullifier.0) || !staged.insert(spend.nullifier.0) {
                return Err("duplicate nullifier");
            }
        }
        let program_cost = match explicit_program_cost {
            Some(cost) => cost,
            None => transaction.programs.iter().try_fold(0u64, |total, call| {
                total
                    .checked_add(self.function_cost(
                        &call.program_id,
                        call.function_id,
                        block_height,
                    )?)
                    .ok_or("program cost overflow")
            })?,
        };
        let next_cost = if block_height == self.current_height {
            self.current_block_program_cost
                .checked_add(program_cost)
                .ok_or("program cost overflow")?
        } else {
            program_cost
        };
        if next_cost > MAX_BLOCK_PROGRAM_COST {
            return Err("program cost limit");
        }

        self.nullifiers.extend(staged);
        for output in &transaction.outputs {
            self.tree.append(output.commitment)?;
        }
        self.current_height = block_height;
        self.current_block_program_cost = next_cost;
        let root = self.root();
        if self.anchors.last().map(|entry| entry.0) != Some(root) {
            self.anchors.push((root, block_height));
        }
        let oldest_height = block_height.saturating_sub(ANCHOR_WINDOW - 1);
        self.anchors.retain(|(_, height)| *height >= oldest_height);
        Ok(())
    }

    fn apply_bridge(
        &mut self,
        transaction: &TransactionPreimage,
        key_image: [u8; 32],
        amount: u64,
        fee: u64,
        height: u64,
    ) -> Result<(), &'static str> {
        let mut next = self.clone();
        let minted = amount.checked_sub(fee).ok_or("bridge underflow")?;
        let mut hash = Sha256::new();
        hash.update(BRIDGE_REPLAY_DOMAIN);
        hash.update(key_image);
        let replay: [u8; 32] = hash.finalize().into();
        if !next.nullifiers.insert(replay) {
            return Err("duplicate bridge");
        }
        next.apply_base(transaction, height, None)?;
        next.total_bridged = next
            .total_bridged
            .checked_add(amount)
            .ok_or("supply overflow")?;
        next.total_fees = next.total_fees.checked_add(fee).ok_or("supply overflow")?;
        next.circulating_supply = next
            .circulating_supply
            .checked_add(minted)
            .ok_or("supply overflow")?;
        *self = next;
        Ok(())
    }

    fn apply_transfer(
        &mut self,
        transaction: &TransactionPreimage,
        height: u64,
    ) -> Result<(), &'static str> {
        let mut next = self.clone();
        next.circulating_supply = next
            .circulating_supply
            .checked_sub(transaction.fee)
            .ok_or("supply underflow")?;
        next.total_fees = next
            .total_fees
            .checked_add(transaction.fee)
            .ok_or("supply overflow")?;
        next.apply_base(transaction, height, None)?;
        *self = next;
        Ok(())
    }

    fn apply_deployment(
        &mut self,
        funding: &TransactionPreimage,
        entry: &ProgramEntry,
        deployment_cost: u64,
        height: u64,
    ) -> Result<(), &'static str> {
        let program_id = entry.id().map_err(|_| "invalid program")?;
        if self.programs.contains_key(&program_id) {
            return Err("duplicate program");
        }
        let mut next = self.clone();
        next.circulating_supply = next
            .circulating_supply
            .checked_sub(funding.fee)
            .ok_or("supply underflow")?;
        next.total_fees = next
            .total_fees
            .checked_add(funding.fee)
            .ok_or("supply overflow")?;
        next.apply_base(funding, height, Some(deployment_cost))?;
        next.programs.insert(
            program_id,
            ReferenceProgram {
                activation_height: entry.activation_height,
                deactivation_height: entry.deactivation_height,
                functions: entry
                    .functions
                    .iter()
                    .map(|function| (function.function_id, function.max_cost))
                    .collect(),
            },
        );
        *self = next;
        Ok(())
    }

    fn apply_issuance(
        &mut self,
        transaction: &TransactionPreimage,
        program_id: [u8; 32],
        sequence: u64,
        amount: u64,
        max_supply: u64,
        height: u64,
    ) -> Result<(), &'static str> {
        let current = self.issuance.get(&program_id).copied().unwrap_or_default();
        if sequence != current.next_sequence || amount == 0 {
            return Err("issuance sequence");
        }
        let issued_supply = current
            .issued_supply
            .checked_add(amount)
            .filter(|supply| *supply <= max_supply)
            .ok_or("issuance cap")?;
        let mut next = self.clone();
        next.apply_base(transaction, height, None)?;
        next.issuance.insert(
            program_id,
            ReferenceIssuance {
                issued_supply,
                next_sequence: sequence + 1,
            },
        );
        *self = next;
        Ok(())
    }

    fn apply_contextual(
        &mut self,
        transaction: &TransactionPreimage,
        application: &StandardApplication,
        prior: CanonicalField,
        next_value: CanonicalField,
        height: u64,
    ) -> Result<(), &'static str> {
        let call = transaction.programs.first().ok_or("missing call")?;
        let state_key = application
            .state_key(&call.program_id)
            .map_err(|_| "state key")?;
        if self
            .program_states
            .get(&state_key)
            .is_some_and(|current| *current != prior)
        {
            return Err("program state conflict");
        }
        let mut next = self.clone();
        next.apply_base(transaction, height, None)?;
        next.program_states.insert(state_key, next_value);
        *self = next;
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
enum Operation {
    Bridge {
        height: u64,
        amount: u64,
        fee: u64,
    },
    Transfer {
        height: u64,
        fee: u64,
    },
    DeployToken {
        height: u64,
    },
    DeployNft {
        height: u64,
    },
    Issue {
        height: u64,
        sequence: u64,
        amount: u64,
    },
    NftCall {
        height: u64,
        nonce: u64,
    },
    RejectDuplicate {
        height: u64,
    },
    RejectStaleAnchor {
        height: u64,
    },
    RejectProgramFork {
        height: u64,
    },
    Undo {
        checkpoint: usize,
    },
    Fork {
        checkpoint: usize,
    },
    Reopen,
}

struct Campaign {
    production: ShieldedState<DEPTH>,
    reference: ReferenceState,
    history: Vec<(Vec<u8>, ReferenceState)>,
    trace: Vec<Operation>,
    all_roots: Vec<CanonicalField>,
    successful_checkpoints: usize,
    counter: u64,
}

impl Campaign {
    fn new() -> Self {
        let production = ShieldedState::<DEPTH>::new(ANCHOR_WINDOW);
        let reference = ReferenceState::new();
        let snapshot = production.encode_snapshot();
        Self {
            production,
            reference: reference.clone(),
            history: vec![(snapshot, reference)],
            trace: Vec::new(),
            all_roots: Vec::new(),
            successful_checkpoints: 0,
            counter: 1,
        }
    }

    fn next_id(&mut self) -> u64 {
        let value = self.counter;
        self.counter += 1;
        value
    }

    fn record_success(&mut self) {
        let snapshot = self.production.encode_snapshot();
        self.history.push((snapshot, self.reference.clone()));
        self.all_roots.push(self.reference.root());
        self.successful_checkpoints += 1;
    }

    fn restore(&mut self, checkpoint: usize) {
        let (snapshot, reference) = self.history[checkpoint].clone();
        self.production = ShieldedState::decode_snapshot(&snapshot).unwrap();
        self.reference = reference;
        self.history.truncate(checkpoint + 1);
    }

    fn check(&mut self, seed: u64, step: usize) {
        let production_snapshot = self.production.encode_snapshot();
        let reopened = ShieldedState::<DEPTH>::decode_snapshot(&production_snapshot)
            .unwrap_or_else(|error| {
                fail(
                    seed,
                    step,
                    &self.trace,
                    &format!("reopen failed: {error:?}"),
                )
            });
        if reopened.encode_snapshot() != production_snapshot {
            fail(seed, step, &self.trace, "snapshot round trip changed bytes");
        }
        compare(seed, step, &self.trace, &self.production, &self.reference);
        compare(seed, step, &self.trace, &reopened, &self.reference);
    }
}

#[derive(Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() as usize) % limit
    }
}

fn reference_poseidon2(a: Fp, b: Fp) -> Fp {
    PoseidonHash::<Fp, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([a, b])
}

fn reference_leaf(value: Fp) -> Fp {
    reference_poseidon2(Fp::from(1), value)
}

fn reference_node(left: Fp, right: Fp) -> Fp {
    reference_poseidon2(Fp::from(2), reference_poseidon2(left, right))
}

fn field(value: u64) -> CanonicalField {
    CanonicalField::from_field(Fp::from(value))
}

fn nullifier(value: u64) -> Nullifier {
    Nullifier(Fp::from(value).to_repr())
}

fn transaction(
    anchor: CanonicalField,
    nullifier_id: Option<u64>,
    commitment_id: u64,
    fee: u64,
    expiry_height: u64,
) -> TransactionPreimage {
    TransactionPreimage {
        network_id: [1; NETWORK_ID_BYTES],
        anchor,
        expiry_height,
        fee,
        spends: nullifier_id
            .map(|id| PublicSpend {
                nullifier: nullifier(id),
                value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                    1,
                    Fp::from(2),
                ),
                randomized_key: [20; 32],
            })
            .into_iter()
            .collect(),
        outputs: vec![PublicOutput {
            commitment: field(commitment_id),
            value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                1,
                Fp::from(3),
            ),
            ephemeral_key: [21; 32],
            ciphertext: vec![1, 2, 3],
            outgoing_ciphertext: vec![4, 5],
        }],
        programs: Vec::new(),
    }
}

fn compare(
    seed: u64,
    step: usize,
    trace: &[Operation],
    production: &ShieldedState<DEPTH>,
    reference: &ReferenceState,
) {
    let observed = (
        production.root(),
        production.leaf_count() as usize,
        production.current_height(),
        production.total_bridged(),
        production.total_fees(),
        production.circulating_supply(),
        production.program_count(),
        production.current_block_program_cost(),
        production.nullifier_count(),
        production.anchor_count(),
        production.issuance_count(),
        production.program_state_count(),
    );
    let expected = (
        reference.root(),
        reference.tree.leaf_count,
        reference.current_height,
        reference.total_bridged,
        reference.total_fees,
        reference.circulating_supply,
        reference.programs.len(),
        reference.current_block_program_cost,
        reference.nullifiers.len(),
        reference.anchors.len(),
        reference.issuance.len(),
        reference.program_states.len(),
    );
    if observed != expected {
        fail(
            seed,
            step,
            trace,
            &format!("state mismatch: observed={observed:?} expected={expected:?}"),
        );
    }
    for nullifier in &reference.nullifiers {
        if !production.is_spent(&Nullifier(*nullifier)) {
            fail(
                seed,
                step,
                trace,
                "reference nullifier missing from production",
            );
        }
    }
    for (root, _) in &reference.anchors {
        if !production.knows_anchor(*root) {
            fail(
                seed,
                step,
                trace,
                "reference anchor missing from production",
            );
        }
    }
    for (program_id, issuance) in &reference.issuance {
        if production.token_issued_supply(program_id) != issuance.issued_supply
            || production.token_next_issuance_sequence(program_id) != issuance.next_sequence
        {
            fail(seed, step, trace, "token issuance ledger mismatch");
        }
    }
    for (state_key, value) in &reference.program_states {
        if production.standard_program_state_by_key(state_key) != Some(*value) {
            fail(seed, step, trace, "standard program state mismatch");
        }
    }
}

fn fail(seed: u64, step: usize, trace: &[Operation], message: &str) -> ! {
    panic!(
        "Onyx state-model divergence: {message}; seed={seed:#018x}; step={step}; shortest_prefix={trace:#?}"
    )
}

fn make_token_entry() -> (ProgramEntry, u64) {
    let issuer = (spend_auth_generator() * pasta_curves::pallas::Scalar::from(77)).to_bytes();
    let max_supply = 10_000;
    let manifest = TokenIssuancePolicy {
        issuer,
        max_supply,
        metadata: b"symbol=MODEL".to_vec(),
    }
    .encode()
    .unwrap();
    // The differential target is the state machine, not key generation or proof verification. Build
    // the same canonical issuance-policy registry shape with a deterministic nonempty test
    // descriptor so debug campaigns do not regenerate every token circuit verifying key.
    let mut registry_manifest = TOKEN_MANIFEST_PREFIX.to_vec();
    registry_manifest.extend_from_slice(&(DEPTH as u64).to_le_bytes());
    registry_manifest.extend_from_slice(&14u32.to_le_bytes());
    registry_manifest.extend_from_slice(&manifest);
    (
        ProgramEntry {
            manifest: registry_manifest,
            backend: TOKEN_PROGRAM_BACKEND.to_owned(),
            activation_height: 1,
            deactivation_height: None,
            functions: vec![ProgramFunction {
                function_id: issuance_function_id(1).unwrap(),
                verifying_key: b"state-model-issuance-vk".to_vec(),
                public_input_schema_hash: issuance_schema_hash(DEPTH, 1).unwrap(),
                max_cost: 140_000,
            }],
        },
        max_supply,
    )
}

fn deploy(
    campaign: &mut Campaign,
    entry: &ProgramEntry,
    height: u64,
    seed: u64,
    step: usize,
    operation: Operation,
) {
    let spend = campaign.next_id();
    let output = campaign.next_id() + 10_000;
    let funding = transaction(
        campaign.reference.root(),
        Some(spend),
        output,
        1,
        height + 100,
    );
    let before = campaign.production.encode_snapshot();
    let production =
        campaign
            .production
            .apply_program_deployment(&funding, entry.clone(), 4_096, height);
    let reference = campaign
        .reference
        .apply_deployment(&funding, entry, 4_096, height);
    campaign.trace.push(operation);
    if production.is_ok() != reference.is_ok() {
        fail(
            seed,
            step,
            &campaign.trace,
            "deployment acceptance mismatch",
        );
    }
    if production.is_ok() {
        campaign.record_success();
    } else if step <= 5 {
        fail(
            seed,
            step,
            &campaign.trace,
            "required deployment prelude was rejected",
        );
    } else if campaign.production.encode_snapshot() != before {
        fail(
            seed,
            step,
            &campaign.trace,
            "rejected deployment mutated state",
        );
    }
}

fn run_campaign(
    seed: u64,
    token_entry: &ProgramEntry,
    token_max_supply: u64,
    nft_entry: &ProgramEntry,
) {
    let token_id = token_entry.id().unwrap();
    let nft_id = nft_entry.id().unwrap();
    let mut rng = Rng(seed.max(1));
    let mut campaign = Campaign::new();

    let steps = std::env::var("ONYX_STATE_MODEL_STEPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(74)
        .max(10);
    let injected_failure_step = std::env::var("ONYX_STATE_MODEL_TEST_FAIL_STEP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    for step in 0..steps {
        let next_height = campaign.reference.current_height + 1;
        // A fixed state-aware prelude guarantees every transition family, reopen, rejection, undo,
        // and fork is exercised before seeded exploration begins.
        let choice = match step {
            0 => 0,  // bridge funds the native supply
            1 => 2,  // token deployment
            2 => 3,  // standard-program deployment
            3 => 4,  // token issuance
            4 => 5,  // contextual standard-program call
            5 => 0,  // ordinary fee-bearing transfer
            6 => 10, // canonical snapshot reopen
            7 => 6,  // atomic duplicate rejection
            8 => 8,  // undo
            9 => 9,  // fork from an earlier checkpoint
            _ => rng.below(12),
        };
        match choice {
            0 | 1 if campaign.reference.circulating_supply < 32 => {
                let amount = 100 + (rng.next() % 100);
                let fee = 1 + (rng.next() % 3);
                let key_image = Fp::from(campaign.next_id()).to_repr();
                let output = campaign.next_id() + 20_000;
                let tx = transaction(
                    campaign.reference.root(),
                    None,
                    output,
                    0,
                    next_height + 100,
                );
                let operation = Operation::Bridge {
                    height: next_height,
                    amount,
                    fee,
                };
                let before = campaign.production.encode_snapshot();
                let production =
                    campaign
                        .production
                        .apply_bridge(&tx, key_image, amount, fee, next_height);
                let reference =
                    campaign
                        .reference
                        .apply_bridge(&tx, key_image, amount, fee, next_height);
                campaign.trace.push(operation);
                if production.is_ok() != reference.is_ok() {
                    fail(seed, step, &campaign.trace, "bridge acceptance mismatch");
                }
                if production.is_ok() {
                    campaign.record_success();
                } else if step <= 5 {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "required bridge prelude was rejected",
                    );
                } else if campaign.production.encode_snapshot() != before {
                    fail(seed, step, &campaign.trace, "rejected bridge mutated state");
                }
            }
            0 | 1 => {
                let fee = 1 + (rng.next() % 3);
                let spend = campaign.next_id();
                let output = campaign.next_id() + 30_000;
                let tx = transaction(
                    campaign.reference.root(),
                    Some(spend),
                    output,
                    fee,
                    next_height + 100,
                );
                let before = campaign.production.encode_snapshot();
                let production = campaign.production.apply_transfer(&tx, next_height);
                let reference = campaign.reference.apply_transfer(&tx, next_height);
                campaign.trace.push(Operation::Transfer {
                    height: next_height,
                    fee,
                });
                if production.is_ok() != reference.is_ok() {
                    fail(seed, step, &campaign.trace, "transfer acceptance mismatch");
                }
                if production.is_ok() {
                    campaign.record_success();
                } else if step <= 5 {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "required transfer prelude was rejected",
                    );
                } else if campaign.production.encode_snapshot() != before {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "rejected transfer mutated state",
                    );
                }
            }
            2 if !campaign.reference.programs.contains_key(&token_id) => deploy(
                &mut campaign,
                token_entry,
                next_height,
                seed,
                step,
                Operation::DeployToken {
                    height: next_height,
                },
            ),
            3 if !campaign.reference.programs.contains_key(&nft_id) => deploy(
                &mut campaign,
                nft_entry,
                next_height,
                seed,
                step,
                Operation::DeployNft {
                    height: next_height,
                },
            ),
            4 if campaign.reference.programs.contains_key(&token_id) => {
                let current = campaign
                    .reference
                    .issuance
                    .get(&token_id)
                    .copied()
                    .unwrap_or_default();
                let amount = 1 + (rng.next() % 20);
                if current.issued_supply + amount > token_max_supply {
                    continue;
                }
                let output = campaign.next_id() + 40_000;
                let mut tx = transaction(
                    campaign.reference.root(),
                    None,
                    output,
                    0,
                    next_height + 100,
                );
                tx.programs.push(ProgramCall {
                    program_id: token_id,
                    function_id: issuance_function_id(1).unwrap(),
                    public_data_hash: issuance_public_data_hash(current.next_sequence, amount),
                });
                let before = campaign.production.encode_snapshot();
                let production = campaign.production.apply_token_issuance(
                    &tx,
                    current.next_sequence,
                    amount,
                    next_height,
                );
                let reference = campaign.reference.apply_issuance(
                    &tx,
                    token_id,
                    current.next_sequence,
                    amount,
                    token_max_supply,
                    next_height,
                );
                campaign.trace.push(Operation::Issue {
                    height: next_height,
                    sequence: current.next_sequence,
                    amount,
                });
                if production.is_ok() != reference.is_ok() {
                    fail(seed, step, &campaign.trace, "issuance acceptance mismatch");
                }
                if production.is_ok() {
                    campaign.record_success();
                } else if step <= 5 {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "required issuance prelude was rejected",
                    );
                } else if campaign.production.encode_snapshot() != before {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "rejected issuance mutated state",
                    );
                }
            }
            5 if campaign.reference.programs.contains_key(&nft_id) => {
                let nonce = campaign.next_id();
                let application = StandardApplication::Nft {
                    collection_id: [1; 32],
                    token_id: [2; 32],
                    serial: 7,
                    transfer_nonce: nonce,
                };
                let state_key = application.state_key(&nft_id).unwrap();
                let prior = campaign
                    .reference
                    .program_states
                    .get(&state_key)
                    .copied()
                    .unwrap_or(field(50_000));
                let next_value = field(campaign.next_id() + 50_001);
                let spend = campaign.next_id();
                let output = campaign.next_id() + 60_000;
                let mut tx = transaction(
                    campaign.reference.root(),
                    Some(spend),
                    output,
                    1,
                    next_height + 100,
                );
                tx.programs.push(ProgramCall {
                    program_id: nft_id,
                    function_id: STANDARD_FUNCTION_ID,
                    public_data_hash: [0; 32],
                });
                let context = ProgramContext::from_transaction(
                    &tx,
                    0,
                    next_height,
                    Some(ProgramStateTransition {
                        prior: prior.bytes(),
                        next: next_value.bytes(),
                    }),
                    application.encode().unwrap(),
                )
                .unwrap();
                tx.programs[0].public_data_hash = context.hash().unwrap();
                let before = campaign.production.encode_snapshot();
                let production =
                    campaign
                        .production
                        .apply_contextual_transaction(&tx, next_height, &[context]);
                let reference = campaign.reference.apply_contextual(
                    &tx,
                    &application,
                    prior,
                    next_value,
                    next_height,
                );
                campaign.trace.push(Operation::NftCall {
                    height: next_height,
                    nonce,
                });
                if production.is_ok() != reference.is_ok() {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "contextual call acceptance mismatch",
                    );
                }
                if production.is_ok() {
                    campaign.record_success();
                } else if step <= 5 {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "required contextual-call prelude was rejected",
                    );
                } else if campaign.production.encode_snapshot() != before {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "rejected contextual call mutated state",
                    );
                }
            }
            6 if !campaign.reference.nullifiers.is_empty() => {
                let duplicate = *campaign.reference.nullifiers.iter().next().unwrap();
                if CanonicalField::from_bytes(duplicate).is_none() {
                    continue;
                }
                let mut tx = transaction(
                    campaign.reference.root(),
                    None,
                    campaign.next_id() + 70_000,
                    1,
                    next_height + 100,
                );
                tx.spends.push(PublicSpend {
                    nullifier: Nullifier(duplicate),
                    value_commitment: crate::value_commitment_circuit::value_commitment_bytes(
                        1,
                        Fp::from(2),
                    ),
                    randomized_key: [20; 32],
                });
                let before = campaign.production.encode_snapshot();
                let production = campaign.production.apply_transfer(&tx, next_height);
                let reference = campaign.reference.apply_transfer(&tx, next_height);
                campaign.trace.push(Operation::RejectDuplicate {
                    height: next_height,
                });
                if production.is_ok()
                    || reference.is_ok()
                    || campaign.production.encode_snapshot() != before
                {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "duplicate rejection was not atomic",
                    );
                }
            }
            7 => {
                let Some(stale) = campaign
                    .all_roots
                    .iter()
                    .copied()
                    .find(|root| !campaign.reference.knows_anchor(*root))
                else {
                    continue;
                };
                let tx = transaction(
                    stale,
                    Some(campaign.next_id()),
                    campaign.next_id() + 80_000,
                    1,
                    next_height + 100,
                );
                let before = campaign.production.encode_snapshot();
                let production = campaign.production.apply_transfer(&tx, next_height);
                let reference = campaign.reference.apply_transfer(&tx, next_height);
                campaign.trace.push(Operation::RejectStaleAnchor {
                    height: next_height,
                });
                if production.is_ok()
                    || reference.is_ok()
                    || campaign.production.encode_snapshot() != before
                {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "stale-anchor rejection was not atomic",
                    );
                }
            }
            8 if campaign.history.len() > 1 => {
                let checkpoint = campaign.history.len() - 2;
                campaign.restore(checkpoint);
                campaign.trace.push(Operation::Undo { checkpoint });
            }
            9 if campaign.history.len() > 2 => {
                let checkpoint = rng.below(campaign.history.len() - 1);
                campaign.restore(checkpoint);
                campaign.trace.push(Operation::Fork { checkpoint });
            }
            10 => {
                let snapshot = campaign.production.encode_snapshot();
                campaign.production = ShieldedState::decode_snapshot(&snapshot).unwrap();
                campaign.trace.push(Operation::Reopen);
                for length in [0, 1, snapshot.len() / 2, snapshot.len() - 1] {
                    if ShieldedState::<DEPTH>::decode_snapshot(&snapshot[..length]).is_ok() {
                        fail(
                            seed,
                            step,
                            &campaign.trace,
                            "truncated snapshot was accepted",
                        );
                    }
                }
            }
            11 if campaign.reference.programs.contains_key(&nft_id)
                && !campaign.reference.program_states.is_empty() =>
            {
                let nonce = campaign.next_id();
                let application = StandardApplication::Nft {
                    collection_id: [1; 32],
                    token_id: [2; 32],
                    serial: 7,
                    transfer_nonce: nonce,
                };
                let next_value = field(campaign.next_id() + 90_000);
                let bad_prior = field(campaign.next_id() + 91_000);
                let mut tx = transaction(
                    campaign.reference.root(),
                    Some(campaign.next_id()),
                    campaign.next_id() + 92_000,
                    1,
                    next_height + 100,
                );
                tx.programs.push(ProgramCall {
                    program_id: nft_id,
                    function_id: STANDARD_FUNCTION_ID,
                    public_data_hash: [0; 32],
                });
                let context = ProgramContext::from_transaction(
                    &tx,
                    0,
                    next_height,
                    Some(ProgramStateTransition {
                        prior: bad_prior.bytes(),
                        next: next_value.bytes(),
                    }),
                    application.encode().unwrap(),
                )
                .unwrap();
                tx.programs[0].public_data_hash = context.hash().unwrap();
                let before = campaign.production.encode_snapshot();
                let production =
                    campaign
                        .production
                        .apply_contextual_transaction(&tx, next_height, &[context]);
                let reference = campaign.reference.apply_contextual(
                    &tx,
                    &application,
                    bad_prior,
                    next_value,
                    next_height,
                );
                campaign.trace.push(Operation::RejectProgramFork {
                    height: next_height,
                });
                if production.is_ok()
                    || reference.is_ok()
                    || campaign.production.encode_snapshot() != before
                {
                    fail(
                        seed,
                        step,
                        &campaign.trace,
                        "program-fork rejection was not atomic",
                    );
                }
            }
            _ => continue,
        }
        campaign.check(seed, step);
        if injected_failure_step == Some(step) {
            fail(
                seed,
                step,
                &campaign.trace,
                "injected qualification failure",
            );
        }
    }
    let required = [
        (
            "bridge",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::Bridge { .. })),
        ),
        (
            "transfer",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::Transfer { .. })),
        ),
        (
            "deployment",
            campaign.trace.iter().any(|op| {
                matches!(
                    op,
                    Operation::DeployToken { .. } | Operation::DeployNft { .. }
                )
            }),
        ),
        (
            "issuance",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::Issue { .. })),
        ),
        (
            "contextual program call",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::NftCall { .. })),
        ),
        (
            "undo/fork",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::Undo { .. } | Operation::Fork { .. })),
        ),
        (
            "snapshot reopen",
            campaign
                .trace
                .iter()
                .any(|op| matches!(op, Operation::Reopen)),
        ),
        (
            "atomic rejection",
            campaign.trace.iter().any(|op| {
                matches!(
                    op,
                    Operation::RejectDuplicate { .. }
                        | Operation::RejectStaleAnchor { .. }
                        | Operation::RejectProgramFork { .. }
                )
            }),
        ),
    ];
    for (name, covered) in required {
        if !covered {
            fail(
                seed,
                steps,
                &campaign.trace,
                &format!("deterministic seed did not cover {name}"),
            );
        }
    }
    let operation_count = |predicate: fn(&Operation) -> bool| {
        campaign
            .trace
            .iter()
            .filter(|operation| predicate(operation))
            .count()
    };
    let root = campaign.reference.root().bytes();
    let root_hex = root
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!(
        "ONYX_STATE_MODEL_RESULT seed=0x{seed:016x} requested_steps={steps} trace_steps={} checkpoints={} snapshot_bytes={} root={} bridge={} transfer={} deployment={} issuance={} contextual={} rejection={} undo={} fork={} reopen={}",
        campaign.trace.len(),
        campaign.successful_checkpoints,
        campaign.production.encode_snapshot().len(),
        root_hex,
        operation_count(|op| matches!(op, Operation::Bridge { .. })),
        operation_count(|op| matches!(op, Operation::Transfer { .. })),
        operation_count(|op| matches!(op, Operation::DeployToken { .. } | Operation::DeployNft { .. })),
        operation_count(|op| matches!(op, Operation::Issue { .. })),
        operation_count(|op| matches!(op, Operation::NftCall { .. })),
        operation_count(|op| matches!(op, Operation::RejectDuplicate { .. } | Operation::RejectStaleAnchor { .. } | Operation::RejectProgramFork { .. })),
        operation_count(|op| matches!(op, Operation::Undo { .. })),
        operation_count(|op| matches!(op, Operation::Fork { .. })),
        operation_count(|op| matches!(op, Operation::Reopen)),
    );
}

#[test]
fn deterministic_state_model_apply_undo_fork_reopen_campaign() {
    let (token_entry, token_max_supply) = make_token_entry();
    let nft_entry = standard_program_entry(StandardProgramKind::Nft, 1, None).unwrap();
    let configured_seed = std::env::var("ONYX_STATE_MODEL_SEED")
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim_start_matches("0x"), 16).ok());
    let seeds: Vec<u64> = configured_seed.map_or_else(
        || vec![0x0123_4567_89ab_cdef, 0x9e37_79b9_7f4a_7c15],
        |seed| vec![seed],
    );
    for seed in seeds {
        run_campaign(seed, &token_entry, token_max_supply, &nft_entry);
    }
}

#[test]
fn current_snapshot_rejects_prefixes_and_single_byte_corruption() {
    let mut state = ShieldedState::<DEPTH>::new(ANCHOR_WINDOW);
    let tx = transaction(state.root(), None, 7, 0, 100);
    state.apply_bridge(&tx, [7; 32], 100, 3, 1).unwrap();
    let snapshot = state.encode_snapshot();
    for length in 0..snapshot.len() {
        assert!(
            ShieldedState::<DEPTH>::decode_snapshot(&snapshot[..length]).is_err(),
            "accepted partial snapshot length {length}/{}",
            snapshot.len()
        );
    }
    let mut corrupt_supply = snapshot.clone();
    let accounting = corrupt_supply
        .windows(3)
        .position(|bytes| bytes == [100, 3, 97])
        .expect("small canonical accounting varints");
    corrupt_supply[accounting + 2] ^= 1;
    assert_eq!(
        ShieldedState::<DEPTH>::decode_snapshot(&corrupt_supply).err(),
        Some(SnapshotError::InvalidSupply)
    );
}
