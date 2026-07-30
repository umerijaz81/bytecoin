# Consensus and privacy incident response

This runbook defines coordination and evidence requirements; it does not grant any operator a hidden
administrative key, unilateral rollback power, or authority to rewrite an accepted chain. A real drill
with named responders and timestamps is required before activation.

## Severity and immediate actions

- **Critical:** unauthorized inflation, accepted invalid proof/signature, nullifier/key-image replay,
  consensus split, release-key compromise, or practical recovery of spend secrets. Stop release and
  activation work, preserve evidence, notify maintainers/auditors privately, and prepare a narrowly
  reviewed fix. Operators may stop their own nodes; no software-controlled global halt exists.
- **High:** deterministic crash/resource exhaustion across honest nodes, wallet loss/corruption,
  material privacy deanonymization, or supply-audit divergence. Disable affected optional services,
  preserve logs without publishing wallet/peer secrets, and reproduce on an isolated network.
- **Medium/Low:** bounded availability, metadata or tooling defects without consensus or secret loss.
  Track normally while retaining enough evidence to prove the classification.

For every incident, record the first observed block/hash, software commit and release checksum,
network, peer topology if relevant, exact RPC/input bytes, local state/snapshot hashes, expected versus
observed supply counters, and who handled each artifact. Never copy wallet seeds, spend keys, plaintext
notes, source IP archives or private audit material into a public issue.

## Activation and rollback boundary

Before activation, rollback means reverting the candidate code/configuration, restoring the recorded
pre-test snapshot, replaying the chain, and reconciling `get_onyx_supply_audit`; placeholder mainnet
heights remain unchanged. After a consensus version has activated, silently rolling back database
state or accepting the old rules creates a fork and is prohibited. Recovery requires a publicly
specified forward consensus change (or explicit coordinated chain choice), independent review,
reproduction from the last agreed block, and governance approval. Checkpoints may document a chosen
history but must never be represented as cryptographic proof that it is correct.

For an Onyx reorg or migration failure:

1. stop transaction submission and proving on the affected deployment;
2. preserve the current database, Onyx snapshot, undo records and block binaries read-only;
3. reproduce apply/undo from the last agreed ancestor using the exact release artifact;
4. compare note-tree roots, anchors, nullifiers, program registry, bridge totals, fees and circulating
   supply at every height;
5. test the proposed fix against the preserved divergent branches and adversarial variants;
6. publish a redacted reconciliation and obtain the same audit/governance approvals as other
   consensus changes.

## Compromise-specific handling

- **Release/signing key:** revoke/rotate it through the documented trust channel, mark affected
  artifacts untrusted, compare their hashes with independently reproduced builds, and do not reuse the
  compromised key to announce its own replacement.
- **ZK proving key or circuit defect:** proving keys are not consensus authority. Freeze the affected
  circuit/backend, identify every accepted proof under the exact verifier key, and treat a soundness
  failure as critical. Parameter replacement requires a versioned hard fork.
- **Wallet/viewing key:** notify affected owners without exposing the key; viewing-key compromise is a
  privacy incident, while spend-key compromise requires owners to migrate funds using reviewed tools.
- **Proxy/Dandelion leak:** preserve topology and packet evidence privately, disable the faulty path,
  and never claim that transport privacy protected already exposed metadata.

## Drill exit criteria

The `incident-response-drill` activation gate can pass only when evidence records detection, triage,
decision authority, preserved artifacts, a clean-room reproduction, migration/supply reconciliation,
communications, recovery time, unresolved actions and independent observer sign-off. Merely linking
this runbook is implementation evidence, not a passed drill.

The typed attestation records an ordered `started_at`/`completed_at` window, at least two distinct
`participant_ids`, at least one distinct entry in `observer_ids` that is not a participant,
`decision_authority`, `communications_recorded`,
`migration_supply_reconciled`, and an `unresolved_actions` array. Its `scenarios` array contains
exactly one structured result for `consensus-stall`, `reorg`, and `proof-dos`. Each result binds
ordered `detected_at`, `triaged_at`, and `recovered_at` timestamps and sets `artifacts_preserved`,
`clean_room_reproduced`, and `recovery_verified` only after those actions have been demonstrated.
The drill cannot begin before the frozen release revision exists.
