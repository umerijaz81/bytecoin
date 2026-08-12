# Onyx deterministic state-model qualification

## Purpose and assurance boundary

`vendor/onyx-zk/src/state_model_tests.rs` compares the production `ShieldedState` implementation
with an independent in-test reference ledger across generated apply, rejection, undo, fork, and
snapshot-reopen sequences. `tools/onyx/state_model_campaign.py` turns that test into a retained,
revision-bound multi-seed campaign.

This is deterministic differential regression evidence. It is not a proof of correctness, an
independent consensus audit, a production database crash simulation, or release evidence. Reports
therefore carry scope `deterministic-local-or-ci-not-release-evidence`.

## State and operation coverage

The reference ledger does not call the production transition helpers. After every generated step,
the test compares:

- commitment count and Poseidon root;
- retained anchors and nullifiers;
- height, bridged amount, fees, and native circulating supply;
- program identifiers, functions, costs, activation, and state;
- token issuance supply, sequence, cap, and mintability;
- canonical snapshot bytes after encode/decode/reopen.

Every campaign begins with a fixed prelude so a passing seed covers bridge, private transfer, token
and NFT deployment, issuance, contextual NFT state, rejection, undo/fork, and reopen behavior.
Seeded exploration then generates additional operations. Rejections must agree in both models and
leave the production snapshot byte-for-byte unchanged. Failures print the seed, step, and generated
operation prefix.

## Retained campaign runner

Run the default qualification from the repository root:

```text
python tools/onyx/state_model_campaign.py \
  --steps 2000 \
  --revision <full-commit> \
  --report build/onyx-qualification/state-model.json
```

The runner invokes the exact Rust test with `cargo test --release --locked --offline`, one seed at a
time and one test thread at a time. Its eight default 64-bit seeds are explicit in the script. Use a
repeated `--seed 0x...` argument to replay or narrow a campaign, and
`--timeout-per-seed <seconds>` to change the default 900-second per-seed ceiling.

The JSON schema is `bytecoin-onyx-state-model-campaign-v1`. It records the requested revision,
manifest and lockfile SHA-256 identities, seeds, step count, elapsed time, command result, captured
output digest, final root and snapshot size, successful checkpoint count, trace length, and count of
each required operation family. The runner rejects a missing/duplicate summary, identity mismatch,
noncanonical root, empty operation family, invalid trace length, empty snapshot, or failed process.
It writes the report atomically after every seed. On failure it also retains the complete combined
Cargo/test output in `state-model-seed-<hex>.log` and records that file's digest.

The scheduled `Onyx sustained qualification` workflow runs all eight seeds at 2,000 requested
iterations each and retains the report (and any failure log) for 90 days, keyed by Git revision.

## Local baseline from 2026-08-12

The first full Windows working-tree run passed:

- 8 of 8 seeds;
- 16,000 requested iterations;
- 11,333 recorded trace operations;
- 608 to 686 successful checkpoints per seed;
- every required operation family nonzero for every seed;
- approximately 183 seconds total including a one-time optimized rebuild;
- approximately 7 to 9 seconds per seed after the build.

The local report used revision label `working-tree-state-model`; it is useful regression evidence but
is deliberately not committed as release evidence. CI reports must use `${{ github.sha }}`.

## Snapshot decoder boundary checks

`state::tests::snapshot_rejects_limit_plus_one_counts_before_allocation` mutates a minimal canonical
version-7 snapshot so its anchor, nullifier, and program-state counts are one greater than their
configured maxima. Each mutation must fail in the count decoder before an attacker-controlled
allocation or element loop begins. Existing tests also reject every truncated prefix and selected
canonical-field corruption.

This does not yet prove that maximum accepted snapshots fit production memory/time budgets, nor does
it cover corrupt SQLite/WAL images or arbitrary coverage-guided mutations.

## Continuation tasks

For the next implementation milestone:

1. Add a minimizer that consumes a failing generated prefix and emits the smallest replayable
   operation sequence; retain both original and minimized digests.
2. Add peak RSS, CPU-time, and output-size ceilings to the campaign report and fail CI on documented
   regressions.
3. Generate valid snapshots at each exact configured maximum and measure decode/reopen resources on
   named hardware. Do not create million-entry fixtures in ordinary unit-test CI.
4. Add coverage-guided snapshot and database-image fuzz targets, including count encodings, ordering,
   duplicates, canonical fields, truncation, trailing bytes, WAL/checkpoint interruption, and partial
   writes.
5. Run identical immutable-revision campaigns on clean Linux, macOS, and Windows hosts and compare
   roots and operation summaries.
6. Extend the full-daemon crash harness across multi-transaction blocks, transfers, issuance,
   deployment rollback, repeated failures, disk-full/I/O faults, and OS flush/power-loss boundaries.
7. Submit the reference-model assumptions and production state transition to an independent
   consensus and cryptographic review.

Do not describe O1 as release-complete until those external and resource-bound gates are satisfied.
