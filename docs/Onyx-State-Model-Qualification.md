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
  --timeout-per-seed 180 \
  --max-seed-cpu-seconds 120 \
  --max-seed-rss-mib 1024 \
  --max-seed-output-mib 2 \
  --revision <full-commit> \
  --report build/onyx-qualification/state-model.json
```

The runner first performs one `cargo test --release --locked --offline --no-run` build, parses Cargo's
JSON artifact stream, requires exactly one Onyx library test executable, and records that executable's
SHA-256. It then invokes the exact Rust test binary for each seed, one test thread at a time. This
separates build resources from campaign resources. Its eight default 64-bit seeds are explicit in the
script. Use a repeated `--seed 0x...` argument to replay or narrow a campaign.

The JSON schema is `bytecoin-onyx-state-model-campaign-v2`. In addition to revision, manifest,
lockfile, executable, output, root, checkpoint, trace, and operation identities, it records platform,
logical CPU count, wall time, sampled CPU time, peak RSS, sample count, and output bytes per seed.
`--timeout-per-seed`, `--max-seed-cpu-seconds`, `--max-seed-rss-mib`, and
`--max-seed-output-mib` are independently enforced. Missing process samples also fail the campaign.

The runner rejects a missing/duplicate summary, identity mismatch, noncanonical root, empty operation
family, invalid trace length, empty snapshot, failed process, timeout, or resource-limit violation. It
writes the report atomically after the build and every seed. On failure it retains the complete test
output in `state-model-seed-<hex>.log` and records that file's digest. Build failures similarly retain
`state-model-build.log`.

When output contains exactly one state-model divergence, the runner derives the smallest possible
requested prefix as `failing step + 1` (subject to the test's ten-step minimum), reruns it, and reruns
the immediately shorter prefix. It reports minimality only if the candidate reproduces the exact
message/seed/step tuple and its predecessor does not. The candidate's full replayable operation trace
is retained in `state-model-seed-<hex>-minimized.log` with a SHA-256 identity. A test-only environment
hook, `ONYX_STATE_MODEL_TEST_FAIL_STEP`, exists solely in the Rust test module to qualify this path.

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

The v2 resource-bound repeat passed the same 16,000 iterations and 11,333 operations with these
maximum per-seed observations on the named local platform in the JSON report:

- 7.61 seconds wall time;
- 7.640625 seconds sampled CPU time;
- 5,832,704 bytes peak RSS;
- 504 output bytes.

An injected step-37 divergence from a 100-step request reproduced at 38 requested steps and did not
reproduce at 37, proving the minimizer and both artifact digests end to end. A separate 1 MiB RSS
ceiling probe failed closed while preserving its successful semantic summary and failed resource
check.

The local report used revision label `working-tree-state-model`; it is useful regression evidence but
is deliberately not committed as release evidence. CI reports must use `${{ github.sha }}`.

## Snapshot decoder boundary checks

`state::tests::snapshot_rejects_limit_plus_one_counts_before_allocation` mutates a minimal canonical
version-7 snapshot so its anchor, nullifier, and program-state counts are one greater than their
configured maxima. Each mutation must fail in the count decoder before an attacker-controlled
allocation or element loop begins. Existing tests also reject every truncated prefix and selected
canonical-field corruption.

`state::tests::snapshot_accepts_exact_configured_collection_limit` is an ignored, opt-in test that
directly constructs valid current-version snapshots at each exact one-million-entry limit. Each case
decodes the snapshot, verifies the resulting collection count, canonical re-encodes it, and requires
byte-for-byte equality. The cases run separately so anchors, nullifiers, and program states do not
artificially multiply one another's peak memory.

Run all exact-limit cases with retained resource evidence:

```text
python tools/onyx/snapshot_limit_campaign.py \
  --timeout-per-case 180 \
  --sample-interval 0.02 \
  --max-case-cpu-seconds 60 \
  --max-case-rss-mib 1024 \
  --max-case-output-mib 2 \
  --revision <full-commit> \
  --report build/onyx-qualification/snapshot-limit.json
```

Schema `bytecoin-onyx-snapshot-limit-campaign-v1` binds the platform, revision, manifest, lockfile,
test executable, per-case output and resource observations. The weekly workflow retains it beside the
state-model report. The 2026-08-12 local Windows run passed:

| Collection | Count | Snapshot bytes | Wall seconds | CPU seconds | Peak RSS bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| anchors | 1,000,000 | 34,983,512 | 0.140 | 0.109375 | 73,945,088 |
| nullifiers | 1,000,000 | 32,000,053 | 0.266 | 0.250000 | 184,213,504 |
| program states | 1,000,000 | 64,000,053 | 0.594 | 0.593750 | 285,687,808 |

These figures are local sampled regression evidence, not portable release limits. The fixtures prove
the configured counts are accepted and canonical on this implementation. They do not cover a single
snapshot containing all maxima simultaneously, corrupt SQLite/WAL images, arbitrary coverage-guided
mutations, or named-hardware production database reopen behavior.

## Structured snapshot corruption campaign

`state::tests::snapshot_structured_corruption_campaign` starts from four canonical version-7
snapshots: empty state and nonempty anchor, nullifier, and program-state collections. Before seeded
exploration it requires exact failure classes for nonminimal and overflowing varints, adjacent
duplicate anchors, duplicate/out-of-order nullifiers, duplicate/out-of-order program-state keys, and
a noncanonical program-state field.

Seeded cases then perform bounded bit flips, byte overwrites, truncation, trailing-byte insertion,
slice deletion, slice insertion, `0xff` range overwrites, and 32-byte segment copies. Every mutation
must satisfy one of two outcomes:

- decoding rejects it; or
- decoding succeeds, canonical re-encoding succeeds, reopening succeeds, and a current-version input
  is byte-for-byte identical to the canonical encoding.

This rejects silent acceptance of nonminimal current-version encodings while allowing explicit
legacy-version migration to stabilize after one current-version encode. Inputs remain below 1 MiB.

Run the retained four-seed campaign:

```text
python tools/onyx/snapshot_corruption_campaign.py \
  --cases 20000 \
  --timeout-per-seed 180 \
  --max-seed-cpu-seconds 150 \
  --max-seed-rss-mib 1024 \
  --max-seed-output-mib 2 \
  --revision <full-commit> \
  --report build/onyx-qualification/snapshot-corruption.json
```

Schema `bytecoin-onyx-snapshot-corruption-campaign-v1` binds revision, manifest, lockfile, executable,
seed, case count, classifications, output digest, platform, and sampled resources. The 2026-08-12
local Windows campaign passed 80,000 cases: 65,706 rejected and 14,294 accepted as canonical current
snapshots. Maximum per-seed observations were 19.234 wall seconds, 19.21875 CPU seconds, 5,763,072
peak RSS bytes, 338 output bytes, and 1,083 input bytes. Weekly CI retains the report and any full
failure log.

This is structured deterministic mutation evidence, not coverage-guided fuzzing. A separate
production-adapter campaign now mutates small SQLite database and rollback-journal images, and a
second campaign covers deterministic WAL and checkpoint-bundle combinations. None proves arbitrary
parser coverage, real checkpoint interruption, torn-write or power-loss behavior, or sanitizer
cleanliness.

## Production SQLite corruption boundary

`tests/network/test_onyx_db_corruption_process.py` creates committed and hot-journal fixtures through
the native production adapter and applies 15 deterministic database/journal mutations. Its exact
state oracle distinguishes fail-closed adapter errors from readable-but-corrupt Onyx state, while an
independent SQLite reader runs `PRAGMA integrity_check` and compares raw rows. The retained report
binds the executable, revision, source/result image sizes and SHA-256 digests, classifications, and
scope. The 2026-08-12 Windows run passed with five adapter failures, seven exact rollback recoveries,
and three semantic mismatches detected before acceptance.

The campaign found and fixed an adapter gap: a corrupted schema name could remain readable through an
already resolved root page even though independent schema inspection rejected it. `DBsqliteKV` now
requires the exact canonical `kv_table` declaration on every open. This is useful corruption-boundary
regression evidence, but it is deliberately not power-loss, maximum-state, or release evidence.
Detailed invocation and case definitions are in `docs/Onyx-Qualification-Network.md`.

### WAL and checkpoint-bundle extension

The WAL campaign uses the production adapter to retain two committed frames, checkpoint a clone, and
exercise eleven WAL mutations plus four pre/post-checkpoint main/WAL/shared-memory combinations. The
local 15-case run produced five exact committed recoveries and ten semantic mismatches, all confirmed
by an independent raw-row/integrity oracle. It also verifies that database deletion removes stale
rollback-journal, WAL, and shared-memory sidecars. Schema `bytecoin-onyx-db-wal-campaign-v1` binds the
revision, executable, WAL geometry, source/output digests, classifications, timeouts, and report size
ceiling. This closes the bounded deterministic WAL-image gap; it does not close real power-loss,
filesystem ordering, in-checkpoint process termination, disk-fault, or coverage-guided gates.

### SQLite page-exhaustion extension

The disk-full campaign fixes `max_page_count` at the current two-page database size and attempts a
1 MiB state value either directly or after a small state write at the undo stage. Both native paths
must return `SQLITE_FULL` (primary code 13), and fresh production-adapter plus independent SQLite
oracles must recover the exact pre-transaction rows. The local run passed both fault cases and a
committed positive control in 0.203 seconds; failed database images were byte-identical before and
after. This safely qualifies SQLite page exhaustion in CI without consuming the host disk. It does
not inject journal-write/fsync errors, enforce real filesystem quotas, or emulate device removal.

### Test-only VFS I/O-fault extension

The compile-time qualification VFS forwards the platform VFS but fails exactly one journal/database/WAL
write or sync. Eight fault types across three fresh-image cycles require exact extended codes 778 or
1034 at their named state/commit stage, exactly one trigger, and exact old-state recovery through both
the production adapter and an independent SQLite reader. Partial-write cases first persist half of a
512-byte journal call or 4,096-byte database call. The final local campaign passed all 24 faults plus a
committed control in 2.157 seconds. Normal artifacts compile out the VFS and markers, which the
release-absence regression scans. This closes bounded repeated independent one-shot rollback-journal,
database, partial-write, and WAL write/sync injection; combined faults, arbitrary cut points, directory
sync, device behavior, and power loss remain.

## Continuation tasks

For the next implementation milestone:

1. Establish immutable-revision resource baselines on named Linux, macOS, and Windows hosts, then
   tighten the deliberately portable weekly ceilings where platform evidence supports it.
2. Repeat exact-limit snapshot cases on named release hardware and through production SQLite
   persistence/reopen, including a deliberately provisioned combined-maxima case outside ordinary CI.
3. Add coverage-guided and sanitizer-backed snapshot/database-image fuzz targets. Structured snapshot
   mutations now cover count encodings, ordering, duplicates, canonical fields, truncation, trailing
   bytes, and bounded splices. Deterministic small SQLite and rollback-journal mutations are covered;
   Real in-checkpoint interruption, arbitrary torn writes, storage ordering, and coverage evidence
   remain after the deterministic WAL/checkpoint-bundle campaign.
4. Run identical immutable-revision campaigns on clean Linux, macOS, and Windows hosts and compare
   roots and operation summaries.
5. Extend the full-daemon crash harness across multi-transaction blocks, transfers, issuance,
   deployment rollback, repeated failures, real filesystem quota exhaustion, partial/repeated/WAL I/O
   combined/arbitrary-cut/directory-sync faults, and OS flush/power-loss boundaries. Bounded SQLite
   page exhaustion and repeated independent one-shot rollback-journal/database/WAL write/sync faults
   are covered at the production adapter boundary.
6. Submit the reference-model assumptions and production state transition to an independent
   consensus and cryptographic review.

Do not describe O1 as release-complete until those external and resource-bound gates are satisfied.
