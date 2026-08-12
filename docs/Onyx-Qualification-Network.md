# Onyx qualification network

`--net=onyx` selects a fixed consensus network for public Onyx migration, proving, reorg, privacy and
recovery qualification. It is not an activation override for mainnet, stagenet or the existing
testnet.

The network has a distinct P2P UUID, genesis nonce, default ports and `_onyxnet` data directory.
Jade V5, RandomX, reserved V6 and Onyx V7 are co-scheduled at height 1, so the first post-genesis
block uses the same direct V4-to-V7 policy intended for release. RandomX uses the genesis block as
its delayed seed ancestor until the normal lag is available. The fixed qualification block target is
one second and its minimum difficulty is deliberately low so deterministic process rehearsals do not
inherit mainnet's 120-second pacing or its fast-block retarget. Performance, throughput, power and
denial-of-service evidence must use separately documented native release parameters.

An `ONYX_ZK=OFF` binary refuses to join this network. There are no compiled-in seed nodes: operators
must publish and independently record the explicit `--seed-node-address` or
`--priority-node-address` topology used for the soak. The network identity and consensus schedule
cannot be changed by command-line flags.

The blockchain database retains its seven checkpoint-difficulty slots for format compatibility, but
all seven qualification-network checkpoint public keys are zero and cannot authorize a signed
checkpoint. Qualification nodes therefore do not inherit mainnet, stagenet or testnet checkpoint
authority. The shared checkpoint admission path rejects an empty public key before invoking signature
verification, which also fails closed for out-of-range key identifiers.

`tests/network/test_onyx_qualification_process.py` performs a bounded local rehearsal with real
ZK-enabled processes:

1. start three isolated qualification daemons and verify their fixed genesis;
2. create an encrypted legacy migration-source wallet, derive its network-bound Onyx identity, and
   mine three branch-B RandomX blocks to that wallet while mining a competing two-block branch A;
3. reconnect A and C to B, require a real reorganization onto B's longer branch, and require all three
   tips to converge;
4. compare the complete `get_onyx_supply_audit` response across all three nodes;
5. submit a truncated V7 transaction to each node, require the canonical invalid-binary error, and
   prove every daemon remains live;
6. prove the wallet recognizes the V7 coinbase rewards, back up its wallet/cache, rotate its password,
   reject the old password, and recover the same legacy address, Onyx address and balance through node C;
7. select a real recovered legacy output, construct and wallet-sign a one-way bridge, reject a
   tampered bridge, mine the valid migration, reconcile legacy/shielded balances and fees on every
   node, and reject reuse of the consumed output;
8. create a second independent encrypted wallet, transfer the migrated shielded value minus a fee,
   reject a tampered transfer and a pending double spend, mine the valid transaction, reconcile both
   wallet balances and supply on every node, and reject confirmed nullifier replay;
9. use that funded wallet to deploy the pinned NFT standard program, reject tampered and pending-
   duplicate deployments, mine the valid registry transition, reconcile the deployment fee and
   program count on every node, and reject confirmed deployment replay;
10. advance to the program's activation height, query the initially absent state, prove and propagate
   one real NFT state transition, and reject byte-tampered proof data;
11. construct a second valid proof whose mutable NFT nonce differs but whose stable state key is the
   same, require the competitor hash to remain absent while the original hash remains in the pool,
   mine the original call, and require identical state and supply on all three nodes;
12. reject confirmed call replay; deploy a capped token with separate native-funding and token-program
   circuit domains; reject tampered, duplicate, replayed, foreign-issuer, zero, and over-cap operations;
13. activate the token, issue 1000 units, transfer 400 units between independent wallets while paying
   a native fee, and reconcile exact token/native balances, registry state, commitments, and supply;
14. deploy and activate vesting, two-of-two multisig custody, and atomic-swap programs; reject early,
   under-threshold, wrong-preimage, and pending competing-branch operations; confirm the valid calls
   at heights 75, 76, and 77;
15. mine the height-78 refund boundary and wait for node C's exact durable SQLite commit before taking
   a transactionally consistent online backup;
16. confirm the timeout refund at height 79, reopen the height-78 backup as an isolated fork, mine a
   longer non-refund branch to height 80, and force all three primaries to roll back to it;
17. require exact restoration of program state, commitment root/count, supply audit, and transaction
   eligibility; reopen the receiver wallet through an alternate primary;
18. submit the identical refund binary to every daemon that lacks it, reconfirm it at height 81, and
   require exact node/wallet/state/audit convergence;
19. prove a testnet daemon cannot cross the network-identity/genesis boundary; and
20. optionally write a revision-bound JSON report containing every node's final height, hash, peer ID,
   supply-audit snapshot, rollback evidence, and nonsensitive wallet qualification results.

Example:

```sh
python3 tests/network/test_onyx_qualification_process.py \
  --bytecoind build/artifacts/bin/bytecoind \
  --minerd build/artifacts/bin/minerd \
  --walletd build/artifacts/bin/walletd \
  --revision "$(git rev-parse HEAD)" \
  --report build/onyx-local-qualification.json
```

The report schema marks itself `local-ci-not-release-evidence`. It is an automated regression artifact,
not an independent node/operator attestation. The consensus workflow runs the rehearsal on Ubuntu and
uploads the report for inspection. It separately runs the Jade invariant suite in both ZK-enabled and
non-ZK configurations; the latter must reject `--net=onyx`.

The native-transfer path uses its committed largest circuit domain `k=16` rather than the unrelated
general-program domain `k=20`. Each process caches Halo2 parameters and native-transfer proving or
verifying keys by the exact `(k, Merkle depth, spend count, output count)` shape. Per-shape first-use
serialization prevents concurrent cold requests from duplicating the same expensive key generation,
while different shapes do not hold one global generation lock. This is a bounded runtime optimization,
not a substitute for the still-required cold-start, parallel valid-proof, memory-pressure, and
denial-of-service qualification.

Program deployments and the four pinned stateful standard programs use their committed full-depth
domain `k=16`. The C ABI fixture proves both deployment funding and an NFT call at that domain. The
process rehearsal additionally proves a real NFT deployment through wallet RPC, mempool admission,
mining, registry application, wallet scanning, cross-node convergence and replay rejection. It then
mines to activation height 26 and proves a real stateful NFT call at height 27. The call scenario
requires exact transaction-hash propagation, tamper and confirmed-replay rejection, stable-state-key
conflict rejection for a different mutable nonce, canonical state-query convergence, and exact final
supply (`742000` bridged, `100002` fees, `641998` circulating, five commitments, one program).

Two RPC details are security-relevant for future qualification extensions. First, an absent
`get_onyx_standard_program_state` value is represented as `found=false` with an empty state string.
Second, `send_transaction.send_result` is deprecated and always says `broadcast`, even if mempool
admission returns false. Tests must establish admission using the exact transaction hash through
`get_raw_transaction` and, where useful, the transaction-pool count. `transaction_pool_version` is a
change counter and must not be treated as proof that a particular transaction is present.

The capped-token path is separated from the generic `k=20` domain in `db044e5`. Program
deployment now carries independent funding and program circuit parameters: native deployment funding
remains `k=16`, while the fixed token artifact, issuance, and mixed token/native-fee transfer use
`ONYX_TOKEN_CIRCUIT_K=14`. This is a capacity selection, not a reduction in curve security. A real
`k=20` deployment exceeded a 1,800-second wallet RPC deadline, and cold `k=16` verification also
approached or exceeded 30 minutes. The token constraint set fits at `k=14`; consensus tests pin that
relationship so future growth fails visibly.

The extended local harness deploys a capped token, waits for activation, issues to an independent
wallet, transfers part of the balance back while paying a native fee, and checks issuer, sequence,
cap, tamper, pending-conflict, replay, balance, registry, commitment, and native-supply invariants.
Deployment creation, verification, and wallet scanning all carry funding and program domains
separately. A one-domain scanner was caught because it accepted the height-28 chain tip but retained
the height-27 wallet balance; that scanner ABI has been split and its rebuilt ZK/Jade suites pass.
Pending duplicate construction also performs a cheap funding-note precheck before token artifact
construction.
Transfer verification and state application receive both native and token values and select one from
the authenticated backend id. This was added after deployment, activation, and issuance reached
height 49 but a mixed token/native-fee transfer built at token `k=14` was presented to the native
`k=16` verifier. The release-mode Rust proof/apply regression pins different values for the two
domains and passes.

The clean release-binary rehearsal exited zero and wrote
`build/codex-zk/onyx-private-token-qualification.json`, marked
`local-ci-not-release-evidence`. Deployment was mined at height 28, activation reached height 48,
issuance was mined at height 49, and the mixed transfer was mined at height 50. All three nodes ended
on `dde2b74470ed0d0a82cb6aeb45365f66594000f91e16b2048d6874de63dc4e11` with commitment root
`3e4c4f8a6f509942186fac0025db2d50fadd9e30ceafe0c0309aa338fcb9c221`, `742000` bridged,
`200003` fees, `541997` circulating native units, 11 commitments, two programs, and block program cost
`378000`. The token id is
`730901bd595a8732a5c85343b80b350f02baa3e7f2c928f4d4d7795c573d8b5e`; final token balances are 600
for the issuer and 400 for the recipient.

Eleven commitments are required. The mixed transfer creates three outputs: recipient token, issuer
token change, and issuer native change after the fee. An earlier functional run converged at height 50
but failed its report assertion because it expected 10; the audited 11-count assertion then passed in
a clean rerun.

Commit `3da16ad` extends the release-binary rehearsal through every remaining pinned stateful profile.
Vesting, multisig, and swap deployments were mined at heights 51, 52, and 53 and activated at 71, 72,
and 73. The harness rejected early vesting release and accepted release at 75; rejected a one-of-two
multisig witness and accepted two-of-two authorization at 76; rejected a wrong swap preimage, accepted
the claim and excluded a competing valid refund branch at 77; then rejected an early refund and
accepted the separate timeout refund at 79. Every valid transition required exact three-node state,
tip, commitment, program-count, fee, and circulating-supply equality plus wallet synchronization and
confirmed replay rejection.

The passing report is `build/codex-zk/onyx-standard-profiles-qualification.json`, marked
`local-ci-not-release-evidence`. Its final block is
`63e8b4f97fb494cd3dacbb82aeb9f188b728116f451b4bd41a937f5b937cbc83`; its commitment root is
`6d3606e4b912bb42f48205ed2401d1bf0483b542f036574ca8ca6fa42fd63b1a`. All nodes report `742000`
bridged, `500003` fees, `241997` circulating native units, 21 commitments, and five programs.

Commit `5101111` extends the rehearsal through deterministic program rollback, reopen, alternate-node
wallet recovery, and reconfirmation. The clean unattended run exited zero and wrote
`build/codex-zk/onyx-program-rollback-qualification.json`, marked
`local-ci-not-release-evidence`.

The rollback design is intentionally strict about database durability. `get_status` exposes the
in-memory/header tip before the daemon's periodic SQLite transaction necessarily commits. The harness
therefore waits until node C logs `db_commit started... tip_height=78`, then uses SQLite's online
backup API while the source remains live. Raw directory copies and backups taken before this event
were observed reopening one block behind. Source and destination SQLite connections are explicitly
closed; a Python connection context manager alone does not close its Windows file handle.

The exact passing branch sequence was:

- height 78 pre-refund tip:
  `8bc5bf085294530004ab078de8ffddc7b3bbd0809bcf2733403df9eef74ebf48`;
- first refund transaction:
  `bae8c1def7efe4c31d9a4f78e370224c5c0745fd901701d0d4263b3d08c04635`, confirmed at 79;
- longer non-refund height-80 tip:
  `21784d82597721d2307ccdb20407f5c82d90ca69079cd27b478c9ef65aebfae8`;
- rollback commitment count/root: `20` /
  `6eb87a0e11d818b4206600234ec8980e61f405c39ae325e80ba5cea9bba97618`;
- identical refund reconfirmation height/final block: `81` /
  `8c7ce1043aadd0a4faeae46a6ef6e5f212a100f7b0353d5d7d79e01205b8cd77`;
- final commitment count/root: `21` /
  `c50ae942893af7412b2ea5263665e16a40a65a0eb311058e7e4333a98a63180d`.

Every primary ended with `742000` bridged, `500003` fees, `241997` circulating native units, five
programs, and current-block program cost `4096`. The report marks program-state rollback,
commitment-root rollback, mempool eligibility restoration, alternate-node wallet reopen, and refund
reconfirmation after node reopen as passed. The test also terminated every daemon/wallet/miner and
removed its temporary directory.

Transaction restoration has an important relay detail: a primary may automatically restore the
rolled-back transaction to its mempool. Sending the duplicate to that same primary returns a known
transaction conflict and does not guarantee rebroadcast to an isolated peer. The harness checks all
four daemons and directly submits the exact binary to each one where it is absent.

The clean rerun also raised capped-token activation mining from 180 to 1,800 seconds. The shorter
timeout expired at height 32 because peers were still applying the deployment proof; the corrected
run crossed the old deadline, reached activation height 48, and completed through height 81.

The run measured minutes of CPU per peer for valid program proof admission/application. Standard-call
admission now authenticates the contextual envelope and checks pool nullifiers/stable keys plus
committed nullifiers/prior state before Halo2. An eligible precheck still enters full verification,
and block consensus is unchanged. The clean rerun recorded the already-built competing NFT call at
`0.015` seconds and the competing swap branch at `0.0` seconds (below timer resolution), under a
conservative 30-second ceiling, in `build/codex-zk/onyx-precheck-qualification.json`.

The first bounded parallel valid-proof HTTP/P2P run passes in `585bc4d`, and `715d019` closes a
worker-ordering gap found during follow-up review. Authenticated pool/state conflicts are now checked
before acquiring a verifier permit or submitting Halo2 work, rather than only when the worker result
returns to the event loop. Cold/warm repetition,
named-hardware variance, invalid-proof floods, sustained sequential load, and memory-pressure
qualification remain open. Authenticated cheap filters cover standard calls, transfers, deployments,
issuance, and bridges. No precheck may become a substitute for full canonical consensus verification.

The node additionally enforces a non-blocking process-local permit and one-job background worker
before external Onyx mempool proof verification: one active verifier globally and per source, with no
internal wait queue. HTTP and P2P share the worker. It verifies only an immutable captured snapshot;
completion returns to the event loop, which requires an exact tip/height/snapshot match and reruns
mutable conflicts. Contention returns retryable RPC `VERIFIER_BUSY` (`-104`) and is not a P2P ban
reason. Block consensus and empty-source reorg restoration bypass the limiter and still verify fully.

Private-transfer admission also authenticates the signed public transaction metadata before Halo2.
Pending or committed nullifier conflicts therefore fail before proof verification, and fee-only
queries no longer invoke Halo2. Eligible transfers still execute the complete stateful proof/apply
operation exactly once before acceptance. The focused optimized regression covers fresh eligibility,
full application, and the resulting spent-nullifier conflict. The `715d019` two-node run then
submitted a distinct valid sibling after the first transfer entered the pool: it rejected in 0.016
seconds, left verifier acquisitions unchanged at 2, incremented the authenticated precheck-conflict
counter from 0 to 1, and kept the pool at one. Live cold/warm and broader parallel-load measurements
remain required.

The `59b0721` extension resubmits the accepted binary exactly after the conflict check. It returns
below timer resolution, leaves verifier acquisitions at 2, leaves the authenticated conflict counter
at 1, and preserves the one-entry pool. Its report records the pool count at duplicate-check time,
before the later block intentionally removes the accepted transaction. The combined live run passed
all nine checks with 143 successful health samples, peak verifier one, and exact post-load progress.

The `d8abdef` extension starts one additional valid-proof request through a raw HTTP socket and waits
until the daemon reports that its verifier permit is active before closing the client. The disconnect
handler increments private `onyx_verifier_abandoned_rpcs` and removes response ownership; the shared
worker input remains alive until verification finishes. The passing run observed abandoned RPCs 0 to
1, verifier acquisitions 1 to 2, active verification returning to zero, no pool entry, and no known
transaction. The later barrier run acquired verifier 3 and completed, proving permit reuse. All ten
wrapper checks passed.

The `933eb94` extension starts a separate synchronized daemon with an explicit private authorization
credential. It proves unauthenticated `confirm=true` and authenticated `confirm=false` shutdown
requests leave the process alive, begins a real valid transfer, waits for one active verifier, and
then calls authenticated `stop_daemon` with `confirm=true`. The acknowledgement is written before a
delayed event-loop cancellation; normal destruction joins the bounded verifier worker. The passing
run exited 0 after 30.703 seconds and reopened the identical database at exact height 4, pool count
zero, and no known interrupted transaction. The combined campaign passed all 11 checks. This proves
safe join and state preservation on the local host, not cooperative Halo2 cancellation or a portable
shutdown-latency bound.

Deployment admission likewise verifies funding authorization and reconstructs the pinned manifest's
canonical program ID before early pool-conflict checks. Eligible deployments still run the complete
stateful proof/application once and must reproduce the authenticated fee and program ID. The focused
real-deployment regression passes; issuance metadata and live load measurements remain open.

Issuance admission is state-aware: the canonical registry supplies the issuer key and cap, after
which the precheck verifies registry identity, active schema, issuer and value-binding signatures,
anchor, sequence, and cumulative supply before Halo2. Eligible issuance still runs the full stateful
proof/application once. Fresh, replay, and corrupted-issuer cases pass in the optimized regression;
live backlog/RSS/load measurements remain open.

Bridge admission structurally extracts the ownership-sighash-covered amount, stack index, key image,
fee, and signature without Halo2. Before those values can drive a conflict rejection, C++ resolves
the exact legacy output, checks subgroup/index/unlock rules, and verifies the ownership ring signature
against that output key. Eligible bridges retain the full stateful bridge proof and authoritative
legacy spent/output/signature checks. The real proof regression, malformed-output clearing test, both
feature-mode builds, both Jade suites, and the complete C++ ZK suite pass.

The P2P body-download backlog now has explicit non-consensus bounds: 32 active transaction downloads
per peer and 128 process-wide. A transaction ID that encounters local Onyx verifier overload is
suppressed for 30 seconds across alternate-peer retry callbacks and reannouncements. Cooldown memory
is capped at 1,024 IDs with expiry cleanup and bounded eviction. Duplicate hashes in a descriptor
message are rejected before state insertion. The policy boundary tests and both
feature-mode builds pass. These controls must still be exercised under real parallel proofs while
recording peak RSS, CPU, latency, ordinary wallet progress, and block application progress.

The authenticated private `get_statistics` endpoint supplies `onyx_verifier_active`,
`onyx_verifier_peak_active`, acquisition and overload-rejection counters,
`onyx_verifier_precheck_conflicts`, `onyx_verifier_abandoned_rpcs`, active transaction downloads, and
retry-cooldown count. Load
evidence must sample these alongside process RSS/CPU and treat an omitted optional zero-valued field
as zero.

`tools/onyx_verifier_load.py` is the bounded live runner. Supply at least two distinct, unsubmitted,
fully formed Onyx transaction files (plain hex or JSON containing `binary_transaction`), the daemon
PID, and private RPC credentials:

```text
python tools/onyx_verifier_load.py \
  --rpc-url http://127.0.0.1:18081/json_rpc \
  --authorization user:password \
  --pid <bytecoind-pid> \
  --transaction-file first.hex \
  --transaction-file second.hex \
  --parallel 2 \
  --revision <full-commit> \
  --max-rss-growth-mib <measured-threshold> \
  --report build/codex-zk/onyx-verifier-load.json
```

The runner starts submissions on one barrier, samples process RSS/peak RSS/CPU independently of RPC,
polls authenticated limiter statistics, records every response and latency, and verifies post-load
RPC health. It fails unless peak verifier concurrency remains at most one, a permit is observed, and
overload is observed (unless `--allow-no-overload` is explicitly used for a control run). An RSS
ceiling is enforced only when supplied; do not invent one before measuring the named host.

`tests/network/test_onyx_verifier_load_process.py` constructs the required transactions itself and
runs a connected primary/relay topology. The 2026-08-12 local run passed with one accepted and one
busy submission, 141 successful daemon samples during proof work, zero sampling or submission
transport errors, verifier peak one, successful P2P propagation, both nodes at height 5, and exact
final commitment-root/supply equality. Peak primary RSS was 563,384,320 bytes and growth was
266,223,616 bytes on that host. The report is explicitly scoped `local-load-not-release-evidence`;
these values are observations, not universal ceilings.

The release gate still requires at least 14 elapsed days, 10,000 blocks and three independently
operated nodes running the exact frozen revision. A private local run or accelerated clock does not
satisfy that evidence.

## SQLite state/undo crash-boundary qualification

`tests/network/test_onyx_db_crash_process.py` launches the native `tests` executable in hidden child
modes that use `platform::DBsqlite3` and the same Onyx state (`Z`) and block-hash-keyed undo (`z...`)
key shapes as the daemon. It forcibly exits after a state-only write, after both writes but before
commit, and immediately after commit. Each restart checks the expected state through the C++ adapter;
the Python parent independently opens the database read-only, runs `PRAGMA integrity_check`, and
compares the exact raw rows.

Run it against a ZK-enabled native test build:

```text
python tests/network/test_onyx_db_crash_process.py \
  --tests build/codex-zk/artifacts/bin/Release/tests.exe \
  --revision <full-commit> \
  --report build/codex-zk/onyx-db-crash-process.json
```

The report scope is `local-process-crash-not-release-evidence`. This verifies transaction atomicity
at the production SQLite adapter boundary and complements the live-daemon campaign below.

## SQLite database and rollback-journal corruption qualification

`tests/network/test_onyx_db_corruption_process.py` copies two disposable images created through the
production `platform::DBsqlite3` adapter: an exactly committed state/undo pair and a deliberately
interrupted transaction with a hot rollback journal. It applies eight deterministic main-database
mutations (header magic, page size, three truncations, state and undo payload bytes, and schema name)
and seven rollback-journal mutations (intact control, header, three truncations, payload, and appended
garbage). The original and resulting image sizes and SHA-256 digests are retained in the report.

The native probe has three explicit outcomes: exact expected state, adapter failure, or semantic
mismatch. Each surviving image is also opened independently with Python SQLite, checked with
`PRAGMA integrity_check`, and compared by raw key/value bytes. A main-image mutation passes only when
the adapter fails closed or the exact Onyx state oracle identifies a mismatch. A journal mutation
passes only when recovery is exact or opening fails; silently returning a mixed state is forbidden.

```text
python tests/network/test_onyx_db_corruption_process.py \
  --tests build/codex-zk/artifacts/bin/Release/tests.exe \
  --revision <full-commit> \
  --report build/codex-zk/onyx-db-corruption-process.json
```

The 2026-08-12 Windows run passed all 15 cases: five adapter failures, seven exact recoveries, and
three semantic mismatches detected before acceptance. The first run exposed a fail-open condition in
which a corrupted `sqlite_master` table name was rejected by independent SQLite inspection but the
embedded adapter still read the old root page. `DBsqliteKV` now requires the exact canonical
`kv_table` schema on every open; the fixed run classifies that case as an adapter failure. The normal
database tests and the original three-boundary crash campaign also pass with this validation.

The report schema is `bytecoin-onyx-db-corruption-v1` and its scope is
`disposable-sqlite-image-local-or-ci-not-power-loss-release-evidence`. This campaign uses rollback
journals and deterministic file mutations. It does not emulate controller caches, filesystem or OS
flush ordering, abrupt power loss, WAL-mode checkpoint interruption, disk-full behavior, arbitrary
I/O faults, maximum-sized state, or coverage-guided fuzzing.

## SQLite WAL and checkpoint-bundle qualification

`tests/network/test_onyx_db_wal_process.py` opts a disposable `DBsqliteKV` fixture into WAL mode,
commits `snapshot-before`, commits the exact state/undo pair in a second WAL transaction, and exits
without a clean connection close so both commit frames remain on disk. It then checkpoints a cloned
bundle through the production adapter. The runner parses and records the 32-byte WAL header, page and
frame sizes, complete-frame count, trailing bytes, and commit-frame boundaries.

Eleven WAL cases cover an intact control, header magic and checksum changes, a frame-checksum change,
empty/header/first-commit/final-byte truncations, state and undo payload changes, and trailing garbage.
Four checkpoint-bundle cases combine pre-checkpoint or post-checkpoint main images with present or
missing WAL/shared-memory sidecars. Every case is opened by the native adapter's exact state oracle,
then independently checked with Python SQLite, `PRAGMA integrity_check`, journal mode, and raw rows.
Only the exact committed state may be classified `exact`; adapter failures and semantic mismatches are
retained as detected corruption/recovery failures rather than accepted state.

```text
python tests/network/test_onyx_db_wal_process.py \
  --tests build/codex-zk/artifacts/bin/Release/tests.exe \
  --revision <full-commit> \
  --report build/codex-zk/onyx-db-wal-process.json
```

The 2026-08-12 final Windows run passed all 15 bounded cases in 1.047 seconds. Five recovered the exact
committed pair and ten were classified as semantic mismatches. The two-frame, 4,096-byte-page fixture
had an 8,272-byte WAL with commit boundaries at bytes 4,152 and 8,272. A missing shared-memory file
was rebuilt safely when the complete WAL remained. Corrupt/truncated WALs were generally discarded by
SQLite, exposing the older main image; the higher-level exact state oracle detected every such case.
This is why SQLite integrity `ok` alone is not evidence that the latest consensus state survived.

The report schema is `bytecoin-onyx-db-wal-campaign-v1`, with an 8 MiB report ceiling, 1 MiB child
output ceiling, per-child timeout, executable/revision binding, and all image digests/sizes. Its scope
is `disposable-sqlite-wal-checkpoint-mix-local-or-ci-not-power-loss-release-evidence`. It models
deterministic WAL corruption and checkpoint file-bundle combinations, not a process killed inside
SQLite's checkpoint routine, real storage write reordering, controller-cache loss, torn sectors,
disk-full/I/O injection, or physical power interruption.

## Deterministic SQLite disk-full qualification

`tests/network/test_onyx_db_full_process.py` uses SQLite's connection-local `max_page_count` at the
fixture's current two-page size. This produces a real `SQLITE_FULL` result without filling the CI
host's disk. Two independent disposable cases attempt a 1 MiB value: one replaces the Onyx state row;
the other first writes the small new state and then attempts the oversized undo row. The native child
must report SQLite primary code 13 at the intended `state` or `undo` stage and exit immediately.

After each failure, a fresh production-adapter process must read exactly `snapshot-before` with no undo
row. An independent read-only SQLite connection must report integrity `ok`, the exact same raw rows,
and unchanged page count. The retained report also records pre/post database sizes and SHA-256
digests; both failed cases were byte-identical before and after recovery. A positive control commits
and recovers the exact new state/undo pair so a uniformly non-writing harness cannot pass.

```text
python tests/network/test_onyx_db_full_process.py \
  --tests build/codex-zk/artifacts/bin/Release/tests.exe \
  --revision <full-commit> \
  --report build/codex-zk/onyx-db-full-process.json
```

The 2026-08-12 final Windows run passed all three cases in 0.203 seconds. Both fault cases returned code 13,
retained the exact 8,192-byte pre-transaction image, and reopened with one state row and no undo. The
control recovered the committed pair. Schema `bytecoin-onyx-db-full-campaign-v1` binds the revision,
executable, fixed 1 MiB attempted value, expected error code, process/report bounds, raw-row evidence,
and image identities. Scope
`sqlite-max-page-count-local-or-ci-not-host-disk-exhaustion-release-evidence` means this proves bounded
SQLite page-exhaustion atomicity, not physical filesystem exhaustion, quota behavior, journal-write or
fsync I/O errors, device removal, storage latency, or power-loss durability.

## Test-only SQLite write and sync I/O-fault qualification

When and only when configured with `ONYX_CRASH_TESTS=ON`, `DBsqlite3.cpp` compiles a forwarding SQLite
VFS named `onyx-fault-vfs`. It wraps the platform's default VFS and delegates every operation except
one armed `xWrite` or `xSync` call on the main rollback journal, main database, or WAL. The wrapper
mirrors each underlying file's exact I/O-method ABI version. The modes therefore return real
extended SQLite codes `SQLITE_IOERR_WRITE` (`778`) or `SQLITE_IOERR_FSYNC` (`1034`) from the intended
storage object without modifying production VFS behavior.

`tests/network/test_onyx_db_ioerr_process.py` runs fifteen fault types across three independent fresh
fixtures per type:

1. journal write failure during the state replacement;
2. journal sync failure during commit;
3. database write failure during commit;
4. database sync failure during commit;
5. journal representative torn writes that persist the first byte, half, or all but the final byte of
   a 512-byte request before returning an error;
6. database representative torn writes that persist the first byte, half, or all but the final byte
   of a 4,096-byte request before returning an error;
7. WAL write failure during commit;
8. WAL sync failure during commit;
9. WAL representative torn writes that persist the first byte, half, or all but the final byte of a
   32-byte request before returning an error.

Every native child must identify the target, operation, state/undo/commit stage, exact extended code,
and exactly one injected call. A new production-adapter process must then return the exact old state
with no undo. Independent read-only SQLite inspection requires integrity `ok` and identical raw rows.
A normal committed control must recover the new state/undo pair.

```text
cmake -S . -B build-onyx-ioerr -DUSE_SQLITE=ON -DONYX_ZK=ON -DONYX_CRASH_TESTS=ON
cmake --build build-onyx-ioerr --target tests
python tests/network/test_onyx_db_ioerr_process.py \
  --tests build-onyx-ioerr/artifacts/bin/tests \
  --revision <full-commit> \
  --report build-onyx-ioerr/onyx-db-ioerr-process.json
```

The 2026-08-12 Windows v3 run at implementation revision `cef868c` passed 45 faults plus one committed
control in 3.734 seconds. Every fault fired once with the expected target, stage, and code; all
recovered exactly. Across every cycle, journal cut points wrote 1, 256, or 511 of 512 requested bytes;
database cut points wrote 1, 2,048, or 4,095 of 4,096 bytes; and WAL cut points wrote 1, 16, or 31 of
32 bytes. The 116,581-byte report uses schema `bytecoin-onyx-db-ioerr-campaign-v3` and scope
`compile-time-test-vfs-representative-torn-writes-local-or-ci-not-device-release-evidence`. It binds
revision/executable identity, process/report/output bounds, before/fault/recovery file manifests, the
requested and persisted prefix lengths, and both native and independent state oracles.

Ordinary builds compile out the VFS, modes, marker, and fault strings. The release-absence regression
scans a normal `bytecoind` and requires the hidden daemon option to remain unknown. This campaign
injects one deterministic call at a time. Independent repetition, journal/database/WAL write and sync
failures, and representative first/half/final-byte-short writes are covered. It does not model
combined faults, every possible cut offset,
directory sync (the Windows VFS did not expose a `syncDir=true` delete boundary), lock/shared-memory
faults, device removal, kernel/controller behavior, or physical power loss.

## Full-daemon apply and reorganization crash qualification

Configure a dedicated, non-distributable build with `ONYX_CRASH_TESTS=ON`. CMake rejects that option
unless `ONYX_ZK=ON`; enabled builds emit a warning. Normal builds compile out the configuration field,
CLI option, marker strings, and fault calls. The consensus workflow runs
`tests/security/test_release_crash_hook_absence.py` against an ordinary artifact to prove both binary
absence and unknown-option rejection.

`tests/network/test_onyx_daemon_crash_process.py` reaches six named transaction points in real daemon
processes with exact exit codes 91 through 96:

1. bridge apply after writing the prior snapshot undo and new state;
2. bridge apply immediately before SQLite commit;
3. bridge apply immediately after commit;
4. longer-chain reorganization after restoring/deleting the stateful NFT call's undo snapshot;
5. that reorganization immediately before commit;
6. that reorganization immediately after commit.

The harness constructs a real signed bridge, deploys and activates the pinned NFT program, proves its
first state transition, and creates a longer branch forked immediately before the call. Pre-commit
terminations must restore the exact old tip, root, supply, program response, state snapshot, and undo
rows. Post-commit terminations must restore the exact committed branch. Every database is opened
independently, must pass `PRAGMA integrity_check`, and has each Onyx state/undo value hashed and sized.

```text
cmake -S . -B build-onyx-crash \
  -DCMAKE_BUILD_TYPE=Release -DUSE_SQLITE=ON -DONYX_ZK=ON -DONYX_CRASH_TESTS=ON
cmake --build build-onyx-crash --target bytecoind walletd minerd
python tests/network/test_onyx_daemon_crash_process.py \
  --bytecoind build-onyx-crash/artifacts/bin/bytecoind \
  --walletd build-onyx-crash/artifacts/bin/walletd \
  --minerd build-onyx-crash/artifacts/bin/minerd \
  --revision <full-commit> \
  --report build-onyx-crash/onyx-daemon-crash.json
```

The local schema is `bytecoin-onyx-daemon-crash-v1` and the scope is
`local-full-daemon-crash-not-release-evidence`. It does not yet simulate disk-full errors, corrupted
WAL/journals, OS power-loss/flush behavior, checkpoint interruption, maximum-sized states, or long
repeated campaigns on independent platforms.

The complementary independent-ledger campaign is documented in
`docs/Onyx-State-Model-Qualification.md`. It retains revision-bound results for eight deterministic
2,000-iteration seeds and checks snapshot maximum-plus-one collection counts before allocation; it
does not replace these full-daemon persistence tests.
