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
14. prove a testnet daemon cannot cross the network-identity/genesis boundary; and
15. optionally write a revision-bound JSON report containing every node's final height, hash, peer ID,
   supply-audit snapshot and the nonsensitive wallet qualification results.

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

The run also measured minutes of CPU per peer for valid program proof admission/application. Confirmed
replays and pending stable-key competitors reached proof verification before cheap conflict rejection.
Cold/warm verifier initialization, bounded admission/backpressure, program-state reorganization and
rollback, reopen behavior, and alternate-node recovery are still open.

The release gate still requires at least 14 elapsed days, 10,000 blocks and three independently
operated nodes running the exact frozen revision. A private local run or accelerated clock does not
satisfy that evidence.
