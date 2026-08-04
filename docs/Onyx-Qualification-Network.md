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
10. prove a testnet daemon cannot cross the network-identity/genesis boundary; and
11. optionally write a revision-bound JSON report containing every node's final height, hash, peer ID,
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
mining, registry application, wallet scanning, cross-node convergence and replay rejection. The
unrelated general token issuance/transfer domain remains `k=20` until it receives the same circuit-
specific qualification.

The release gate still requires at least 14 elapsed days, 10,000 blocks and three independently
operated nodes running the exact frozen revision. A private local run or accelerated clock does not
satisfy that evidence.
