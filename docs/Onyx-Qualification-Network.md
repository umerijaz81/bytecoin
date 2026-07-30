# Onyx qualification network

`--net=onyx` selects a fixed consensus network for public Onyx migration, proving, reorg, privacy and
recovery qualification. It is not an activation override for mainnet, stagenet or the existing
testnet.

The network has a distinct P2P UUID, genesis nonce, default ports and `_onyxnet` data directory.
Jade V5, RandomX, reserved V6 and Onyx V7 are co-scheduled at height 1, so the first post-genesis
block uses the same direct V4-to-V7 policy intended for release. RandomX uses the genesis block as
its delayed seed ancestor until the normal lag is available. Qualification difficulty is deliberately
low; performance evidence must use separately documented native release parameters.

An `ONYX_ZK=OFF` binary refuses to join this network. There are no compiled-in seed nodes: operators
must publish and independently record the explicit `--seed-node-address` or
`--priority-node-address` topology used for the soak. The network identity and consensus schedule
cannot be changed by command-line flags.

The blockchain database retains its seven checkpoint-difficulty slots for format compatibility, but
all seven qualification-network checkpoint public keys are zero and cannot authorize a signed
checkpoint. Qualification nodes therefore do not inherit mainnet, stagenet or testnet checkpoint
authority. The shared checkpoint admission path rejects an empty public key before invoking signature
verification, which also fails closed for out-of-range key identifiers.

`tests/network/test_onyx_qualification_process.py` starts two real ZK-enabled qualification daemons,
checks their fixed genesis and successful P2P handshake, then proves a testnet daemon cannot cross the
network-identity/genesis boundary. The consensus workflow separately runs the Jade invariant suite in
both ZK-enabled and non-ZK configurations; the latter must reject `--net=onyx`.

The release gate still requires at least 14 elapsed days, 10,000 blocks and three independently
operated nodes running the exact frozen revision. A private local run or accelerated clock does not
satisfy that evidence.
