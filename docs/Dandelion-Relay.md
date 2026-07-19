# Dandelion++ transaction relay

Bytecoin P2P protocol v5 adds a negotiated stem transaction message. Dandelion++ is enabled by
default; `bytecoind --disable-dandelion` restores immediate diffusion for compatibility and debugging.
The option reduces transaction-origin privacy and is not recommended for normal operation.

The non-consensus policy can be tuned with `--dandelion-epoch-seconds` (1 to 86400),
`--dandelion-embargo-min-seconds` and `--dandelion-embargo-max-seconds` (each 1 to 600, minimum no
greater than maximum), and `--dandelion-fluff-probability` (0 to 100 percent). Defaults remain 600,
10, 30 and 10 respectively. Values outside those bounds fail startup; a zero fluff probability still
has bounded liveness because loop, disconnect and embargo recovery remain active.

## Relay state

Locally submitted transactions and valid transactions received in a stem are processed as follows:

1. Select one outbound protocol-v5 peer with bounded randomized delivery weights and retain it for a
   600-second epoch. Fluff reflected by a different peer rewards the live stem peer; direct reflection
   from the selected peer cannot cancel the embargo. Loops and embargo expiry penalize and rotate it.
   Scores are clamped, decay toward neutral, never exclude a peer, and disappear with the connection
   so they cannot become a permanent identity reputation.
2. Diffuse with 10% probability; otherwise send one descriptor to the selected peer as a stem.
3. Retain the descriptor and a random 10–30 second embargo while the next peer requests and validates
   the full transaction through the existing object-download path.
4. Diffuse immediately if the hop reaches 20, the stem loops back, the selected peer disconnects, or
   no eligible outbound v5 peer exists.
5. Diffuse on embargo expiry if no normal relay was observed. A normal relay cancels upstream pending
   embargo state and is reflected through the usual diffusion path.

The stem message contains exactly one canonical transaction descriptor and an unsigned hop count.
It is accepted only from negotiated v5 peers. V4 and older peers never receive the new command and
continue to interoperate through the existing transaction diffusion message.

## Security boundary

Dandelion++ raises the cost of simple first-spy source correlation. It does not hide node IP addresses,
defeat a sufficiently dense Sybil observer, or replace Tor/I2P. Outbound P2P can be routed through a
SOCKS5 proxy with `--p2p-proxy`; see `docs/SOCKS5-Proxy.md`. The policy gate runs a deterministic
64-peer, 20,000-transaction campaign with sixteen self-reflecting/disconnecting adversarial peers. It
proves every pending stem recovers to fluff, every live peer remains eligible, connection replacement
resets reputation, score bounds/decay hold and repeated failures receive materially less traffic. It
passed on Linux, macOS and Windows in GitHub Actions run `29523898138`.

`tests/network/test_dandelion_process.py` adds a socket-level qualification with four isolated real
daemon processes plus real wallet and miner processes. One non-default daemon target advertises only
protocol v4 while retaining the production parser, consensus and socket stack; there is no production
CLI downgrade switch. The test mines spendable testnet funds and proves
that a transaction reaches the sole outbound stem peer while an inbound observer stays unaware;
selected-peer fluff reflection does not end the embargo; expiry and selected-peer disconnect both
recover to diffusion; and after that v5+ stem peer disconnects, the v4 peer receives immediate
compatibility diffusion without waiting for the embargo. It also rejects out-of-range policy
configuration before startup. The consensus-integration workflow builds all required binaries and
runs this qualification on Linux.

The implementation still needs long-running sanitizer fuzzing, public testnet soak, a matrix against
historically released v4 binaries and independent review before release. The delivery score limits
repeated use of unreliable live peers; it is not Sybil resistance and does not infer operator, subnet
or autonomous-system identity.

The protocol constants are intentionally conservative defaults, not consensus rules. Changing them
does not change transaction validity, but wire-version changes must remain negotiated to preserve
backward compatibility.
