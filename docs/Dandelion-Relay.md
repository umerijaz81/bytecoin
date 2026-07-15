# Dandelion++ transaction relay

Bytecoin P2P protocol v5 adds a negotiated stem transaction message. Dandelion++ is enabled by
default; `bytecoind --disable-dandelion` restores immediate diffusion for compatibility and debugging.
The option reduces transaction-origin privacy and is not recommended for normal operation.

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
SOCKS5 proxy with `--p2p-proxy`; see `docs/SOCKS5-Proxy.md`. The current implementation still needs
socket-level adversarial multi-node topology tests, long-running sanitizer fuzzing, testnet soak and
independent review before release. The delivery score limits repeated use of unreliable live peers;
it is not Sybil resistance and does not infer operator, subnet or autonomous-system identity.

The protocol constants are intentionally conservative defaults, not consensus rules. Changing them
does not change transaction validity, but wire-version changes must remain negotiated to preserve
backward compatibility.
