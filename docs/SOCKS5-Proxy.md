# SOCKS5 outbound P2P proxy

Use `bytecoind --p2p-proxy=127.0.0.1:9050` to route every outbound P2P connection through a
no-authentication SOCKS5 proxy such as a locally managed Tor instance. The proxy address must be a
numeric IPv4 address. Bytecoin peer identities are also numeric addresses, so neither endpoint is
resolved by the daemon.

The transport is fail closed: when configured, it never retries a peer directly. It requires SOCKS5
method `0x00`, sends the destination in the proxy CONNECT request, validates the complete reply and
abandons negotiation after 30 seconds. Proxy failures do not ban the destination peer.

## Privacy boundary

This option affects outbound P2P sockets only. It does not automatically create an onion/I2P hidden
service, hide an explicitly public listening address, proxy RPC/wallet traffic, or protect traffic
outside this process. For an outbound-only setup, bind P2P to a local interface and do not advertise
an external port. Configure and verify the anonymity network independently.

The SOCKS5 policy layer now has canonical domain framing restricted to v3 `.onion` and I2P
`.b32.i2p` addresses; it rejects clearnet names, malformed lengths, uppercase/non-base32 labels and
zero ports. It only emits the domain bytes to the proxy and never resolves them locally. The current
peer-address database and wire format still cannot carry those hostnames, so this is a tested framing
seam rather than full hidden-service peer integration. Before release, complete that versioned peer
identity work and run packet-capture leak tests plus multi-node Tor/I2P connection, reconnect, timeout
and shutdown tests on every supported platform.
