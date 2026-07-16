# SOCKS5 outbound P2P proxy

Use `bytecoind --p2p-proxy=127.0.0.1:9050` to route every outbound P2P connection through a
no-authentication SOCKS5 proxy such as a locally managed Tor instance. The proxy address must be a
numeric IPv4 address. Numeric peers and canonical v3 `.onion`/`.b32.i2p` peers may be supplied through
the existing seed, priority and exclusive-node options. Hostnames are sent only in a SOCKS5 domain
CONNECT request; the daemon never passes them to a local resolver or falls back to a direct socket.

An outbound-only hidden service can advertise its stable endpoint to protocol-v6 peers:

```text
bytecoind --p2p-proxy=127.0.0.1:9050 \
  --p2p-advertise-anonymity-address=<56-base32-characters>.onion:8080
```

The advertised service must be configured separately in Tor/I2P. The daemon does not manage the
anonymity process or its private keys.

The transport is fail closed: when configured, it never retries a peer directly. It requires SOCKS5
method `0x00`, sends the destination in the proxy CONNECT request, validates the complete reply and
abandons negotiation after 30 seconds. Proxy failures do not ban the destination peer.

## Privacy boundary

This option affects outbound P2P sockets only. It does not automatically create an onion/I2P hidden
service, hide an explicitly public listening address, proxy RPC/wallet traffic, or protect traffic
outside this process. For an outbound-only setup, bind P2P to a local interface and do not advertise
an external port. Configure and verify the anonymity network independently.

The SOCKS5 policy layer restricts domains to v3 `.onion` and I2P `.b32.i2p` addresses; it rejects
clearnet names, malformed lengths, uppercase/non-base32 labels, mixed numeric/hostname identities and
zero ports. P2P v6 carries anonymity identities in a separate bounded handshake list, leaving the
v1-v5 numeric address encoding unchanged. Only successfully connected identities enter the shareable
white list; unverified advertisements remain gray. Peer DB v4 persists the hostname and clears the old
numeric-only cache once during upgrade.

The Linux CI process qualification builds and launches the real daemon against an adversarial SOCKS5
server and TCP destination. It proves that a successful numeric connection carries a P2P handshake
through the proxy, identifies and rejects any direct-fallback source, proves proxy rejection never
reaches the destination, and uses an `LD_PRELOAD` `getaddrinfo` tripwire to prove a canonical onion
hostname is sent intact without a local lookup. GitHub Actions run `29523281753` passed these cases on
2026-07-16; the framing policy suite passed on Linux, macOS and Windows in the same run.

Before release, repeat packet-capture DNS/direct-leak tests on every supported platform and run
multi-node connection, reconnect, timeout and shutdown tests against real Tor and I2P service
processes. The hermetic SOCKS5 qualification proves the daemon boundary, but it does not prove an
operator's external proxy/service configuration is private or interoperable.
