# Traffic compatibility

The compatibility target is correct UniVPN protocol behavior and preservation of
the application's traffic. A successful login or transfer does not prove that
the client is indistinguishable from another implementation, or predict how a
particular gateway's identification policy will classify it.

## Layers and current guarantees

| Layer | Current behavior | Boundary |
| --- | --- | --- |
| Application over SOCKS5 / CONNECT | Relays the TCP byte stream; no destination TLS termination or application-header rewriting | TCP packet boundaries and timing can change |
| Application UDP | Preserves each SOCKS5 UDP payload and datagram boundary | IP fragmentation and scheduling can differ |
| Ordinary HTTP proxy | Preserves client User-Agent and encoding negotiation, including absence; keeps encoded response content | HTTP is parsed and serialized; header casing/order, connection handling and transfer framing are not byte-identical |
| UniVPN framing | The supported v1 commands, bounded TLVs, MFA, token/VIP binding and IPv4 data framing are exercised | Other versions and optional extensions are not implied |
| Session behavior | Independent control/data TLS channels, 10-second control and 15-second data keepalives | Reconnect is fresh authentication; no supported token-refresh flow |
| Gateway TLS | Go `crypto/tls`, TLS 1.2 or later, verified CA/name or explicit leaf pin on both channels | No vendor TLS fingerprint equivalence is claimed |
| Virtual TCP/IP | gVisor IPv4 TCP/UDP, configurable MTU, TCP retransmission/window handling | TCP options, segmentation, source ports and timing can differ from an OS TUN client |

Ordinary HTTP forwarding removes hop-by-hop and proxy-authentication headers,
does not add `Via` or `X-Forwarded-For`, and does not insert a default User-Agent
or negotiate gzip on the client's behalf. SOCKS5 or CONNECT is appropriate when
an application's own protocol serialization and TLS handshake must pass through.

## Client metadata and policy

The current authentication MAC-format identifier is a stable, locally administered
value derived by uvpn; it is not read from a physical adapter. Deployments that
bind access to hardware identity or require other client metadata have not been
validated. Protocol-version support is not a claim to reproduce every vendor
metadata field.

Mandatory endpoint checks are reported and refused when they cannot be completed;
uvpn does not manufacture a successful posture result. Accepted protocol fields
must represent the actual supported profile, rather than advertise unimplemented
capabilities to satisfy a gateway policy.

## What has and has not been compared

The validation covers one authorized gateway's password/MFA login and live
TCP/UDP transfers, plus deterministic local framing and forwarding tests. See
[validation](validation.md). There is no same-host, same-configuration paired
capture proving equivalence of the original client and uvpn's complete handshake,
TCP options, record sizes or timing.

In particular, the TLS implementation and its defaults can change with the Go
toolchain. Packet batching combines queued VPN frames for throughput; it does
not preserve another client's TLS record boundaries. Matching a single TLS
fingerprint would not establish equivalence at the other layers.

For interoperability work, compare the expected protocol events, negotiated
versions, MTU, error handling, and application payload integrity under the same
conditions. Keep credentials, session keys and raw captures private. Deployments
that require an official client or its security components need a supported
deployment path; this project makes no guarantee of avoiding identification.

## References

- [Go TLS configuration](https://pkg.go.dev/crypto/tls#Config)
- [Go HTTP transport](https://pkg.go.dev/net/http#Transport)
- [gVisor networking guide](https://gvisor.dev/docs/user_guide/networking/)
