# Proxy composition with mihomo / Clash

`uvpn` exposes a standard loopback mixed proxy. A routing client can use it as an
upstream SOCKS5 node and select that node for particular domains or IPv4 ranges.
This is a design reference; it does not install a routing client or modify its
configuration.

```text
Application → routing client → uvpn loopback proxy → VPN → private service
                 domain/IP        allow_cidrs
                   rules          + VPN DNS
```

## Local endpoint contract

| Interface | Supported traffic | Endpoint selection |
| --- | --- | --- |
| SOCKS5 CONNECT | TCP streams | `listen` in the uvpn profile |
| SOCKS5 UDP ASSOCIATE | UDP datagrams | Same TCP port; reply supplies the UDP relay port |
| HTTP CONNECT | TCP tunnels, including HTTPS | Same mixed port |
| Ordinary HTTP proxy | HTTP/1.x requests | Same mixed port |

Choose a fixed, unused loopback port for composition, such as
`"listen": "127.0.0.1:10808"`. The default remains `127.0.0.1:7890`, which may
already belong to a routing client. Binding happens before VPN authentication, so
a port conflict fails before requesting MFA. `uvpn dial -proxy 127.0.0.1:10808`
also accepts the selected endpoint.

The local proxy is plain SOCKS5/HTTP on loopback; gateway TLS is a separate
connection managed by uvpn. Both clients must share a network namespace.
Non-loopback listeners are rejected. No gateway credentials or VPN session token
belong in the routing client's proxy definition.

## Reference node and rules

For a uvpn profile using the example port, the relevant mihomo fields are:

```yaml
proxies:
  - name: UniVPN
    type: socks5
    server: 127.0.0.1
    port: 10808
    udp: true

rules:
  - DOMAIN,atlas.internal,UniVPN
  - DOMAIN-SUFFIX,lab.example.internal,UniVPN
  - IP-CIDR,10.20.30.40/32,UniVPN,no-resolve
```

This fragment defines the upstream and specific routes, not a replacement for a
user's complete configuration. Position specific routes before broader rules;
retain the user's handling for unrelated traffic. For private routes, select the
UniVPN node directly rather than a group that can fall back to DIRECT. The uvpn
destination allowlist is still enforced after the routing client's decision.

Use SOCKS5 with UDP enabled when UDP is needed; an HTTP node cannot provide UDP.
Older Clash variants may have different UDP capabilities. The reference follows
the current mihomo schema; it is not a claim that every client/version was tested.

## Domain resolution and routing loops

- Keep private-domain rules ahead of IP rules that could trigger local DNS.
  `no-resolve` prevents that particular IP rule from initiating a lookup; it does
  not undo lookups already performed elsewhere.
- When uvpn receives a domain through SOCKS5 or CONNECT, it resolves via its
  configured `hosts` or VPN-side `dns`, then checks every resulting IP against
  `allow_cidrs`. For the example alias, the uvpn profile needs an allowed target
  and a mapping such as `"hosts": {"atlas.internal": "10.20.30.40"}`. Other
  private names need corresponding mappings or working VPN DNS.
- The routing client's DNS/fake-IP behavior determines whether the original
  domain reaches uvpn. A synthetic address is not a substitute for VPN DNS;
  retain domain metadata and do not add the fake-IP range to `allow_cidrs`.
  Routing a domain to a proxy alone does not guarantee that an earlier DNS query
  stayed private.
- With a system TUN or process-wide capture, uvpn's connections to the VPN gateway
  must take an independent path. Exclude the actual gateway IP from routing back
  through UniVPN and keep gateway DNS bootstrap independent of the VPN. Otherwise
  establishing the VPN would require the same VPN to be established first.
- An unavailable uvpn node should fail its selected private requests. uvpn does
  not provide a direct fallback, but a separate routing client's fallback policy
  can still select another route.

SOCKS5 and CONNECT preserve application streams; they do not make uvpn's gateway
TLS or virtual TCP/IP stack identical to the vendor client. See
[traffic compatibility](traffic-compatibility.md).

## References

- [mihomo SOCKS outbound](https://wiki.metacubex.one/config/proxies/socks/)
- [mihomo routing rules and no-resolve](https://wiki.metacubex.one/config/rules/)
- [mihomo DNS resolution flow](https://wiki.metacubex.one/config/dns/diagram/)

These pages describe the upstream schema. Existing uvpn tests exercise standard
SOCKS5 TCP/UDP, HTTP CONNECT, domain forwarding, and cleanup; no user's running
Clash/mihomo instance is configured by this project.
