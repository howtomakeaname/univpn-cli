# UniVPN CLI v0.1.0 (experimental)

- Independent Go CLI for the tested UniVPN v1 IPv4-over-TLS profile.
- Password and interactive SMS/email MFA, verified TLS on both channels.
- Loopback mixed SOCKS5/HTTP proxy; built-in `uvpn dial` for SSH ProxyCommand.
- User-space gVisor TCP stack, explicit destination allowlist, bounded queues,
  independent keepalives, and batched TLS writes.
- Linux/macOS/Windows amd64 and arm64 archives, licenses and SHA256SUMS.

An authorized live gateway, SSH login and bidirectional integrity-checked
transfers were exercised from Linux amd64. Native CI results are separate from
live VPN validation. The other hardware/platform combinations are build targets,
not claims of live interoperability tests on every device.

UDP/DTLS, IPv6, IPsec, endpoint plugins, browser SSO and transparent reconnect
are outside this release. Windows uses interactive/stdin password input rather
than Unix password-file permissions. See README and docs/validation.md.
