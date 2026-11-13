# UniVPN CLI v0.2.0 (experimental)

- Add SOCKS5 UDP ASSOCIATE over the verified TLS data tunnel, using the same
  destination allowlist and VPN DNS as TCP. Associations bind client sources,
  enforce flow limits and release resources on control/session closure.
- Detect required endpoint policies, runtime revocation and re-authentication;
  close the tunnel when the required security state cannot be established.
- Add optional bounded fresh-login reconnect (`-reconnect-attempts`) and a local
  session-duration cap (`session_max_seconds`). Reconnect verifies TLS and follows
  the gateway's password/MFA requirements again; existing streams are not resumed.
- Document MFA persistence boundaries: one-time codes are not cached, and tokens
  remain in memory. Keepalive is not token refresh or persistent device trust.
- Add forwarding and session diagrams, bilingual guides and offline documentation
  to Linux/macOS/Windows amd64 and arm64 archives, with licenses and SHA256SUMS.

An authorized live gateway, SSH login and bidirectional integrity-checked
transfers were exercised from Linux amd64 for the original TLS/TCP path. New UDP
and reconnect behavior is covered by local TLS/MFA gateway integration tests,
including concurrent TCP/UDP, 60 KB datagrams and two independent MFA logins.
Native CI and cross-builds are separate from live gateway acceptance.

Outer encrypted UDP/DTLS tunnels, legacy HTTP-authenticated VPN sessions, IPv6,
IPsec, endpoint security plugins, browser SSO, token-refresh/remember-device flows
and transparent connection migration remain outside this release. Windows uses
interactive/stdin password input rather than Unix password-file permissions.
See README and docs/validation.md.
