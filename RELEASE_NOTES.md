# UniVPN CLI v0.2.1 (experimental)

- Preserve ordinary HTTP requests without inserting a default User-Agent or
  negotiating gzip on the application's behalf. Encoded response bytes remain
  encoded; explicit application headers remain unchanged. Raw HTTP regression
  tests cover both absent and explicit negotiation headers.
- Document the existing configurable loopback listener as a SOCKS5 upstream for
  mihomo / Clash, with domain/IP reference rules, VPN DNS considerations and
  routing-loop prevention. No user's routing-client configuration is modified;
  no running third-party routing client was used for acceptance testing.
- Explain application-payload preservation separately from gateway TLS, virtual
  TCP/IP, metadata and timing. Protocol interoperability does not establish an
  identical vendor-client fingerprint or guarantee how a gateway classifies it.
- Include both references in the six platform archives alongside the bilingual
  guides, diagrams, licenses and SHA256SUMS.

Automated proxy tests cover HTTP headers and encoded response integrity. The
authorized live gateway and transfer measurements in docs/validation.md were
recorded with v0.2.0; they were not repeated for this HTTP forwarding patch.
SOCKS5/CONNECT and VPN session behavior are unchanged. Native CI and cross-builds
are separate from live gateway acceptance.

Outer encrypted UDP/DTLS tunnels, legacy HTTP-authenticated VPN sessions, IPv6,
IPsec, endpoint security plugins, browser SSO, token-refresh/remember-device flows
and transparent connection migration remain outside this release. Windows uses
interactive/stdin password input rather than Unix password-file permissions.
See README and docs/validation.md.
