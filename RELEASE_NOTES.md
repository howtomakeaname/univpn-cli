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

Automated proxy tests cover HTTP headers and encoded response integrity.
Subsequent validation with the published v0.2.1 Linux amd64 binary repeated a fresh
password/MFA login, SSH login, ordinary HTTP and HTTP CONNECT. Two 64 MiB transfers
passed SHA-256 in both directions: uploads 2.94 / 1.93 MiB/s and downloads
12.62 / 7.58 MiB/s. Rates varied and uploads were lower than earlier observations;
the cause has not been isolated. See docs/validation.md for all recorded results.
SOCKS5/CONNECT and VPN session behavior are unchanged. Native CI and cross-builds
are separate from live gateway acceptance.

Outer encrypted UDP/DTLS tunnels, legacy HTTP-authenticated VPN sessions, IPv6,
IPsec, endpoint security plugins, browser SSO, token-refresh/remember-device flows
and transparent connection migration remain outside this release. Windows uses
interactive/stdin password input rather than Unix password-file permissions.
See README and docs/validation.md.
