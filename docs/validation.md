# Validation

Recorded on 2026-11-13. No gateway address, account, certificate, session token or
private log is included here.

## Automated checks

- TLS: system/private CA trust, explicit full certificate pin, wrong pin and
  hostname rejection.
- Protocol: fragmented frames, bounded lengths, truncated TLVs, password escaping,
  interactive MFA, expiry reminders and mandatory password changes.
- Lifecycle: cancellation during setup, endpoint requirements refused before data
  binding, runtime revocation/re-authentication, local duration limits, worker
  shutdown and bounded fresh-login reconnect.
- Networking: 16 concurrent TCP sessions with a deliberately dropped initial packet,
  byte-for-byte verification, destination allowlist and no host-DNS/direct fallback.
- Proxies: SOCKS5 TCP and UDP, UDP source isolation, control-connection lifetime,
  resource caps and empty datagrams; HTTP body relay, removal of proxy and
  hop-by-hop headers, pipelined data following CONNECT, loopback-only listeners.
- Integration: actual local TLS, MFA, both VPN channels, two gVisor stacks and eight
  concurrent HTTP CONNECT streams carrying 256 KiB each alongside 0/32/60,000-byte
  UDP round trips, including IPv4 fragmentation/reassembly. Reconnect tests perform
  two complete logins with distinct MFA codes and tokens, observe old-listener
  cleanup during backoff and stop on final gateway revocation.

Linux amd64 passed `go test -race ./...` and `go vet ./...`. The release workflow
runs native tests on Linux/macOS/Windows, then cross-builds amd64/arm64 archives.
Successful cross-builds do not constitute live testing on all six hardware targets.

## Authorized live gateway

The tested environment required a self-signed gateway certificate. The user
explicitly accepted first-use trust; the observed certificate was then pinned on
both TLS channels. Password and SMS MFA completed successfully. The proxy reached
SSH through both SOCKS5 and HTTP CONNECT, and reached HTTP/HTTPS management services.
SSH login and read-only server inspection succeeded through the built-in `dial`
helper. The connection remained usable across idle periods and repeated tests.

## Transfer performance

Path: SSH → loopback SOCKS5 → gVisor IPv4/TCP → UniVPN v1 TLS → allocated host.
Upload/download payloads stayed in memory; no remote disk file or persistent service
was created. Rates below are MiB/s (1 MiB = 1,048,576 bytes), measured after SSH
authentication, with SHA-256 verified in both directions. These are link-level
observations including SSH overhead, not a general performance guarantee or a
comparison with the vendor client.

| Final implementation | Payload per direction | Upload | Download |
| --- | --- | --- | --- |
| One SSH stream | 64 MiB | 11.11 MiB/s | 13.08 MiB/s |
| Four simultaneous streams, run 1 | 4 × 16 MiB | 10.93 MiB/s aggregate | 12.07 MiB/s aggregate |
| Four simultaneous streams, run 2 | 4 × 16 MiB | 11.30 MiB/s aggregate | 12.50 MiB/s aggregate |

The VPN process used approximately 13.1 MiB RSS and 1.99 seconds of CPU during
the single-stream bidirectional transfer. CPU time excludes the separate SSH
processes and remote server. An earlier unbatched run had variable concurrent
upload performance; repeated final-version measurements are reported above.

Live compatibility was exercised from Linux amd64 against one gateway. UDP and
fresh-login reconnect additions have been exercised with a local verified-TLS
gateway simulator; the existing live tunnel was kept running for ongoing server
work. These additions have not yet had a new live-gateway acceptance run. Other
firmware variants, multi-hour session renewal, lossy-WAN performance, internal DNS
interoperability and live operation on other operating systems remain unverified.
