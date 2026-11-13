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

The v0.2.0 build subsequently completed a new live password/MFA login. SOCKS5 UDP
round trips of 0, 32, 1200, 8192 and 60,000 bytes matched byte-for-byte. A temporary
in-memory echo service ran on the allocated server. Its host firewall initially
rejected the test port; a runtime-only rule limited to the observed client `/32`
and that single ephemeral UDP port enabled the test. The rule had a 120-second
expiry, was explicitly removed in cleanup, and the rule set was verified unchanged.
The echo service and diagnostic processes were also stopped.

## Transfer performance

Path: SSH → loopback SOCKS5 → gVisor IPv4/TCP → UniVPN v1 TLS → allocated host.
Upload/download payloads stayed in memory; no remote disk file or persistent service
was created. Rates below are MiB/s (1 MiB = 1,048,576 bytes), measured after SSH
authentication, with SHA-256 verified in both directions. These are link-level
observations including SSH overhead, not a general performance guarantee or a
comparison with the vendor client.

| Version / test | Payload per direction | Upload | Download |
| --- | --- | --- | --- |
| v0.1.0, one SSH stream | 64 MiB | 11.11 MiB/s | 13.08 MiB/s |
| v0.1.0, four streams, run 1 | 4 × 16 MiB | 10.93 MiB/s aggregate | 12.07 MiB/s aggregate |
| v0.1.0, four streams, run 2 | 4 × 16 MiB | 11.30 MiB/s aggregate | 12.50 MiB/s aggregate |
| v0.2.0, one SSH stream | 64 MiB | 10.51 MiB/s | 12.23 MiB/s |

The v0.2.0 VPN process used approximately 13.9 MiB RSS and 2.14 seconds of CPU during
the single-stream bidirectional transfer (v0.1.0: 13.1 MiB / 1.99 seconds). CPU time
excludes the separate SSH processes and remote server. These measurements do not
establish a performance difference between versions. An earlier unbatched run had
variable concurrent upload performance; the table uses batched TLS writes.

The live UDP echo run sent 8192 datagrams of 1200 payload bytes with a window of 64.
All 8192 returned intact, with zero observed loss, in 2.936 seconds: **3.193 MiB/s
echo payload goodput**. This counts each returned payload once, includes round-trip
and echo overhead, and is not a maximum link-throughput result or directly
comparable to the SSH stream measurements.

Live compatibility was exercised from Linux amd64 against one gateway. Automatic
fresh-login reconnect has been exercised with a local verified-TLS gateway
simulator; a forced live reconnect/MFA cycle has not been separately exercised. Other
firmware variants, multi-hour session renewal, lossy-WAN performance, internal DNS
interoperability and live operation on other operating systems remain unverified.
