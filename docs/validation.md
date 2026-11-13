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
  hop-by-hop headers, preservation of absent or explicit User-Agent/Accept-Encoding
  and encoded response bytes, pipelined data following CONNECT, loopback-only
  listeners. Raw HTTP tests avoid client libraries masking default-header changes.
- Integration: actual local TLS, MFA, both VPN channels, two gVisor stacks and eight
  concurrent HTTP CONNECT streams carrying 256 KiB each alongside 0/32/60,000-byte
  UDP round trips, including IPv4 fragmentation/reassembly. Reconnect tests perform
  two complete logins with distinct MFA codes and tokens, observe old-listener
  cleanup during backoff and stop on final gateway revocation.

Linux amd64 passed `go test -race ./...` and `go vet ./...`. The release workflow
runs native tests on Linux/macOS/Windows, then cross-builds amd64/arm64 archives.
Successful cross-builds do not constitute live testing on all six hardware targets.

The [routing-client reference](proxy-chaining.md) uses the documented mihomo
SOCKS5 schema and the tested local proxy interfaces. No running Clash/mihomo
instance was configured or used for an end-to-end acceptance test. See
[traffic compatibility](traffic-compatibility.md) for payload-preservation and
fingerprint boundaries; no paired vendor-client capture comparison was performed.

## Authorized live gateway

The tested environment required a self-signed gateway certificate. The user
explicitly accepted first-use trust; the observed certificate was then pinned on
both TLS channels. Password and SMS MFA completed successfully. The proxy reached
SSH through both SOCKS5 and HTTP CONNECT, and reached HTTP/HTTPS management services.
SSH login and read-only server inspection succeeded through the built-in `dial`
helper. The connection remained usable across idle periods and repeated tests.

The downloaded v0.2.1 Linux amd64 release subsequently completed a fresh
password/MFA login on a separately configured loopback listener. SSH login through
SOCKS5 succeeded; ordinary HTTP received the management service's 301 response,
and HTTP CONNECT returned the allocated host's SSH banner. This did not involve
configuring a running third-party routing client.

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
| v0.2.1, one SSH stream, run 1 | 64 MiB | 2.94 MiB/s | 12.62 MiB/s |
| v0.2.1, one SSH stream, run 2 | 64 MiB | 1.93 MiB/s | 7.58 MiB/s |

The v0.2.0 VPN process used approximately 13.9 MiB RSS and 2.14 seconds of CPU during
the single-stream bidirectional transfer (v0.1.0: 13.1 MiB / 1.99 seconds). CPU time
excludes the separate SSH processes and remote server. These measurements do not
establish a performance difference between versions. An earlier unbatched run had
variable concurrent upload performance; the table uses batched TLS writes.

Both v0.2.1 transfers passed SHA-256 checks in each direction. Its process used
13.4 / 14.1 MiB RSS and 2.15 / 2.44 seconds of CPU across the two runs. Upload
was lower than earlier observations, with variable download results; these runs
do not isolate the cause or establish whether the variation is client- or
path-related. The HTTP patch does not change the SOCKS5 data path. No vendor-client
performance comparison was performed.

### Interleaved follow-up

Later on the same day, the still-running earlier development build (`5e63c0f`,
before v0.2.0) and the downloaded v0.2.1 release were tested in alternating order:
earlier 1, v0.2.1 1, earlier 2, v0.2.1 2, earlier 3, v0.2.1 3. Each transfer used
the same allocated host, SSH settings, 64 MiB in-memory payload per direction and
SHA-256 verification. Both binaries used Go 1.27.4 and the same dependencies;
their configurations differed only in the loopback listener. The two existing
authenticated VPN sessions remained separate, so session and path effects were
not eliminated.

| Build / round | Upload | Download |
| --- | --- | --- |
| Earlier development build, 1 | 6.12 MiB/s | 14.42 MiB/s |
| v0.2.1, 1 | 7.17 MiB/s | 12.46 MiB/s |
| Earlier development build, 2 | 10.56 MiB/s | 11.31 MiB/s |
| v0.2.1, 2 | 12.14 MiB/s | 14.05 MiB/s |
| Earlier development build, 3 | 10.51 MiB/s | 11.27 MiB/s |
| v0.2.1, 3 | 12.15 MiB/s | 14.76 MiB/s |

All six transfers passed both checksums. Samples of the outer VPN TCP data
connections showed first-round congestion windows growing from 5 to 226 segments
for the earlier build and 8 to 235 for v0.2.1. Subsequent rounds began with larger
windows. The earlier session had no additional retransmitted bytes across these
runs; v0.2.1 had none in rounds 1 and 3, and one 90-byte retransmission in round 2.

This follow-up did not reproduce a consistent throughput regression. The first
round's smaller congestion windows are consistent with ramp-up affecting these
short transfers, but comparable TCP samples were not collected during the original
slow runs, so their cause remains unresolved. The v0.2.1 HTTP header patch leaves
the SOCKS5/SSH forwarding path unchanged. These results do not establish a causal
speed improvement between versions either.

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
