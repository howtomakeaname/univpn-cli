# UniVPN CLI

[![Test](https://github.com/howtomakeaname/univpn-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/howtomakeaname/univpn-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/howtomakeaname/univpn-cli?include_prereleases)](https://github.com/howtomakeaname/univpn-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A Go CLI for UniVPN SSL VPN, with local **SOCKS5 and HTTP proxies**.

[简体中文](README.zh-CN.md) · [Releases](https://github.com/howtomakeaname/univpn-cli/releases) · [Configuration](config.example.json) · [Validation](docs/validation.md)

## Features

- Password authentication with interactive SMS/email MFA.
- A mixed SOCKS5 / HTTP / HTTPS CONNECT listener for SSH, browsers and command-line tools.
- Rootless IPv4 networking with the gVisor TCP/IP stack. No system TUN device or route changes.
- Verified TLS on both VPN channels, private CA support, and explicit certificate pinning.
- Explicit destination CIDRs, VPN-side name resolution, bounded queues and independent keepalives.
- A single executable: `uvpn`, including an SSH `ProxyCommand` helper.

**Experimental:** compatibility is currently limited to the tested UniVPN v1 IPv4-over-TLS profile. See [scope](docs/protocol.md) and [validation](docs/validation.md). This is an independent project, not an official vendor client.

## Install

Download an archive from [Releases](https://github.com/howtomakeaname/univpn-cli/releases), verify it against `SHA256SUMS`, and extract it.

| Platform | Architectures | Executable |
| --- | --- | --- |
| Linux | amd64, arm64 | `uvpn` |
| macOS | amd64, arm64 | `uvpn` |
| Windows | amd64, arm64 | `uvpn.exe` |

macOS and Windows packages are unsigned. Cross-platform builds and native CI tests are separate from live gateway validation.

## Quick start

Copy [config.example.json](config.example.json) to `uvpn.local.json`. Set your gateway, VPN username and permitted internal addresses:

```json
{
  "gateway": "vpn.example.com:443",
  "username": "YOUR_VPN_USERNAME",
  "listen": "127.0.0.1:7890",
  "allow_cidrs": ["10.20.30.40/32"],
  "hosts": {"atlas.internal": "10.20.30.40"}
}
```

```sh
uvpn connect -config uvpn.local.json
```

Enter your VPN password and, when requested, the SMS/email code. `READY` means the proxy is available. Keep the process running; press Ctrl-C to disconnect.

TLS certificate and hostname verification are enabled by default. For a private CA, set `ca_file`; for an IP gateway with a certificate issued to a verified hostname, set `server_name`. Alternatively, set `cert_sha256` to a trusted SHA-256 fingerprint of the DER leaf certificate. Obtain trust information from your gateway administrator. `inspect-cert` only reports an **unverified** observation and does not change trust.

```sh
uvpn inspect-cert -config uvpn.local.json
uvpn probe -config uvpn.local.json
```

`probe` checks TLS and protocol setup without submitting credentials. Relative file paths resolve from the configuration directory.

## Use the proxy

```sh
ssh -o 'ProxyCommand=uvpn dial %h:%p' SSH_USER@10.20.30.40
curl --proxy socks5h://127.0.0.1:7890 http://atlas.internal:8080/
curl --proxy http://127.0.0.1:7890 https://atlas.internal/
```

Put `uvpn` on PATH or use its absolute path in `ProxyCommand`. SSH credentials and host-key verification remain with OpenSSH. Destination TLS verification remains with the application.

Names resolve through `hosts` or an explicitly configured VPN DNS server. Targets outside `allow_cidrs` are rejected; there is no direct-connection fallback. The listener accepts numeric loopback addresses only, but other local processes can use it.

Passwords and session tokens are not logged or exported. Unix users may set `password_file` to a private file with mode `0600`; Windows users should use the interactive prompt or `--password-stdin`. `--otp-stdin` reads a code only when requested by the gateway. See the [Chinese usage guide](README.zh-CN.md) for automation and spreadsheet import.

## Scope

Supported: SOCKS5 CONNECT, ordinary HTTP and HTTP CONNECT over IPv4/TLS. Session failures close both VPN channels and require a new login.

Not implemented: SOCKS UDP ASSOCIATE, IPv6, UDP/DTLS tunnels, IPsec, browser SSO, client-certificate login, endpoint compliance plugins, password changes or transparent reconnect. Ordinary HTTP proxy requests use separate connections; use CONNECT for streaming upgrades. TCP-over-TCP performance depends on network conditions.

## Build and test

Use the Go version in [.go-version](.go-version):

```sh
make build
make test
make check
```

CI runs tests on Linux, macOS and Windows. Tagged releases build six platform archives and publish checksums. Contributions should include tests for protocol, proxy or security behavior changes; never submit credentials, private configurations or packet captures.

## License and acknowledgements

[MIT](LICENSE). Dependencies keep their respective licenses; see [third-party notices](THIRD_PARTY_NOTICES.md). Thanks to [gVisor](https://github.com/google/gvisor) for the user-space network stack and the independent [UniVPN Connect](https://github.com/Bruce-lhq/univpn-connect) project for public interoperability notes. UniVPN and other product names remain the trademarks of their respective owners.
