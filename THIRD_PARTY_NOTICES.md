# Third-party notices

UniVPN CLI's original code is MIT licensed (see LICENSE). Dependencies retain
their own licenses. Exact source revisions and checksums are in go.mod/go.sum.

| Dependency | Version | License |
| --- | --- | --- |
| gvisor.dev/gvisor | 39ed1f5ac29c (2025-05-03) | Apache-2.0 |
| github.com/google/btree | v1.1.2 | Apache-2.0 |
| golang.org/x/sys | v0.33.0 | BSD-3-Clause |
| golang.org/x/term | v0.32.0 | BSD-3-Clause |
| golang.org/x/time | v0.7.0 | BSD-3-Clause |

Copies of their licenses are in third_party/licenses and are included in release
archives. The Go runtime retains the Go project's BSD-style license; its notice
is included in third_party/licenses/go-runtime.txt.

Public interoperability observations were cross-checked against
[Bruce-lhq/univpn-connect](https://github.com/Bruce-lhq/univpn-connect), an MIT
licensed independent project. Its protocol notes are referenced in
docs/protocol.md; its Python/OpenConnect code is not bundled or linked here.

No UniVPN/Leagsoft/Huawei binary, private gateway configuration, credentials,
certificate, original guide, or workbook is distributed. Product names identify
compatibility, and their trademarks remain with their respective owners.
