# paneldns-agent

The agent for **Panel Sync**, a PanelDNS feature. It runs as a systemd service on a hosting
server (cPanel, DirectAdmin, another panel, or plain BIND/PowerDNS), reads that server's own DNS
zones, and pushes every zone in full to the PanelDNS ingest API over HTTPS, with each request
Ed25519-signed.

**It only pushes.** PanelDNS never logs in to, polls or connects to the hosting server, and holds
no credential for it. The agent opens no listening socket, never writes zone files, named
configuration or panel data, and never downloads or replaces code.

This repository is public so that a hosting company can read exactly what it installs, rebuild it
and compare the result with the published packages.

> Status: pre-release (0.1.0-dev); no release has been published yet.

## Install

Signed `.deb` and `.rpm` packages come from `https://packages.paneldns.com`; see
[`docs/INSTALL.md`](docs/INSTALL.md). Signing key fingerprint:
`AAE3 B3B1 258C AAB0 ED1A  E1C3 697D 46A6 32CB 9283`.

## How it works

1. `paneldns-agent enrol --url https://app.paneldns.example --code <one-time code>` (as root)
   detects the zone source and the panel's owner file, generates an Ed25519 key pair on the
   server, sends only the public key with the code, grants the `paneldns-agent` user read
   access through POSIX ACLs (never group membership in `named`, `bind` or `pdns`), runs
   `--check` as that user and starts the service. It also enables `paneldns-agent-acl.path`, a
   root watcher that runs `paneldns-agent fix-acls` when the panel writes zone files, because
   panels such as cPanel create new zone files with mode 0600, which masks the agent's
   inherited ACL entry. `--no-acl` prints the `setfacl` commands instead; `--no-start` leaves
   the service and the watcher stopped.
2. `paneldns-agent run` (the systemd unit) scans the zones every `INTERVAL` seconds, pushes
   changed zones and deletions, sends a heartbeat, and every `RESYNC` seconds sends a full
   inventory of names and content hashes.
3. `paneldns-agent --check` is a read-only self-test: config and file modes, the zone source and
   view, the first five zones read and hashed, zones the agent can't read, the owner file,
   PanelDNS reachability, certificate, key, IP allowlist, clock skew and version. It exits 1 on
   any failure. `--check --zone example.com` prints one zone's canonical text and hash;
   `--json` gives the report as JSON.

## What it reads

- **BIND** (`ZONE_SOURCE=bind`): named.conf and its includes, one view (`VIEW`, else `_default`,
  else `external`, else the first view matching any client), every `type primary`/`master` zone
  with a `file`. Each changed zone is read with `named-compilezone` (journal applied, `$INCLUDE`
  and `$GENERATE` expanded, the zone's own `check-names` and integrity options), or with the
  built-in parser when `named-compilezone` isn't installed.
- **PowerDNS** (`ZONE_SOURCE=powerdns-api`): the local HTTP API on a loopback address, zone list
  and `/export`. Only Native and Master zones.
- System zones (`localhost`, loopback and RFC 1918 reverse zones and the like) are never sent.
  DNSSEC records (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY) and private types
  (TYPE65280–TYPE65534) are stripped; a zone that had DNSKEY or RRSIG records is reported as
  signed at the source.

Design choices are recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md); the wire protocol,
including the canonical zone text and content hash, in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Security model

- The private key is generated on the server and never leaves it (`/var/lib/paneldns-agent/agent.key`,
  mode 0600). PanelDNS stores only the public key, so a leak on the PanelDNS side can't be used to
  push zones.
- Every request is signed with Ed25519 over the method, path, time stamp, a random nonce, the
  server-issued epoch, a sequence number that only increases, and the SHA-256 of the body bytes
  as sent. Replays and reordered requests are refused by the server.
- HTTPS only, certificate always verified. PanelDNS also refuses requests from addresses that
  are not on the server's IP allowlist; the agent says so plainly in its log and in `--check`.
- The service runs as the `paneldns-agent` user with no capabilities, `NoNewPrivileges`,
  `ProtectSystem=strict` (only `/var/lib/paneldns-agent` is writable), `ProtectHome=read-only`, a
  `@system-service` seccomp filter, no access to loopback addresses (so not to rndc), the rndc
  key and `pdns.conf` made inaccessible, and `MemoryMax=128M`; see
  [`packaging/systemd/paneldns-agent.service`](packaging/systemd/paneldns-agent.service). When
  the PowerDNS API or the system resolver is on a loopback address, enrol adds a drop-in with
  `IPAddressAllow=` for exactly those addresses.
- The agent itself never runs as root. The one root piece is the ACL watcher's oneshot
  `paneldns-agent-acl.service` (`fix-acls`): it only adds the agent's read entry and the read bit
  of the mask on the files and directories enrol planned, never on key files, never lowering a
  mask or widening anyone else's access. It runs with `CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID`
  only, no network and no `AF_UNIX`, and writes only to the planned paths; see
  [`packaging/systemd/paneldns-agent-acl.service`](packaging/systemd/paneldns-agent-acl.service).

## Owners

The agent reports, per zone, the hosting account that owns it, read from the panel's own owner
file (never its API): cPanel `/etc/userdomains` (or `/etc/userdatadomains`), DirectAdmin
`/etc/virtual/domainowners`. Other panels send no owner in this version.

## Configuration

`/etc/paneldns-agent.conf`; see [`packaging/paneldns-agent.conf`](packaging/paneldns-agent.conf)
for every key and its default.

## Building

Go 1.27 or later. No cgo.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -buildid= -X github.com/hostingsimple/paneldns-agent/internal/version.Version=0.1.0" \
  -o dist/paneldns-agent-linux-amd64 ./cmd/paneldns-agent
```

The same command with `GOARCH=arm64` builds for arm64. Builds are reproducible: the same source
and Go version give the same bytes.

## Tests

```sh
go vet ./...
go test ./...
gofmt -l .                          # must print nothing
go run ./tools/repocheck testdata   # documentation names and addresses only
go test -tags integration ./internal/integration/ -v   # needs BIND 9 and PowerDNS; see CI
```

CI (`.github/workflows/`) also runs staticcheck, govulncheck, a reproducibility build and the
integration tests against real `named`, `named-compilezone` and PowerDNS.

## Dependencies

None outside the Go standard library (`go.mod` has no `require`). `crypto/ed25519`,
`crypto/sha256`, `crypto/x509` (PKCS #8 key file), `compress/gzip`, `net/http` and
`encoding/json` cover everything the agent needs. The zone and named.conf parsers are written
here rather than taken from `github.com/miekg/dns`, because the canonical hash must be
reproduced exactly by the PanelDNS (PHP) side from a short written rule set, not from a
library's presentation format (see `docs/DECISIONS.md` D-01). Fewer dependencies also means
less code to audit in a program that root installs on every hosting server. CI tools
(staticcheck, govulncheck) are run at pinned versions with `go run` and are not dependencies of
the agent.

## Repository layout

| Path | What |
|---|---|
| `cmd/paneldns-agent/` | The command |
| `internal/config/` | `/etc/paneldns-agent.conf` reader and writer |
| `internal/namedconf/` | named.conf parser: includes, views, primary zones and their options |
| `internal/zonefile/` | RFC 1035 zone-file parser and the DNSSEC/private-type strip list |
| `internal/source/` | Zone sources: BIND (named.conf + `named-compilezone`) and the PowerDNS local API |
| `internal/filter/` | System zones and `EXCLUDE` patterns |
| `internal/engine/` | Scan, change detection, batching, retries, inventory, heartbeat |
| `internal/backoff/` | Exponential backoff with full jitter |
| `internal/state/` | Atomic state files in `/var/lib/paneldns-agent` |
| `internal/protocol/` | Ingest API: wire types, Ed25519 request signing, HTTPS client |
| `internal/enrol/` | `enrol`: detection, key generation, enrolment, read ACLs |
| `internal/host/` | Host name, OS, panel and public addresses |
| `internal/owners/` | Panel owner files |
| `internal/check/` | `--check` |
| `internal/fixtures/` | Checks and regenerates the shared fixtures in `testdata/` |
| `internal/version/` | Version string, set at build time |
| `internal/integration/` | Tests against real BIND 9 and PowerDNS (`-tags integration`) |
| `tools/repocheck/` | CI rules: testdata scan, workflow pinning and permissions |
| `tools/aclplan/` | Prints the read-ACL commands enrol would run |
| `packaging/` | Sample config, hardened systemd unit, package scripts, repository publishing, `install.sh` |
| `.goreleaser.yaml` | Package and tarball build (GoReleaser/nfpm) |
| `docs/` | Protocol and design decisions |
| `testdata/` | Shared fixtures the PanelDNS app copies and pins by checksum ([README](testdata/README.md)) |

## Licence

SPDX-License-Identifier: Apache-2.0

Copyright 2026 HostingSimple. Licensed under the Apache License, Version 2.0; see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
