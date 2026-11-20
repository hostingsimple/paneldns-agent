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

> Status: pre-release (0.1.0-dev). Packaging and the signed APT/YUM repository come later.

## How it works

1. `paneldns-agent enrol --url https://app.paneldns.example --code <one-time code>` (as root)
   detects the zone source, generates an Ed25519 key pair on the server, and sends only the
   public key with the code.
2. `paneldns-agent run` (the systemd unit) scans the zones every `INTERVAL` seconds, pushes
   changed zones and deletions, sends a heartbeat, and every `RESYNC` seconds sends a full
   inventory of names and content hashes.
3. `paneldns-agent --check` is a read-only self-test for support.

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

Design choices are recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md).

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
gofmt -l .        # must print nothing
```

## Dependencies

None outside the Go standard library. `crypto/ed25519`, `crypto/sha256`, `compress/gzip`,
`net/http` and `encoding/json` cover everything the agent needs. Fewer dependencies means less
code to audit in a program that root installs on every hosting server.

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
| `internal/protocol/` | Ingest API wire types (and, from t042, signing and the client) |
| `internal/version/` | Version string, set at build time |
| `packaging/` | Sample config (and, later, the systemd unit) |
| `docs/` | Protocol and design decisions |
| `testdata/` | Shared fixtures the PanelDNS app copies and pins by checksum |

## Licence

Not yet chosen; see the open question in the specification. Until a licence is published, no
licence is granted.
