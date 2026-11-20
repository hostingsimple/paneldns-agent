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
| `internal/version/` | Version string, set at build time |
| `packaging/` | Sample config (and, later, the systemd unit) |
| `docs/` | Protocol and design decisions |
| `testdata/` | Shared fixtures the PanelDNS app copies and pins by checksum |

## Licence

Not yet chosen; see the open question in the specification. Until a licence is published, no
licence is granted.
