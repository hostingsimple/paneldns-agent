# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Integration CI: the PowerDNS service image `powerdns/pdns-auth-49:4.9` does not exist; use
  `powerdns/pdns-auth-51:5.1.5`, as the PanelDNS app's DNS suite does, pinned by digest.
- Enrolment's read ACLs (and `tools/aclplan`) now follow `$INCLUDE` inside zone files,
  recursively, granting read on the included files and their directories; without this the
  agent couldn't read zones that include other files. Includes outside named's directory and
  the zone directories, or at key material, are refused (DECISIONS D-22).

### Changed

- An inline `key` statement in named.conf, or in an include that also holds other configuration,
  is now refused instead of warned about: enrolment stops before contacting PanelDNS, and
  `--check` fails, naming the file and line and telling you to move the key into a separate
  include the agent doesn't read (DECISIONS D-22).
- D-21: the loopback-resolver residual risk is recorded as accepted by the owner.

### Added

- Repository skeleton: Go module, command, configuration reader and writer, sample
  `/etc/paneldns-agent.conf`, README, security policy, code owners.
- Zone readers (t040): named.conf parser with includes, glob includes, views and per-zone
  `check-names`/integrity/format options; `named-compilezone` reader with the built-in RFC 1035
  parser as fallback; PowerDNS local API reader; system-zone list, `EXCLUDE` matching and the
  DNSSEC/private-type strip list.
- Change detection and the push cycle (t041): canonical zone form and `sha256:` content hash
  (serial ignored), per-zone fingerprints, full resync every `RESYNC` seconds with a re-read of
  every zone, batches of up to 100 zones or 8 MB, deletions, inventories paged at 20,000 names,
  exponential backoff with full jitter and `Retry-After`, offline behaviour that sends only the
  latest content, empty-inventory and unreadable-include guards, atomic `state.json`.
- Enrolment and request signing (t042): `paneldns-agent enrol` with zone-source detection,
  Ed25519 key generated on the server (PKCS #8, mode 0600), identity, epoch and state files;
  signed requests with timestamp, nonce, epoch and sequence (sequence numbers allocated under a
  file lock so `--check` and the service never reuse one); `/epoch` recovery, key rotation,
  clear messages for a refused IP, a bad clock, a revoked key and a too-old agent;
  `paneldns-agent run`. `docs/PROTOCOL.md` describes the wire protocol and lists every choice
  made where the spec is ambiguous (P-01 to P-20).
- Shared fixtures in `testdata/`: the Ed25519 request-signing vector and the canonical-hash
  fixture, with `SHA256SUMS` (regenerate with `go test ./internal/fixtures -update`).
- Owner files and hardening (t043): cPanel `/etc/userdomains` (and `/etc/userdatadomains`) and
  DirectAdmin `/etc/virtual/domainowners`; the systemd unit with the spec 7.9 hardening
  (dedicated user, `ProtectSystem=strict`, `NoNewPrivileges`, no capabilities, seccomp filter,
  no loopback access, key files inaccessible, 128 MB memory cap, idle I/O); enrol grants read
  ACLs, writes the loopback drop-in when needed, runs `--check` as the agent user and starts
  the unit; `paneldns-agent --check` (`--zone`, `--json`).
- Licence: Apache-2.0 (`LICENSE`, `NOTICE`), copyright HostingSimple.
- CI (written, not yet run): lint (gofmt, vet, staticcheck, workflow rules), unit tests with
  `-race` and cross-compiles, govulncheck, a build-twice reproducibility check, a testdata scan
  for non-documentation names and addresses; integration tests against real `named`,
  `named-compilezone` and PowerDNS, and an ACL-only access test. Actions pinned by commit SHA.
  `tools/aclplan` prints the ACL commands enrol would run.
