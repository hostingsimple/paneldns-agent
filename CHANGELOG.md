# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`--check` run as root no longer stops the service from syncing.** A root `--check` (for
  example `sudo paneldns-agent --check`) took a sequence number and left `sequence.json` and its
  lock owned by root, so the service could no longer sign a request and stopped pushing until the
  files were given back by hand. Run as root, `--check` now re-runs itself as `paneldns-agent`,
  which also means it shows exactly the service's access; it first gives back those two files if
  an earlier root run left them owned by root (D-34). Found in the PanelDNS b10 load test.

## [0.1.6] - 2026-11-27

Lab check of the agent on HestiaCP, Virtualmin, ISPConfig and CyberPanel (2026-11-27).

### Fixed

- **CyberPanel zones can be read.** CyberPanel stores TXT records without quotes, and PowerDNS 5's
  HTTP API then refuses the whole zone (HTTP 500), so no zone with an SPF record could be synced.
  When the API refuses a listed zone, the agent now reads it by AXFR from the local PowerDNS with
  `dig` (D-33). Found on a CyberPanel 3.0 lab server.
- **`acl` is now a dependency of the packages** instead of a recommendation, so a server that
  doesn't install recommendations still gets `setfacl` and the agent can read zone files a panel
  writes without world read (ISPConfig) (D-32).

### Changed

- Enrol's message for a PowerDNS without its HTTP API (CyberPanel's default) lists the `pdns.conf`
  lines to add.

## [0.1.5] - 2026-11-24

Security review 2026-11, the remaining agent findings.

### Security

- Enrol and `fix-acls` (both root) no longer hand `setfacl` a path that can change under them.
  The plan notes the object each path reaches, walking from `/` without following any symbolic
  link; when the ACL is set, the path is walked again the same way and must reach that same
  object, and `setfacl` gets the open descriptor (`/proc/self/fd/N`), not the path. A user who
  can write a directory on the path (a HestiaCP home directory, a `named`-writable zone directory)
  could swap a component for a link between the plan and `setfacl` and so have root grant the
  agent read access to any file (review A-3, residual of 0.1.4's fix). A path that changed stops
  enrol and is reported by `fix-acls`; a file with several hard links in such a directory is
  refused too.
- The service's unit now also denies link-local (cloud metadata services), multicast, RFC 1918,
  shared (RFC 6598) and IPv6 unique local addresses, not only loopback (review A-11), and hides
  home directories (`ProtectHome=yes`) instead of making them read-only on every server (review
  A-12). Enrol writes the exceptions this server needs into drop-ins: `IPAddressAllow=` for the
  PowerDNS API, the resolvers in `/etc/resolv.conf` and PanelDNS's own addresses when they fall
  in a denied range, and `ProtectHome=read-only` only when zone data lives under `/home`
  (HestiaCP), also through a symbolic link. The ACL watcher's home rule now follows links too.

- `named`, `named-compilezone`, `setfacl` and `systemctl` are run by absolute path, found in
  `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin` or `/usr/local/bin` (in that order)
  and only when root owns the file and its directory and nobody else can write them; `$PATH` is
  never used. Enrol and `fix-acls` run as root, so a `PATH` set by the caller, or a writable
  directory early in it, chose the binary root ran (review A-13).

### Added

- `paneldns-agent update-units` (root) rewrites this server's unit drop-ins (the agent's and the
  ACL watcher's). The package runs it on upgrade before restarting the agent, so a server
  enrolled with 0.1.4 or earlier gets its exceptions before the stricter unit starts; `fix-acls`
  run by hand does it too. `--check` warns when the drop-ins are out of date (a resolver that
  moved). Removing the package now also deletes the agent's own drop-ins.

### Fixed

- A key rotation whose answer was lost (a timeout, a proxy error, a crash or restart right
  after `/rotate`) no longer locks the agent out a day later. PanelDNS may already have switched
  to the new key, accepting the old one for 24 hours only, but the agent threw the new key away
  (also at every start), so the server had to be enrolled again (review A-15). The agent now
  drops the new key only when PanelDNS refuses the rotation outright; otherwise it keeps both,
  goes on with the old one, and before its next requests asks again and, if needed, checks
  whether PanelDNS accepts the new key, then keeps whichever key PanelDNS holds. A switch
  interrupted by a crash is finished at the next start. Works with the released PanelDNS; no
  server change.
- Enrol reads `pdns.conf` as PowerDNS does: a `#` after white space starts a comment, so
  `api=yes  # on` is on (it was refused), and a line ending in `\` continues on the next.
  Booleans follow PowerDNS's `mustDo`: only `no` and `off` are off. `false`, `0` and other values
  PowerDNS also reads as on are now refused with that explanation rather than taken as off; write
  `api=yes`. The refusal says whether `api` was missing or set to off.
- The ACL plan reads named.conf's `key-directory` (options, views, zones). A DNSSEC key folder
  outside the zone directories was not known to the plan; now no key folder gets `rx` or a
  default ACL, even when a zone `$INCLUDE`s a public key from it, and `fix-acls` removes any agent
  entry from the folder and its key files.

## [0.1.4] - 2026-11-24

Security review 2026-11 (agent findings A-1 to A-10; A-3 for planted links only).

### Security

- Enrol now trusts a running `named` process to say which named.conf it reads only when the
  process runs as root or as the `named`/`bind` user. Before, any process called `named` counted,
  so a local user could choose the config enrol reads, and with it the zones the agent pushes and
  the files enrol grants it read access to.
- `enrol --code -` reads the one-time code from standard input, and `install.sh --code -` does
  the same. A code on the command line is visible to every user of the server while enrol runs,
  and whoever sends it first enrols their own key; enrol and `install.sh` now warn when given
  the code that way. The dashboard's install command should switch to `--code - <<< 'CODE'`.
- The read-access plan of enrol and `fix-acls` (both root) no longer grants an ACL through a
  symbolic link unless root owns the link and the directory holding it can only be changed by
  root. `setfacl` follows links, so a link a user or the `named` user could plant in a planned
  path redirected the grant to any file. Such paths are skipped with a warning; that zone then
  fails to read and is reported.
- The running agent applies the `$INCLUDE` rule enrol already enforced: a zone whose `$INCLUDE`
  (at any depth) leaves named's directory and the zone directories, or names the agent's state
  directory or key material, is not read (reported as `read_failed`). Before, `named-compilezone`
  and the built-in parser read any file the agent could open into the zone.
- The PowerDNS API client no longer follows redirects. Go forwards the `X-API-Key` header
  (a read-write key) to the redirect target, wherever it is.
- A zone whose name starts with `-` is not passed to `named-compilezone`, where it would be read
  as an option. Zone files and `$INCLUDE`d files the agent reads itself are capped at 16 MB, the
  limit `named-compilezone` output already had.
- Before each PowerDNS API request the agent checks, in `/proc/net/tcp` and `tcp6`, that every
  socket listening on the API address belongs to root or the `pdns`/`powerdns` user, and sends
  no API key otherwise. Any local user can listen on a free port above 1023, for example while
  PowerDNS restarts.
- Enrol (root) changes the owner of the state directory and of the files it wrote there only,
  instead of everything it finds in that agent-owned directory, and skips files with more than
  one hard link.
- A zone directory that also holds named's configuration or key files (Debian's `/etc/bind`, a
  directory with `rndc.key`, `*.private` or `*.key` files) no longer gets a default ACL. A key
  created there later (`rndc-confgen -a`, `tsig-keygen > x.key`) inherited
  `u:paneldns-agent:r`. New zone files in such a directory get their read ACL from the root
  watcher. `fix-acls` removes the agent's default entry that an earlier version left on such a
  directory, and the agent's entry on key files there, without recalculating the mask, and the
  plan warns about key files every local user can read (DECISIONS D-22).

### Fixed

- Enrol treated a bare `api` line in `pdns.conf` as unset and reported the PowerDNS API as off.
  PowerDNS reads a bare boolean key as on; `api=no`, `api=off` and `api=false` still count as
  off.

## [0.1.3] and earlier

### Added

- Root ACL watcher (DECISIONS D-30): `paneldns-agent fix-acls` (root only) re-grants the agent's
  read access the enrol plan grants where it was lost, adding only the agent's entry and the
  needed mask bits (never lowering a mask or widening other entries, never touching key files),
  and logs one summary line. `paneldns-agent-acl.path` watches the zone directories and the
  directories of named.conf, its includes and the owner file, and starts the hardened oneshot
  `paneldns-agent-acl.service` (`CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID` only, no network, no
  `AF_UNIX`, writable paths limited to the planned ones). Enrol writes the per-server drop-ins
  (`watch.conf` for both units), runs one fix pass and enables the watcher (not with `--no-acl`
  or `--no-start`). `--check` reports whether the watcher is active and enabled and which zone
  directories it doesn't watch. Both units ship in the packages; removal disables them and
  deletes the drop-ins. CI reproduces the 0600 case and runs the units end to end.

### Fixed

- New zone files that cPanel creates with mode 0600 were unreadable by the agent: the inherited
  `u:paneldns-agent:r` entry landed with `mask::---` (cPanel DNSOnly lab test, cPanel 11.138 on
  AlmaLinux 9). Files a panel replaces with a new inode (cPanel's `rebuilddnsconfig` and
  named.conf) lost their ACL. The ACL watcher restores both; the `--check` hint now names
  `paneldns-agent fix-acls`.

### Changed

- Repository re-signing: APT `Valid-Until` is now 30 days (was 14), and `resign-schedule.yml`
  dispatches the re-sign on the 1st and 15th of each month (was every Monday). Each run still
  waits for the owner's approval; one missed approval leaves about two weeks of margin.

### Fixed

- The stable repository no longer lists pre-release packages: a release or re-sign on `main`
  removes any version containing `~` (the P5 dry run's `0.1.0~p5.1` had reached it).
- `enrol` reads the named.conf the running named uses (its `-c`, else the `named -V` default)
  instead of the first file found. On DirectAdmin for Ubuntu a stale `/etc/named.conf` sat next
  to the live `/etc/bind/named.conf` (prototype P1 on fusion).
- Releases build the pushed tag when a commit carries several tags (`GORELEASER_CURRENT_TAG`);
  v0.1.0 failed its reproducibility check because goreleaser stamped `0.1.0-p5.1`.

### Added

- Packaging and releases (t044): GoReleaser/nfpm `.deb` and `.rpm` for linux amd64/arm64 with
  the systemd unit, sample config and user-creating maintainer scripts; reproducible tarballs
  with `SHA256SUMS`; `release.yml` (tag-only build, provenance, owner-approved signing job in
  the `release-signing` environment that signs the packages, checksums and APT/YUM metadata and
  publishes to `paneldns-packages` with a deploy key); weekly re-sign dispatch; install docs
  (`docs/INSTALL.md`) and `packaging/install.sh`; a CI job that builds snapshot packages and
  installs them on Debian, Ubuntu and AlmaLinux; stricter workflow lint.

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
