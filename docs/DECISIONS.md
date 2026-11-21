# Design decisions

Choices made while building the agent where the specification
(`docs/specs/panel-cluster-sync.md` in the PanelDNS app repository, "the spec") is silent,
ambiguous or contradicts itself. Protocol choices that the PanelDNS ingest side must match are in
[`PROTOCOL.md`](PROTOCOL.md); this file covers the agent's own behaviour. Each entry names the
spec section it touches. The owner may overrule any of them.

## D-01 No third-party dependencies (7.1, 7.11)

The agent uses only the Go standard library. The obvious candidate, `github.com/miekg/dns`, was
considered for zone parsing and rejected: the canonical hash (8.7) must be reproduced exactly by
the PHP side from the pushed text, so the canonical form has to be defined in a few pages of
rules (PROTOCOL.md section 5) rather than as "whatever a Go library prints". A token-level parser
of ~400 lines does that and keeps the audited surface small.

## D-02 named.conf is read by the agent's own parser, not `named-checkconf -p -x` (7.3, 7.9)

Spec 7.3 lists zones with `named-checkconf -p -x`, which reads every include. Spec 7.9 says the
agent must not be able to read rndc or TSIG key files at all, and those are normally pulled in
with `include "/etc/rndc.key";`. Run as the unprivileged agent, `named-checkconf` stops with
"permission denied" on that include, so on a correctly hardened server it would always fail.

The agent therefore parses named.conf itself (`internal/namedconf`): the full statement grammar,
the three comment styles, `include` (also with glob patterns) at any level, views. The parser
also reads `named-checkconf -p` output, which is a subset. An include that can't be read because
of **permission denied** is skipped quietly and listed by `--check`; any other unreadable include
is a warning. To stop a lost read permission from looking like deleted zones, the sync engine
refuses to send an inventory or deletions while a config file that declared zones in the last
good scan can't be read (see D-14).

## D-03 The agent keeps the SOA record (7.3, 8.4)

Spec 7.3 says the agent strips the types in the app's `ZONE_READ_SKIPPED_TYPES`, which include
SOA. Spec 8.4 shows the SOA in the pushed text and 7.4 hashes "with the SOA serial removed", so
the SOA must be there. The agent strips RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY, CDS, CDNSKEY and
TYPE65280–TYPE65534, and keeps SOA; the server strips SOA itself (10.1 step 3).

## D-04 Relative paths in named.conf (7.3)

named resolves relative paths against its working directory. The agent resolves a relative
`include` (in any file) against the directory of the main named.conf, and a relative zone `file`
or `journal` against `options { directory }`. Without a `directory` option the main named.conf's directory is used.
Panels write absolute include paths, so this only matters for hand-made configs.

## D-05 Chroot handled by path prefix, not `-t` (7.2, 7.3)

`named-compilezone -t <dir>` calls chroot(2), which needs root; the agent has no capabilities.
With `CHROOT` set, the agent prefixes the chroot to every absolute path named would open
(includes, `directory`, zone files, journals, pid file) and passes host paths to
`named-compilezone`. `ZONES_FILE` is the host path of named.conf (for Plesk on RHEL,
`/var/named/run-root/etc/named.conf`; `/etc/named.conf` is a symlink to it). An absolute
`$INCLUDE` inside a zone file of a chrooted named is not rewritten when `named-compilezone` reads
it; the agent's own parser does rewrite it.

## D-06 `named-compilezone -i` mode (7.3)

Spec 7.3 passes the zone's "integrity options". named's `check-integrity` (default yes for a
primary zone) checks in-zone data only; `named-compilezone -i full` would also look names up in
the DNS, which the agent must not do. The mapping is: `check-integrity no` → `-i none`;
`check-integrity yes` with `check-sibling yes` (both default) → `-i local`; with
`check-sibling no` → `-i local-sibling`. `-k` takes the zone's effective `check-names` (zone, then
`check-names primary|master <mode>` in the view, then in options, default `fail`). `-f` follows
`masterfile-format`; a zone-level `journal` is passed with `-J`.

## D-07 Without `named-compilezone` (7.3)

`named-compilezone` is the reader of record. If it is not installed, the agent falls back to its
own parser, which handles `$ORIGIN`, `$TTL`, `$INCLUDE`, parentheses, quoted and multi-string
TXT, escapes, TTL units and class/TTL in either order, but refuses a zone that has a journal, is
not in text format, or uses `$GENERATE`. `--check` says which reader is in use.

## D-08 Which view is read (7.3, decision 23)

`VIEW` if set; else the view named `_default`; else the view named `external`; else the first
view in file order that matches any client, meaning it has no `match-clients` or its
`match-clients` list contains a plain `any` element. If no view qualifies, the agent stops with
an error asking for `VIEW`. Zones declared only in other views are listed by `--check` and are
never sent or counted as deleted.

## D-09 System zones (7.3)

The agent's list matches names exactly: `.` (the root hint), `localhost`, `localdomain`,
`localhost.localdomain`, `0.in-addr.arpa`, `127.in-addr.arpa`, `0.0.127.in-addr.arpa`,
`255.in-addr.arpa`, the `::1` reverse zone, `10.in-addr.arpa`, `16.172.in-addr.arpa` to
`31.172.in-addr.arpa` and `168.192.in-addr.arpa`. System zones are neither pushed nor listed in
the inventory (7.4). Secondary, forward, stub, hint, `in-view` and file-less zones are skipped
because they are not primary zones with a file.

## D-10 PowerDNS (7.3)

Zones of kind `Native`, `Master` or `Primary` are read; `Slave`, `Secondary`, `Producer` and
`Consumer` are skipped. The fingerprint is `serial` plus `edited_serial` from the zone list; a
change made without a serial change is picked up by the next full resync, which re-reads every
zone (D-13). The export is accepted as `text/plain` or as the older `{"zone": "..."}` JSON.

## D-11 Change detection (7.4)

The fingerprint is: BIND, the zone file's size and mtime (nanoseconds), the journal's, the
zone's `check-names`, integrity and format options, and the size and mtime of every file the
zone `$INCLUDE`s at top level (found by a cheap scan of the zone file whenever its own stamp
changes); PowerDNS, `serial` and `edited_serial`. A zone whose fingerprint changed is read and
hashed; it is pushed only if the hash differs from the hash the server last acknowledged, so a
serial bump alone sends nothing. A zone that fails to read keeps its last acknowledged content on
the server, is reported in the heartbeat, and is retried every scan; it is never treated as
deleted.

## D-12 What "acknowledged" means (7.5, 8.4)

The agent records a zone's hash as acknowledged when the server answers `accepted`,
`unchanged`, `stored`, `skipped_records`, `held` or `excluded`. `refused` records the hash as
refused: that exact content is not sent again until it changes, or the server asks for it (an
inventory's `need` or a heartbeat's `resync_names`). An unknown status or a missing result leaves
the zone pending, so it is sent again next cycle. A non-retryable 4xx for a whole `/zones` batch
(not 401, 403, 409 `epoch_stale` or 426) marks every zone in the batch refused with reason
`http_<status>`. A changed owner (panel account) makes the agent push the zone again even if its
content is unchanged.

## D-13 Full resync re-reads every zone (7.4)

On start, every `RESYNC` seconds after the last acknowledged inventory, after an epoch reset, and
when the server asks, the next scan re-reads every zone (not only changed fingerprints) and the
inventory follows it. This catches edits that left the fingerprint unchanged. While PanelDNS is
unreachable the inventory stays due, but scans after the first full one are incremental again, so
an offline agent doesn't compile every zone every minute.

## D-14 Guards before reporting (7.4)

A scan is refused, and nothing but a heartbeat with the error is sent, when (a) the zone listing
fails, (b) a config file that declared zones in the last good scan can't be read now (D-02), or
(c) the spec's empty-inventory guard trips: the scan found no zones, or fewer than half of the
last acknowledged inventory, and the DNS server is not confirmed running. "Running" for BIND
means named's pid file (`pid-file` option or the usual paths) names a live process; for PowerDNS
that the API answers. An unknown state counts as not running, so the guard errs on the side of
not deleting.

## D-15 Offline behaviour and the state files (7.5)

What is pending is derived from the state, not queued: a zone is pending while its current hash
differs from the acknowledged one, and a deletion is pending while a name the server
acknowledged is gone. After an outage the agent therefore sends each zone's latest content once.
Zone text read during a scan is kept in memory (up to 8 MB) until it is acknowledged; zones beyond
that are read again when sent. `state.json` holds the per-zone fingerprints and hashes; the epoch
and sequence live in `sequence.json` (see PROTOCOL.md) because `--check` must take a sequence
number while the service runs.

## D-16 Backoff (7.5)

Full jitter: each delay is uniform in [0, min(10 min, 5 s × 2^n)), with a floor of 1 s. A
`Retry-After` (seconds or HTTP date, capped at one hour) wins when it is longer. 401 and 426 wait
the maximum 10 minutes between attempts. Scans continue on their interval during backoff.

## D-17 Keys and enrolment files (7.1, 8.1)

The key pair is generated on the server with `crypto/rand` and stored as PKCS #8 PEM in
`/var/lib/paneldns-agent/agent.key`, mode 0600, owner `paneldns-agent` (readable with
`openssl pkey`). The agent refuses to start if the key file is readable by group or others.
Enrolment writes nothing until PanelDNS has accepted the code; then it writes the key,
`identity.json`, `sequence.json` (the epoch from the answer) and an empty `state.json`, so the
first run sends a full inventory without an extra `/epoch` call. A re-enrol replaces all four.
The enrolment code may be given as `--code` or in `PANELDNS_ENROL_CODE`.

## D-18 Zone source detection at enrolment (7.1, 7.3)

In order: a PowerDNS `bind-config=` pointing at an existing named.conf (cPanel's PowerDNS with
the bind backend) → BIND with that file; a chrooted named (`ROOTDIR` in `/etc/sysconfig/named`,
an enabled `named-chroot.service` with `/var/named/chroot/etc/named.conf`, or `/etc/named.conf`
linking into `/var/named/run-root` or `/var/named/chroot`) → BIND with `CHROOT`; the first of
`/etc/named.conf`, `/etc/bind/named.conf`, `/etc/namedb/named.conf`,
`/usr/local/etc/namedb/named.conf` → BIND; else a `pdns.conf` with `api=yes` and a plain
`api-key` on a loopback (or wildcard) `webserver-address` → `powerdns-api`, the key copied to
`pdns-api-key` (0600). A hashed PowerDNS API key can't be copied, so enrol stops and says what
to do. The Plesk chroot detection is unverified until tried on a Plesk server.

## D-19 Key rotation (8.1)

On `rotate_key: true` the agent writes the new key to `agent.key.next`, calls `/rotate` signed
with the old key, and only then renames the new key over `agent.key` and stores the new key id.
If the agent dies in between, the old key still works (spec: until the new one is used once, or
24 hours) and the server asks again; a stale `agent.key.next` is removed at start.

## D-20 Owner files (7.3, 18.4 item 4)

cPanel `/etc/userdomains` and DirectAdmin `/etc/virtual/domainowners` are read as `domain: user`
per line; cPanel's `/etc/userdatadomains` (`domain: user==owner==...`) works too. Domains are
matched exactly after lower-casing and dropping a trailing dot; cPanel's `* : nobody` catch-all,
comments, lines without a colon and users that are not 1–64 characters of `A-Za-z0-9._-` are
skipped. A later line wins. The file is re-read only when its size or mtime changes. Enrol
picks the file from the detected panel (cPanel, DirectAdmin); other panels send no owner in
v1. Both formats remain unverified against the owner's servers until prototype P1.

## D-21 Loopback access and the unit drop-in (7.9)

The unit has `IPAddressDeny=localhost`, so the agent can't reach rndc on 127.0.0.1:953. Spec
7.9 allows `IPAddressAllow=` for the PowerDNS API address. A second case the spec doesn't
mention: if `/etc/resolv.conf` points at a loopback resolver (systemd-resolved's `127.0.0.53`,
or a local named at `127.0.0.1`, common on cPanel servers), the agent could not resolve the
PanelDNS host name at all. Enrol therefore writes
`/etc/systemd/system/paneldns-agent.service.d/10-paneldns-network.conf` with
`IPAddressAllow=` for the PowerDNS API host and any loopback nameserver, and removes it when
neither applies. `IPAddressAllow=` can't name a port, so on a server whose resolver is a local
named on `127.0.0.1` the agent can reach `127.0.0.1:953` too; it still can't use rndc, because it
can't read the rndc key (ACLs plus `InaccessiblePaths=`). `--check` reports a failed lookup of
the PanelDNS host with this hint.

**Accepted** by the owner (2026-11-20): on a server whose resolver is a local named on
`127.0.0.1`, the agent can reach `127.0.0.1:953`; that residual risk is accepted, since the rndc
key stays unreadable.

## D-22 Read ACLs (7.1 step 3, 7.9)

Enrol (as root) grants, with `setfacl`, `u:paneldns-agent:r` on named.conf, on every readable
include except files holding only `key`/`tsig-keygen` statements, on every zone file, existing
journal and the owner file; `u:paneldns-agent:rx` plus the default ACL `u:paneldns-agent:r` on
each zone directory (new zone files and journals inherit it); and `u:paneldns-agent:x` on parent
directories that others can't search. It never adds group membership. `--no-acl` prints the commands instead of running them. Panels
do lose these ACLs (the cPanel lab test found new zone files created 0600, so masked); the root
watcher of D-30 restores them. `--check` opens every zone file as the agent and fails with the
list of unreadable ones.

**`$INCLUDE` in zone files** (found by the CI ACL test). The plan follows `$INCLUDE` in every
text-format zone file, recursively up to 8 levels (the parser's limit), resolving relative names
against named's `directory` as named and `named-compilezone -w` do, and absolute names inside the
chroot. Each included file gets `u:paneldns-agent:r` and its directory `rx` plus the default
`r` (parents `x`), like a zone file. Enrol refuses, naming the zone file, line and target:
an include outside named's `directory` and the zone directories (after resolving `..`); one of
the key files the unit makes inaccessible or a `.private` DNSSEC key; and any included file whose
content holds key material (a `key`/`tsig-keygen` statement, a `secret "..."`, or
`Private-key-format:`). Public `K*.key` DNSKEY files are allowed. An include that can't be read
even as root is a warning: that zone fails to read and is reported, but enrolment goes on.

**Inline keys are refused** (owner decision, 2026-11-20; it replaced a warning). A `key` (or
`tsig-keygen`) statement, at top level or directly inside a `view`, in the main named.conf or in
an include that also holds other configuration, sits in a file the agent must read, so the agent
would see the secret. Enrol refuses before it contacts PanelDNS (nothing is written, the code is
not used), the ACL plan refuses, and `--check` fails; the message names each file and line and
says to move the key into a separate file holding only key statements, included from named.conf
and not readable by `paneldns-agent`. Such a key-only include is the supported setup and is never
flagged, even when `--check` runs as root and can read it. Key names inside other blocks (for
example the `keys { ... }` list of `controls`) are references, not secrets, and are ignored. The
running service does not stop on an inline key; it never sends config contents anyway.

## D-23 Low priority for `named-compilezone` (7.8)

Instead of wrapping each run in `nice 10` and `ionice -c3`, the unit sets `Nice=10` and
`IOSchedulingClass=idle`, which the agent and every `named-compilezone` child inherit. It needs
no extra binaries and no `ioprio_set` call inside the seccomp filter. At most two compiles run at
a time.

## D-24 `--check` (7.7)

`--check` reads the config, the state files, the zone source and the owner file, and sends one
heartbeat with `"check": true`. It takes a sequence number (under the same lock as the service)
but never writes `state.json`. It reads the first five zones that would be synced, opens every
zone file to find ones the agent can't read, and reports the service's last scan, failed,
refused and signed zones from `state.json`. Clock skew is measured against the HTTP `Date`
header of the heartbeat answer. Exit status 1 on any FAIL. `--check --zone NAME` only reads that
zone and prints its canonical text and hash; it makes no network call. Enrol runs `--check` as
the agent user (not root), so it sees exactly the service's access, and starts the unit only if
it passes.

## D-25 Is named running? (7.4)

The empty-inventory guard needs to know whether named runs. The agent first reads named's pid
file and sends signal 0 (EPERM still means the process exists); if the pid file is unreadable,
which is common because `/run/named` is often private to named, it asks systemd
(`systemctl is-active` for `named.service`, `named-chroot.service`, `bind9.service`). Unknown
counts as not running.

## D-26 CI (7.11, 17)

`ci.yml`: gofmt, `go vet` (also with the `integration` tag), staticcheck, the workflow rules,
unit tests with `-race`, a linux/amd64 and linux/arm64 cross-compile, govulncheck, a
reproducibility job that builds both architectures from two copies of the tree in different
directories with separate build caches and compares the bytes, and the testdata scan plus the
shared-fixture check. `integration.yml` installs the distribution's BIND 9 (`named`,
`named-compilezone`, `nsupdate`) on the runner rather than using a BIND service container,
because the tests need `named-compilezone` locally and the fixture files mounted before the
container starts, which service containers can't do; PowerDNS runs as a service container:
`powerdns/pdns-auth-51:5.1.5`, the image and version the PanelDNS app's own DNS integration suite
uses, pinned by the digest of its multi-arch index
(`sha256:77ff4efdbb9ec30e9309c8a1cbed6121a67fa3be25c848bbbfa756fc75bf9a27`, read from Docker
Hub and confirmed against the registry). The API key comes from `PDNS_AUTH_API_KEY`; the image's
startup script writes the API and webserver settings to `pdns.d/_api.conf`, as in the app's
suite. The app also mounts a `pdns.d` file with `secondary=yes` and an empty
`security-poll-suffix`; a service container starts before checkout and can't mount repository
files, and neither setting matters to these tests (no zone transfers; the runner has outbound
network). Bump the version together with the app's suite. Actions are pinned by commit SHA, every workflow
has `permissions: {}` at the top and `contents: read` per job, `actions/setup-go` runs with
`cache: false`, and checkout keeps no credentials. `tools/repocheck workflows` enforces the pins,
the top-level permissions, no `pull_request_target`/`workflow_run`, and no `environment:` outside
`release.yml`.

`tools/repocheck testdata` scans every `testdata/` directory: IPv4 addresses must be in
`192.0.2.0/24` or loopback; IPv6 in `2001:db8::/32`, `::1` or `::`; names must end in
`example.com`, `example.net` or a reserved TLD (`example`, `test`, `invalid`, `localhost`,
`localdomain`, `local`), and `.arpa` names must be reverse zones of documentation, loopback or
private space. Other dotted words count as names only if the last label is a known TLD (every
two-letter label except common file extensions, plus a list of generic TLDs), so file names
like `named.conf` pass. It is a heuristic: a customer domain under an unlisted generic TLD would
slip through.

## D-27 Publishing to paneldns-packages with an SSH deploy key (7.10, 7.12)

Spec 7.10 and 7.12 name a fine-grained personal access token (`contents: write` on
`hostingsimple/paneldns-packages` only). The release workflow uses an **SSH deploy key** with
write access on that one repository instead (secret `PACKAGES_DEPLOY_KEY`, owner decision
2026-11-20). Both are least privilege, one repository and write. A deploy key isn't tied to a
person's account, doesn't expire with a token policy, can be created and revoked through the
repository's API, and can't be used against any other repository. Rotate it together with the
signing subkey each year. The job pins `github.com`'s published ed25519 host key
(`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`), and deletes the key file at the end.

## D-28 Release workflow shape (7.10)

- `build` has no secrets. It runs GoReleaser (pinned, checksum-verified) on the tag, after checking
  that the tag points at a commit on `main`, and checks that the packaged binary equals a plain
  reproducible `go build`.
- `attest` has no secrets and attests the tarballs and `.deb` files.
- `sign-and-publish` is the only job naming `environment: release-signing`, and the only one that
  reads secrets. It installs `gnupg`, `rpm`, `createrepo-c` and `apt-utils` from the runner's
  distribution before the key is imported, verifies the artefacts against `SHA256SUMS`, and refuses
  to run unless `packaging/gpg.key` is a real public key with fingerprint
  `AAE3B3B1258CAAB0ED1AE1C3697D46A632CB9283`. It imports the subkeys into a throw-away keyring,
  refusing if the primary secret key is present, since it must stay offline. It then signs the
  `.rpm` files (checked with `rpmkeys --checksig`), rewrites and signs `SHA256SUMS`, rebuilds and
  signs the APT metadata (`Valid-Until` 30 days) and the YUM metadata (`repomd.xml.asc`; clients
  expire it after `metadata_expire=1d`), commits to `paneldns-packages`, creates the GitHub
  release, and deletes the keyring, passphrase file and deploy key.
- `attest-signed` has no secrets and attests the signed `.rpm` files and the final `SHA256SUMS`,
  because signing changes the `.rpm` bytes.
- The keyless cosign signature of spec 7.10 step 2 is not added. The GitHub attestations are
  Sigstore-backed and verified with `gh attestation verify`; cosign can be added if wanted.
- Pre-release tags (containing `-`, e.g. `v0.1.0-p5.1`) publish to a `staging` branch of
  `paneldns-packages` and create a GitHub pre-release. Pages serves `main` only, so a P5 dry run
  never reaches customers.
- Fortnightly re-sign (owner decision 2026-11-21: `Valid-Until` 30 days, re-signed on the
  1st and 15th, so one missed approval is safe; was 14 days, weekly): `resign-schedule.yml` holds no secret and dispatches `release.yml` with
  `mode=resign` on the latest non-pre-release tag. That run needs the owner's approval like any
  signing run. The daily reminders from day 7 (spec 7.10) and the rollback mode (7.12) are not
  built yet.
- Pruning keeps the newest 5 versions per architecture and format. "Every version still at or
  above the minimum supported version" needs the minimum from PanelDNS and is not applied yet.
- `tools/repocheck workflows` (run in CI and as a unit test over the real workflows) enforces:
  actions pinned by SHA and images by digest; `permissions:` at the top and on every job; no
  `pull_request_target`/`workflow_run`; only `release.yml`'s `sign-and-publish` names an
  environment or reads secrets other than `GITHUB_TOKEN`; `release.yml` has no `pull_request`
  trigger and every one of its jobs is guarded by `startsWith(github.ref, 'refs/tags/v')`;
  `actions/setup-go` always runs with `cache: false`.

## D-29 Packages (7.1)

GoReleaser (nfpm) builds `.deb` and `.rpm` for amd64 and arm64. Each installs `/usr/bin/paneldns-agent`,
`/usr/lib/systemd/system/paneldns-agent.service`, `/etc/paneldns-agent.conf` (a config file, mode
0640 `root:paneldns-agent`, kept on upgrade), `/var/lib/paneldns-agent` (0700) and the licence
files. The packages recommend `acl` (for `setfacl`), and the `.rpm` depends on `shadow-utils`.
The maintainer scripts only create the system user and group, fix the two modes, run
`systemctl daemon-reload`, restart the unit on upgrade if it is enabled, and stop and disable it
on removal. They never enable it on a first install (enrol does that), and they make no network
call. `dpkg --purge` removes the state directory and leaves the user. File times come from the
commit, so packages and tarballs are reproducible. The package maintainer field is
`HostingSimple` until the owner names a contact address. `packaging/gpg.key` is a **placeholder**:
GitHub has no public copy of the key, and the release job refuses to run until the owner commits
the real public key.

## D-30 The root ACL watcher (7.9)

**Finding** (cPanel DNSOnly lab test: cPanel 11.138, AlmaLinux 9, PowerDNS with the bind backend
reading `/var/named`). cPanel edits existing zone files in place, so their ACL survives, but
creates every new zone file with mode 0600. The file inherits `default:user:paneldns-agent:r`
from the directory, but the 0600 mode sets its mask to `---`, so `getfacl` shows
`user:paneldns-agent:r--  #effective:---` and the agent can't read new zones. `rebuilddnsconfig`
also replaces `/etc/named.conf` with a new file (new inode, ACL gone; harmless there only
because it is 0644). No default ACL can prevent the first case: the creating process's mode caps
the mask.

**Decision** (owner, 2026-11-21): a root systemd path watcher; the agent stays non-root.
`paneldns-agent-acl.path` watches (`PathChanged=`) every zone directory and the directory of every
other planned file (named.conf, its includes, the owner file), plus `/etc/paneldns-agent.conf`,
and starts the oneshot `paneldns-agent-acl.service`, which runs
`paneldns-agent fix-acls --settle 3s --no-units`.

**Scope of the root helper.** `fix-acls` (refused unless euid 0) builds the same plan as enrol
(`PlanACLs`) and, for each planned path, reads its access and default ACL from the
`system.posix_acl_*` xattrs and adds only what is missing: `u:paneldns-agent:r` on files, `rx`
on zone directories plus the default `r`, `x` on parents. Access through "other" bits counts
(a replaced 0644 named.conf needs nothing). The mask becomes the current mask OR'd with the
needed bits, never lower (a 0660 file keeps group write), and any other group-class entry
(`group::`, named users and groups) that the wider mask would expose is cut back to what the old
mask let through, so only the agent gains access: the 0600 case becomes
`u:paneldns-agent:r--,g::---,m::r--`. It never touches files outside the plan, files the plan
skips as key-only, the rndc key and config files, or `*.private` DNSSEC keys, whatever a plan
says; inherited entries on other files in a zone directory (a new `K*.private` there) stay masked.
It writes `setfacl` with the agent's numeric uid, so no NSS lookup is needed. It logs one line:
`fix-acls: N fixed (paths), M already fine`, plus any errors (exit 1).

**Races.** Events that arrive while the oneshot runs merge into that run. So each run first waits
`--settle` (3 s; the panel writes the zone file, then named.conf), and passes again, after
another wait, while a pass still fixed something (at most 5 passes). Its own `setfacl` calls
trigger one more, empty run. The service has `StartLimitIntervalSec=0` (the settle delay spaces
starts); the path unit has `TriggerLimitIntervalSec=10s`, `TriggerLimitBurst=2000`, which only a
runaway loop should reach. Hitting it leaves the watcher failed until restarted, and `--check`
reports that.

**Hardening.** Root, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID`:
`CAP_DAC_READ_SEARCH` to read named.conf, includes and zone files (to follow `$INCLUDE` and
classify key files) and search directories owned by `named`; `CAP_FOWNER` because setting an ACL
on a file root doesn't own needs the owner or this capability; `CAP_FSETID` because the kernel
clears the setgid bit when it sets an ACL on a file or directory whose group the caller isn't in,
unless the caller has it. No `CAP_DAC_OVERRIDE`. `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp`, `PrivateDevices`, `PrivateNetwork`, `IPAddressDeny=any`,
`RestrictAddressFamilies=none`, the `@system-service` filter minus `@chown @setuid`, and the
usual kernel/proc protections. The service drop-in written by enrol adds `ReadWritePaths=` for
the zone directories and for each planned file or traversed directory outside them (named.conf
itself, not `/etc`), and `ProtectHome=read-only` only when a path is under a home directory
(HestiaCP). The rndc key is not made inaccessible here, unlike in the agent's unit: the planner
must read include files to classify them as key-only, and an inaccessible (empty) node would read
as a harmless file.

**Who updates the watch list.** With no `AF_UNIX` the service can't reach systemd, and it can't
write unit files; letting it rewrite its own drop-in would let it widen its own sandbox. So the
service only reports a stale watch list (in its log, and `--check` lists unwatched zone
directories). Enrol, and `fix-acls` run by hand as root, rewrite
`/etc/systemd/system/paneldns-agent-acl.{path,service}.d/watch.conf` when they changed, then
`daemon-reload` and `try-restart` the path unit. Enrol writes the drop-ins even with `--no-acl`
or `--no-start` but enables the watcher only without them, and runs one fix pass right after
setting the ACLs, before `--check`. The packages ship both units without enabling them; removal
stops and disables them and deletes the two drop-ins.

**Residual risk.** A zone file created in the moment between a run's last plan and its exit
waits for the next change in a watched directory (or a manual `fix-acls`); the agent reports the
zone as unreadable meanwhile. A zone in a brand-new directory isn't watched until `fix-acls` runs
by hand. Watching named.conf's directory (`/etc`) means unrelated writes there start runs; each
re-reads named.conf and the zone files for `$INCLUDE`.
