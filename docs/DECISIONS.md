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
