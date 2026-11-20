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
