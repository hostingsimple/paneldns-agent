# Ingest API: the protocol as the agent speaks it

This is the normative description of what `paneldns-agent` sends to and expects from the
PanelDNS ingest API (spec section 8). The PanelDNS side is built separately from the same spec;
where section 8 is ambiguous, the choice made here is marked **[P-nn]** and listed in section 9,
so both sides can implement the same thing.

Shared fixtures that pin the details: [`testdata/signing/ed25519-request-signing.json`](../testdata/signing/ed25519-request-signing.json)
(section 3) and [`testdata/canonical/`](../testdata/canonical/) (section 5), with checksums in
[`testdata/SHA256SUMS`](../testdata/SHA256SUMS).

## 1. Transport

- Base URL: `PANELDNS_URL` from the config, `https://` only, certificate verified against the
  system roots, TLS 1.2 or later. There is no option to disable verification. Redirects are not
  followed (a 3xx is an error). [P-01]
- Every endpoint is `POST <PANELDNS_URL><path>`, where path is `/api/agent/v1/<endpoint>`. If
  `PANELDNS_URL` has a path (`https://host/prefix`), the prefix is part of the request path and of
  the signed path. [P-02]
- Every request body is UTF-8 JSON, gzip-compressed, with `Content-Type: application/json` and
  `Content-Encoding: gzip`, including `/enrol` and requests whose body is the empty object `{}`.
  [P-03]
- Every request carries `User-Agent: paneldns-agent/<version>` and
  `X-PanelDNS-Agent-Version: <version>` (spec 7.6). `<version>` has no leading `v`.
- Responses are JSON (`Content-Type: application/json`); the agent accepts gzip transfer
  encoding as negotiated by Go's HTTP client. An empty 2xx body is treated as `{}`. Responses
  larger than 4 MB are rejected. Responses are not signed; TLS protects them.
- The agent sends one request at a time per source; requests never overlap.

## 2. Identifiers

- `source_id` and `key_id` are opaque server-issued strings matching `[A-Za-z0-9_-]+` (no
  dot). The server should send them as JSON strings; JSON integers are accepted and turned into
  their decimal string. [P-04]
- `X-PanelDNS-Key: <source_id>.<key_id>`.
- Zone names on the wire are lower case, without the trailing dot (`example.com`); the root zone
  never appears (it is a system zone). Names are compared after lower-casing and dropping a
  trailing dot.
- Times are Unix seconds (integers).

## 3. Signing (spec 8.2)

Every request except `/enrol` carries:

| Header | Value |
|---|---|
| `X-PanelDNS-Key` | `<source_id>.<key_id>` |
| `X-PanelDNS-Timestamp` | Unix seconds, decimal |
| `X-PanelDNS-Nonce` | 16 random bytes as 32 lower-case hex characters [P-05] |
| `X-PanelDNS-Epoch` | decimal; `0` only on `/epoch` when the agent has no epoch |
| `X-PanelDNS-Seq` | decimal, starts at 1 in each epoch, +1 per request |
| `X-PanelDNS-Signature` | standard base64 (RFC 4648 section 4, with padding) of the 64-byte Ed25519 signature [P-06] |

The signed message is these seven fields joined with `\n` (0x0A), with no trailing newline:

```
METHOD \n PATH \n TIMESTAMP \n NONCE \n EPOCH \n SEQ \n HEX(SHA-256(BODY))
```

- `METHOD` is upper case (`POST`).
- `PATH` is the request path exactly as sent, percent-encoding as sent, without scheme, host or
  query string (the agent never sends a query string). [P-02]
- `TIMESTAMP`, `NONCE`, `EPOCH`, `SEQ` are the header values byte for byte.
- `BODY` is the request body **as sent on the wire**, i.e. the gzip bytes; the hash is 64
  lower-case hex characters. The server verifies before inflating. [P-07]

The Ed25519 key is the agent's own (RFC 8032, pure Ed25519, no context, no pre-hash). Verify in
PHP with `sodium_crypto_sign_verify_detached($sig, $message, $publicKey)`.

**Replay and ordering** (server side, as spec 8.2 states; listed so the agent's behaviour makes
sense):

- timestamp outside ±300 s of the server clock → `401` with `"error": "timestamp_out_of_window"`
  [P-08];
- nonce seen for this source in the last 10 minutes → `401`;
- epoch older than the current one → `409` with `"error": "epoch_stale"`;
- seq not greater than the last seq of this source in the current epoch → ignored (the agent
  never reuses one).

The agent allocates every seq from `/var/lib/paneldns-agent/sequence.json` under an exclusive
`flock`, writing and fsyncing the new value before the request is signed, so a crash, a restart
or a `--check` running next to the service never reuses a number. Retries are new requests:
new timestamp, nonce and seq.

## 4. Endpoints (spec 8.3)

### 4.1 `POST /api/agent/v1/enrol` (unsigned)

```json
{"code": "<one-time code>", "public_key": "<base64 of the 32-byte Ed25519 public key>",
 "hostname": "web1.example.com", "os": "Debian GNU/Linux 13 (trixie)", "backend": "bind",
 "panel": "directadmin", "public_ips": ["192.0.2.10"], "agent_version": "1.0.0"}
```

- `code`: as shown in the dashboard; the agent removes white space only.
- `backend`: `bind` or `powerdns-api`. `panel`: `cpanel`, `directadmin`, `plesk`, `virtualmin`,
  `hestiacp`, `ispconfig`, `cyberpanel` or `none` (detected from install directories).
- `public_ips`: the server's global unicast addresses that are not private, loopback or
  link-local, from its interfaces (no outside lookup). The allowlist prefill uses the request's
  TCP peer address, not this list (spec 8.1).
- There is no proof of possession of the private key; the code is the credential. [P-09]

Answer `200`:

```json
{"source_id": "17", "key_id": "4", "epoch": 1,
 "cluster_name": "Brand A", "source_name": "web1", "allowed_ips": ["192.0.2.10"]}
```

`epoch` must be at least 1. `cluster_name`, `source_name` and `allowed_ips` are optional and
only displayed. Errors the agent explains to the person running `enrol`: `401`/`404`/`410` (code
invalid, expired or used), `403` `ip_refused`, `429`. The agent writes nothing to disk unless
enrolment succeeds.

### 4.2 `POST /api/agent/v1/epoch`

Body `{}`. Signed with the current key, with the agent's current (possibly stale) epoch, or `0`
if it has none, and the next seq in that epoch. The server must accept any epoch value on this
endpoint (after checking key, signature, timestamp and nonce). [P-10]

Answer `{"epoch": <new epoch ≥ 1>}`. The agent then restarts seq at 1 and sends a full inventory
(section 6.2). The agent calls `/epoch` when `sequence.json` or `state.json` is missing at start,
and once after any `409 epoch_stale`.

### 4.3 `POST /api/agent/v1/rotate`

Body `{"public_key": "<base64 32 bytes>"}`, signed with the **old** key. Answer
`{"key_id": "<new key id>"}`. From then on the agent signs with the new key and sends
`X-PanelDNS-Key: <source_id>.<new key_id>`. The agent rotates only when a heartbeat answer has
`"rotate_key": true`.

When the answer is lost (no answer, 5xx, a 2xx without a usable key id), the agent keeps both keys
and, before its next requests, sends the same `/rotate` again signed with the old key, and if
that is refused (409, 400 or 401) a `/rotate` signed with the new key under the old key id plus
one. Any answer to that one other than 401 (and the pre-signature 403, 413, 429) tells it the
server holds the new key. This relies on the server's current behaviour (numeric key ids that a
rotation increments, the signature checked before the request is looked at), not on anything
this section requires; see DECISIONS.md D-19.

### 4.4 `POST /api/agent/v1/heartbeat`

Sent once per scan interval, after the cycle's other requests, and by `--check`.

```json
{"agent_version": "1.0.0", "hostname": "web1.example.com", "os": "…", "backend": "bind",
 "panel": "cpanel", "view": "external", "public_ips": ["192.0.2.10"],
 "zone_count": 412, "excluded_count": 3, "signed_count": 1,
 "scan_started_at": 1795000000, "scan_completed_at": 1795000004,
 "errors": [{"zone": "example.com", "code": "read_failed", "message": "named-compilezone failed: …"}],
 "check": false}
```

- `zone_count` counts names reported as not excluded (including zones that failed to read);
  `excluded_count` names reported as excluded; system zones are never counted.
- `scan_started_at`/`scan_completed_at` are those of the **last successful** scan (spec 10.5's
  settle window). A failed scan leaves them unchanged and adds an error.
- `errors` (at most 100): `code` is one of `scan_failed` (the listing or a guard failed; nothing
  else is sent this cycle), `config_warning`, `read_failed` (one zone; it keeps its last
  acknowledged content). `zone` is absent for source-wide errors.
- `check: true` marks a heartbeat sent by `paneldns-agent --check`; it carries the same data and
  must not trigger anything a normal heartbeat wouldn't. [P-11]

Answer (every field optional):

```json
{"config": {"interval": 60, "resync": 21600, "exclude": ["*.test.example.com"]},
 "latest_version": "1.1.0", "minimum_version": "1.0.0", "minimum_grace_until": 1796000000,
 "resync": false, "resync_names": ["example.com"], "rotate_key": false,
 "cluster_name": "Brand A", "source_name": "web1"}
```

- `config` is the overlay of spec 7.2. `interval` (seconds, used only if ≥ 15) and `resync`
  (used only if ≥ 60) replace the file's values; `exclude` patterns are added to the file's
  `EXCLUDE`. The file always wins for the zone source, view, owner file and URL. The overlay is
  kept until a later answer carries a different `config`; an answer without `config` keeps the
  current overlay. [P-12]
- `resync: true` → the next scan re-reads every zone and a full inventory follows.
- `resync_names` → those zones are re-read and pushed in full on the next cycle, even if
  unchanged.
- `rotate_key: true` → section 4.3 after this cycle.

### 4.5 `POST /api/agent/v1/inventory`

A full inventory, possibly in parts of at most 20,000 names:

```json
{"inventory_id": "1795000000-0a0b0c0d", "part": 1, "parts": 1,
 "scan_started_at": 1795000000, "scan_completed_at": 1795000004,
 "zones": [{"name": "example.com", "hash": "sha256:…", "excluded": false},
           {"name": "printer.example.net", "excluded": true}]}
```

- Parts of one inventory share `inventory_id` (unique per inventory) and are sent in order
  1..`parts`. The server should treat the inventory as complete, and infer deletions from it,
  only once it has every part of one `inventory_id`. If a part fails, the agent restarts the
  whole inventory later with a new `inventory_id`. [P-13]
- Excluded names have no `hash`. A zone that has never been read successfully has no `hash`
  and `excluded: false`: it exists and must not be treated as deleted. [P-14]
- System zones are not listed (spec 7.4).

Answer `{"need": ["example.com", …]}`: names the server lacks or holds with a different hash.
The agent sends those in full via `/zones` in the same cycle. Names it doesn't know are ignored.

An acknowledged inventory implies every pending deletion; the agent drops its pending deletion
list afterwards.

### 4.6 `POST /api/agent/v1/zones`

At most 100 zones and 8 MB of uncompressed JSON per request; each zone's `text` is at most 2 MB
(larger zones are not sent and are reported as `read_failed`).

```json
{"scan_started_at": 1795000000,
 "zones": [{"name": "example.com", "seq": 1842, "owner": "exampleuser",
            "hash": "sha256:…", "serial": 2026112001, "signed_at_source": false,
            "format": "rfc1035", "text": "$ORIGIN example.com.\nexample.com. 3600 IN SOA …\n…"}]}
```

- `seq` of every zone equals the request's `X-PanelDNS-Seq`. The agent sends a zone's latest
  content, read just before sending, so the request seq orders zone contents correctly; the
  server's per-(source, zone) rule of spec 8.2 compares `(epoch, seq)`. [P-15]
- `owner`: the panel account from the owner file, or `null`. [P-16]
- `hash`, `serial`, `text`: section 5. `format` is always `rfc1035`.
- `signed_at_source`: a DNSKEY or RRSIG was stripped.

Answer:

```json
{"results": [{"name": "example.com", "status": "accepted"},
             {"name": "example.net", "status": "refused", "reason": "public_suffix", "message": "…"}]}
```

`status` is one of spec 8.4's: `accepted`, `unchanged`, `stored`, `skipped_records` (optionally
with `skipped_records: [...]`, which the agent only displays), `refused`, `held`, `excluded`.
`reason` is a stable code, `message` free text, both optional.

- Acknowledged (`accepted`, `unchanged`, `stored`, `skipped_records`, `held`, `excluded`): the
  agent records the hash and won't send this content again. [P-17]
- `refused`: the agent won't send this exact content again until it changes, or the server asks
  for it (`need`, `resync_names`).
- A zone missing from `results`, or an unknown status: sent again next cycle.
- The server should update the owner on every push, `unchanged` included: an owner change alone
  makes the agent push the zone again with the same hash. [P-16]

### 4.7 `POST /api/agent/v1/deletions`

At most 1,000 names per request:

```json
{"scan_started_at": 1795000000, "deletions": [{"name": "old.example.com", "seq": 1843}]}
```

`seq` equals the request's `X-PanelDNS-Seq` [P-15]. A name is sent only if the server had
acknowledged content for it and it is gone from a complete listing (not merely excluded, not
failing to read). The answer may carry `{"results": [{"name": …, "status": "deleted"}]}`; the
agent treats any 2xx as acknowledging every name in the request. [P-18]

## 5. Canonical zone text and content hash (spec 7.4, 8.7)

The server must compute the same hash from pushed text (and from a DirectAdmin native push), so
these rules are exact. `testdata/canonical/` pins them.

### 5.1 Reading

RFC 1035 section 5 master-file syntax with these rules:

- `;` starts a comment outside quotes; `(` `)` join lines; a line starting with white space
  repeats the previous owner; `\r\n` equals `\n`.
- Directives: `$ORIGIN`, `$TTL`. `$INCLUDE` is expanded by the agent's reader; text pushed to
  the server never contains it. `$GENERATE` is expanded by `named-compilezone`; the agent's own
  parser refuses it.
- Owner `@` is the origin; a name not ending in an unescaped `.` is relative to the current
  origin.
- TTL and class may appear in either order before the type. TTLs accept BIND units
  (`1w2d3h4m5s`, any case). Without an explicit TTL: `$TTL`, else the last explicit TTL, else
  (for an SOA) the SOA minimum.
- Only class `IN` is accepted.

### 5.2 Stripping

Records of these types are removed before anything else: RRSIG (46), NSEC (47), DNSKEY (48),
NSEC3 (50), NSEC3PARAM (51), CDS (59), CDNSKEY (60), and TYPE65280–TYPE65534, whether written as
mnemonic or `TYPEnnn`. `signed_at_source` is true when a DNSKEY or RRSIG was removed. SOA is
kept. [P-19]

### 5.3 Canonical record line

`<owner> <ttl> IN <type>[ <rdata>]`, fields separated by one space (0x20).

- **Names** (owner and the name fields below): made absolute; each label decoded (`\X` → X,
  `\DDD` → byte DDD) and ASCII `A`–`Z` lower-cased; re-encoded with `\` before `.` `\` `"` `(`
  `)` `;` `@` `$`, `\DDD` (three digits) for bytes ≤ 0x20 and ≥ 0x7F, other bytes as is; joined
  with `.` and ending in `.`. The root is `.`. An empty label, a label over 63 bytes or a name
  over 255 bytes makes the zone fail.
- **TTL**: decimal seconds, no leading zeros.
- **Type**: upper-case mnemonic; `TYPEnnn` becomes the mnemonic when the number is in this list:
  A 1, NS 2, CNAME 5, SOA 6, MB 7, MG 8, MR 9, PTR 12, HINFO 13, MINFO 14, MX 15, TXT 16, RP 17,
  AFSDB 18, RT 21, SIG 24, KEY 25, PX 26, AAAA 28, LOC 29, NXT 30, SRV 33, NAPTR 35, KX 36,
  CERT 37, DNAME 39, DS 43, SSHFP 44, RRSIG 46, NSEC 47, DNSKEY 48, DHCID 49, NSEC3 50,
  NSEC3PARAM 51, TLSA 52, SMIMEA 53, HIP 55, CDS 59, CDNSKEY 60, OPENPGPKEY 61, CSYNC 62,
  ZONEMD 63, SVCB 64, HTTPS 65, SPF 99, NID 104, L32 105, L64 106, LP 107, EUI48 108, EUI64 109,
  URI 256, CAA 257, AVC 258, DOA 259, AMTRELAY 260, RESINFO 261, WALLET 262, TA 32768,
  DLV 32769. Otherwise `TYPEnnn` with the decimal number.
- **Character-strings** (where listed below): decoded like labels, then written as `"…"` with
  `\"` for `"`, `\\` for `\`, `\DDD` for bytes < 0x20 and ≥ 0x7F, other bytes as is. An unquoted
  token in a character-string position is treated the same way, so `plain\ word` becomes
  `"plain word"`.
- **Rdata by type.** The per-type rule applies only when the token count matches (exact, or the
  minimum for types with a tail) and every field parses; otherwise the record uses the generic
  rule. A bad record never fails the zone.

| Type | Tokens | Fields |
|---|---|---|
| A | 1 | IPv4 dotted quad (as parsed: `192.0.2.1`) |
| AAAA | 1 | IPv6 in RFC 5952 form (`2001:db8::10`); no zone index |
| NS, CNAME, DNAME, PTR, MB, MG, MR | 1 | name |
| MX, RT, KX, AFSDB | 2 | uint, name |
| SRV | 4 | uint, uint, uint, name |
| SOA | 7 | name, name, serial (uint), refresh, retry, expire, minimum (each a TTL with units allowed, written in seconds) |
| RP, MINFO | 2 | name, name |
| PX | 3 | uint, name, name |
| NAPTR | 6 | uint, uint, string, string, string, name |
| CAA | 3 | uint, tag lower-cased, string |
| HINFO | 2 | string, string |
| URI | 3 | uint, uint, string |
| DS, TLSA | ≥ 4 | uint, uint, uint, then every remaining token concatenated and upper-cased (hex) |
| SSHFP | ≥ 3 | uint, uint, then the rest concatenated and upper-cased (hex) |
| TXT, SPF | ≥ 1 | every token a string (multi-string records keep their strings separate) |
| SVCB, HTTPS | ≥ 2 | uint, name, then the remaining tokens with the generic rule |

"uint" is a decimal 0–4294967295 written without leading zeros. A name field must be unquoted.

- **Generic rule**: tokens joined with one space; quoted tokens become canonical
  character-strings; unquoted tokens stay exactly as written (case and escapes kept).
- **RFC 3597** rdata `\# <len> <hex>…`: `\# <len> <HEX>` with the hex concatenated and upper
  cased, or `\# 0`.

### 5.4 Zone

1. Exactly one SOA (identical duplicates count as one), owned by the zone apex. No SOA, two
   different SOAs, or an SOA elsewhere fails the zone. `serial` is its third field.
2. Lines are de-duplicated and sorted by byte value (unsigned bytes, as `strcmp`/Go strings).
3. **Hash input**: every sorted line, with the SOA line's serial field removed (so the SOA line
   has 10 space-separated fields), each followed by `\n`.
4. **Hash**: `sha256:` + lower-case hex of SHA-256 of the hash input.
5. **Pushed text**: `$ORIGIN <apex>\n`, then the SOA line (with its serial), then every other
   line in sorted order, each followed by `\n`. Parsing and canonicalising the pushed text gives
   the same text and hash (the fixture checks this).

## 6. Agent behaviour the server can rely on

### 6.1 A cycle

Every `INTERVAL` (default 60 s): scan, then, unless in backoff: `/epoch` if needed, `/inventory`
if due (after a scan that re-read every zone), `/zones` for every zone whose hash differs from
the acknowledged one, `/deletions`, `/heartbeat`. Any failing request ends the cycle; the next
attempt follows the backoff (6.3).

### 6.2 Full inventory

On start, every `RESYNC` (default 21,600 s) after the last acknowledged inventory, after
`/epoch`, when the excluded set changes, and on `resync: true`. The scan before it re-reads
every zone.

### 6.3 Errors and retries (spec 7.5)

| Answer | Agent |
|---|---|
| transport error, `408`, `409` (not `epoch_stale`), `429`, `5xx` | retried with backoff: full jitter, 5 s doubling to 10 min; `Retry-After` (seconds or HTTP date, at most 1 h) wins when longer |
| `409 epoch_stale` | `/epoch`, then the cycle once more |
| `401` | logged with "re-enrol" advice; retried every 10 min |
| `403 ip_refused` | logged with the address and where to allow it; retried with backoff |
| `426` | logged with "update the package"; retried every 10 min |
| other `4xx` on `/zones` | every zone in the batch is marked refused (reason `http_<status>`) and not resent until it changes |
| other `4xx` on `/deletions` | the names are dropped; the next inventory implies them |
| other `4xx` elsewhere | retried with backoff |

### 6.4 Guards

No inventory and no deletions are sent from a scan that failed: the listing failed; a config
file that declared zones last time can't be read now; or the scan found no zones, or fewer than
half of the last inventory, and named/PowerDNS is not confirmed running (spec 7.4). Such a
cycle sends only a heartbeat with a `scan_failed` error.

## 7. Error bodies

Non-2xx answers should carry `{"error": "<code>", "message": "<text>"}`; for `ip_refused` also
`"ip": "<the refused address>"`, which the agent prints. Codes the agent acts on:
`epoch_stale` (409), `ip_refused` (403), `timestamp_out_of_window` (401, printed as a clock
problem), `unauthorized` (401), `upgrade_required` (426). Any other code is logged as is.
[P-20]

## 8. Local files

`/var/lib/paneldns-agent/` (mode 0700, owner `paneldns-agent`):

| File | Mode | Content |
|---|---|---|
| `agent.key` | 0600 | Ed25519 private key, PKCS #8 PEM; refused at start if group or others can read it |
| `agent.key.next` | 0600 | only during a rotation |
| `identity.json` | 0600 | URL, source id, key id, names |
| `sequence.json` | 0600 | epoch and last seq |
| `state.json` | 0600 | per-zone fingerprint, hash, acknowledged hash, last status; pending deletions; last inventory |
| `pdns-api-key` | 0600 | PowerDNS sources only |

## 9. Choices made where spec section 8 is ambiguous

| # | Topic | Choice |
|---|---|---|
| P-01 | Redirects | Not followed; a 3xx is an error |
| P-02 | Signed path | The request path as sent, including any path prefix of `PANELDNS_URL`, no query |
| P-03 | Body encoding | Every request body gzip JSON, `/enrol` and `{}` bodies included |
| P-04 | Id types | Opaque strings without dots; integers accepted |
| P-05 | Nonce format | 32 lower-case hex characters (16 random bytes) |
| P-06 | Signature encoding | Standard base64 with padding; public keys likewise (32 raw bytes) |
| P-07 | Body hash in the message | Lower-case hex SHA-256 of the gzip bytes |
| P-08 | Clock-skew error | `401` with `timestamp_out_of_window` |
| P-09 | Enrolment proof of possession | None; the one-time code is the credential |
| P-10 | `/epoch` epoch header | Any epoch accepted, `0` when the agent has none; signature, timestamp and nonce still checked |
| P-11 | `--check` heartbeat | A normal signed heartbeat with `"check": true` |
| P-12 | Overlay lifetime | Kept until a later answer carries `config`; `exclude` adds to the file's list |
| P-13 | Inventory paging | `inventory_id`, `part`, `parts`; complete only with every part of one id |
| P-14 | Unreadable zone in an inventory | Listed without a hash; present, not deleted |
| P-15 | Per-zone and per-deletion `seq` | Equal to the request's `X-PanelDNS-Seq` (spec says "the seq of the scan"; the request seq is monotonic and always newer for newer content, and survives epoch resets) |
| P-16 | Owner | `null` when unknown; the server updates the owner on every push, including `unchanged` |
| P-17 | Which statuses acknowledge | All except `refused` |
| P-18 | `/deletions` answer | Any 2xx acknowledges every name; per-name results optional |
| P-19 | SOA and the strip list | Agent keeps SOA (spec 7.3 lists it among stripped types, 8.4 needs it); the server strips it |
| P-20 | Error body | `{"error", "message", "ip"?}` |
