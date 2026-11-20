# Shared fixtures

These files are shared with the PanelDNS app (private repository), which copies them and pins
them by the checksums in [`SHA256SUMS`](SHA256SUMS), so the agent's and the server's test suites
can't drift apart. They are generated from fixed inputs and must not change unless the protocol
changes on purpose.

Everything here uses documentation names and addresses only: `example.com`, `example.net`,
`192.0.2.0/24` and `2001:db8::/32`. A CI job fails on anything else.

## `signing/ed25519-request-signing.json`

The request-signing vector of spec 8.2 and [`docs/PROTOCOL.md`](../docs/PROTOCOL.md) section 3.

- The key is a **test key**: the Ed25519 seed is the 32 bytes `00 01 02 … 1f`
  (`private_key_seed_hex`); the public key is given in base64 and hex.
- Each case gives the request fields (`method`, `path`, the `X-PanelDNS-*` header values), the
  JSON body (`body_json`) and the exact bytes sent on the wire (`body_wire_base64`, gzip). The
  signature covers the SHA-256 of the **wire bytes**, so a server must hash the body before
  inflating it.
- `signing_string` is the exact message signed; `x_paneldns_signature` is the expected standard
  base64 signature. Ed25519 is deterministic, so a correct implementation reproduces it byte for
  byte.
- `negative_cases` lists changes that must make verification fail (or, for the method's case,
  still pass).

PHP check, per case:

```php
$wire = base64_decode($case['body_wire_base64']);
$msg  = implode("\n", [strtoupper($case['method']), $case['path'], $case['x_paneldns_timestamp'],
         $case['x_paneldns_nonce'], $case['x_paneldns_epoch'], $case['x_paneldns_seq'], hash('sha256', $wire)]);
assert($msg === $case['signing_string']);
assert(sodium_crypto_sign_verify_detached(base64_decode($case['x_paneldns_signature']), $msg,
       base64_decode($vector['public_key_base64'])));
```

## `canonical/`

The canonical-hash fixture of spec 7.4 and 8.7 and [`docs/PROTOCOL.md`](../docs/PROTOCOL.md)
section 5.

- `*.db` are the inputs: the same zone `example.com` written four ways (by hand, as
  `named-compilezone -s full` prints it, as DirectAdmin writes it, and as a signed PowerDNS
  export with DNSSEC and private records), and `rules.example.net.db`, which has one record per
  canonical rule.
- `canonical-hash.json` gives, per input, the origin, SOA serial, whether it was signed at the
  source, how many records were stripped, the exact `hash_input`, the `hash`, and the `text` the
  agent pushes. `same_hash` lists inputs that must hash equal: the four `example.com` files do,
  although their serials and layout differ.

## Regenerating

Only after a deliberate protocol change, with the change written down in `docs/PROTOCOL.md` and
`CHANGELOG.md`:

```sh
go test ./internal/fixtures -update
```

This rewrites `signing/ed25519-request-signing.json`, `canonical/canonical-hash.json` and
`SHA256SUMS` from the fixed inputs. Without `-update`, `go test ./...` fails if any of them is out
of date. The PanelDNS app must then copy the new files and update its pinned checksums.
