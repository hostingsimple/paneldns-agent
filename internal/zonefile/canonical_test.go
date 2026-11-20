package zonefile

import (
	"strings"
	"testing"
)

func canon(t *testing.T, origin, text string) *Canonical {
	t.Helper()
	rrs, err := Parse([]byte(text), Options{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	rrs, _ = Strip(rrs)
	c, err := MakeCanonical(rrs, origin)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// handWritten and compiled are the same zone: one as a person writes it,
// one as named-compilezone -s full prints it.
const handWritten = `$TTL 1h
$ORIGIN Example.COM.
@ IN SOA NS1 hostmaster ( 2026112001 1h 15m 1w 5m )
  IN NS ns1
  IN NS ns2.example.net.
@ 300 IN MX 010 Mail
mail IN A 192.0.2.10
mail IN AAAA 2001:DB8:0:0:0:0:0:10
txt IN TXT "v=spf1 " "ip4:192.0.2.0/24 -all"
esc IN TXT "\065BC" "q\"uote" "back\\slash" "tab	x"
caa IN CAA 0 ISSUE "letsencrypt.example"
_443._tcp IN TLSA 3 1 1 ab12 CD34
sub IN DS 12345 13 2 abcdef0123 456789
_sip._tcp IN SRV 0 5 5060 sip
www IN CNAME @
`

const compiled = `example.com.                3600 IN SOA ns1.example.com. hostmaster.example.com. 2026112099 3600 900 604800 300
example.com.                3600 IN NS ns1.example.com.
example.com.                3600 IN NS ns2.example.net.
example.com.                300 IN MX 10 mail.example.com.
_sip._tcp.example.com.      3600 IN SRV 0 5 5060 sip.example.com.
_443._tcp.example.com.      3600 IN TLSA 3 1 1 AB12CD34
caa.example.com.            3600 IN CAA 0 issue "letsencrypt.example"
esc.example.com.            3600 IN TXT "ABC" "q\"uote" "back\\slash" "tab\009x"
mail.example.com.           3600 IN A 192.0.2.10
mail.example.com.           3600 IN AAAA 2001:db8::10
sub.example.com.            3600 IN DS 12345 13 2 ABCDEF0123456789
txt.example.com.            3600 IN TXT "v=spf1 " "ip4:192.0.2.0/24 -all"
www.example.com.            3600 IN CNAME example.com.
`

func TestCanonicalEquivalentInputs(t *testing.T) {
	a := canon(t, "example.com", handWritten)
	b := canon(t, "example.com.", compiled)
	if a.Hash != b.Hash {
		t.Fatalf("hashes differ\n%s\n---\n%s", a.HashInput(), b.HashInput())
	}
	if a.Serial != 2026112001 || b.Serial != 2026112099 {
		t.Fatalf("serials %d %d", a.Serial, b.Serial)
	}
	if a.Text == b.Text {
		t.Fatal("texts should differ in the serial")
	}
	want := []string{
		`_443._tcp.example.com. 3600 IN TLSA 3 1 1 AB12CD34`,
		`_sip._tcp.example.com. 3600 IN SRV 0 5 5060 sip.example.com.`,
		`caa.example.com. 3600 IN CAA 0 issue "letsencrypt.example"`,
		`esc.example.com. 3600 IN TXT "ABC" "q\"uote" "back\\slash" "tab\009x"`,
		`example.com. 300 IN MX 10 mail.example.com.`,
		`example.com. 3600 IN NS ns1.example.com.`,
		`example.com. 3600 IN NS ns2.example.net.`,
		`example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026112001 3600 900 604800 300`,
		`mail.example.com. 3600 IN A 192.0.2.10`,
		`mail.example.com. 3600 IN AAAA 2001:db8::10`,
		`sub.example.com. 3600 IN DS 12345 13 2 ABCDEF0123456789`,
		`txt.example.com. 3600 IN TXT "v=spf1 " "ip4:192.0.2.0/24 -all"`,
		`www.example.com. 3600 IN CNAME example.com.`,
	}
	if strings.Join(a.Lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s", strings.Join(a.Lines, "\n"))
	}
	if !strings.HasPrefix(a.Text, "$ORIGIN example.com.\nexample.com. 3600 IN SOA ") {
		t.Fatalf("text must start with $ORIGIN and the SOA:\n%s", a.Text)
	}
	if !strings.Contains(a.HashInput(), "IN SOA ns1.example.com. hostmaster.example.com. 3600 900") {
		t.Fatalf("serial not removed from hash input:\n%s", a.HashInput())
	}
	if !strings.HasPrefix(a.Hash, "sha256:") || len(a.Hash) != 71 {
		t.Fatalf("hash format %q", a.Hash)
	}
}

func TestCanonicalIdempotent(t *testing.T) {
	a := canon(t, "example.com", handWritten)
	b := canon(t, "example.com", a.Text)
	if a.Text != b.Text || a.Hash != b.Hash {
		t.Fatalf("not idempotent:\n%s\n---\n%s", a.Text, b.Text)
	}
}

func TestCanonicalChanges(t *testing.T) {
	base := "$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN A 192.0.2.1\n"
	h := canon(t, "example.com", base).Hash
	tests := []struct {
		name string
		text string
		same bool
	}{
		{"serial bump only", "$TTL 300\n@ IN SOA ns1 h 2 2 3 4 5\n@ IN A 192.0.2.1\n", true},
		{"comments and layout", "; c\n$TTL 300\n@\tIN\tSOA\tns1 h (1 ; s\n 2 3 4 5)\n\n@ IN A 192.0.2.1 ; x\n", true},
		{"duplicate record", base + "@ IN A 192.0.2.1\n", true},
		{"record order", "$TTL 300\n@ IN A 192.0.2.1\n@ IN SOA ns1 h 1 2 3 4 5\n", true},
		{"stripped DNSSEC", base + "@ IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.com. AA==\n", true},
		{"ttl change", "$TTL 600\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN A 192.0.2.1\n", false},
		{"soa refresh change", "$TTL 300\n@ IN SOA ns1 h 1 9 3 4 5\n@ IN A 192.0.2.1\n", false},
		{"record added", base + "@ IN A 192.0.2.2\n", false},
		{"rdata case matters in TXT", base + "@ IN TXT \"A\"\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canon(t, "example.com", tt.text).Hash
			if (got == h) != tt.same {
				t.Fatalf("same=%v, want %v", got == h, tt.same)
			}
		})
	}
	if canon(t, "example.com", base+"@ IN TXT \"a\"\n").Hash == canon(t, "example.com", base+"@ IN TXT \"A\"\n").Hash {
		t.Fatal("TXT case folded")
	}
}

func TestCanonicalRdataRules(t *testing.T) {
	tests := []struct {
		name, rr, want string
	}{
		{"name lower-cased and absolute", `@ IN CNAME Target.Sub`, `example.com. 300 IN CNAME target.sub.example.com.`},
		{"owner escapes", `w\065b IN A 192.0.2.1`, `wab.example.com. 300 IN A 192.0.2.1`},
		{"escaped dot kept", `a\.b IN A 192.0.2.1`, `a\.b.example.com. 300 IN A 192.0.2.1`},
		{"non-printable owner byte", `a\009b IN A 192.0.2.1`, `a\009b.example.com. 300 IN A 192.0.2.1`},
		{"unquoted TXT becomes quoted", `@ IN TXT plain\ word`, `example.com. 300 IN TXT "plain word"`},
		{"high byte escaped", `@ IN TXT "caf\195\169"`, `example.com. 300 IN TXT "caf\195\169"`},
		{"generic RFC 3597", `@ IN TYPE999 \# 3 abcd ef`, `example.com. 300 IN TYPE999 \# 3 ABCDEF`},
		{"generic empty", `@ IN TYPE999 \# 0`, `example.com. 300 IN TYPE999 \# 0`},
		{"TYPEnnn of a known type", `@ IN TYPE1 192.0.2.7`, `example.com. 300 IN A 192.0.2.7`},
		{"bad A falls back to generic", `@ IN A not-an-address`, `example.com. 300 IN A not-an-address`},
		{"A with IPv6 falls back", `@ IN A 2001:db8::1`, `example.com. 300 IN A 2001:db8::1`},
		{"AAAA mapped form", `@ IN AAAA 2001:0db8:0000:0000:0000:ff00:0042:8329`, `example.com. 300 IN AAAA 2001:db8::ff00:42:8329`},
		{"MX wrong arity generic", `@ IN MX 10`, `example.com. 300 IN MX 10`},
		{"SRV dot target", `_x._tcp IN SRV 0 0 0 .`, `_x._tcp.example.com. 300 IN SRV 0 0 0 .`},
		{"HTTPS params generic", `@ IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1`, `example.com. 300 IN HTTPS 1 . alpn=h2,h3 ipv4hint=192.0.2.1`},
		{"SSHFP hex", `@ IN SSHFP 4 2 abCD 0123`, `example.com. 300 IN SSHFP 4 2 ABCD0123`},
		{"NAPTR", `@ IN NAPTR 100 10 u E2U+sip "!^.*$!sip:x@example.com!" .`, `example.com. 300 IN NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:x@example.com!" .`},
		{"CAA unquoted value", `@ IN CAA 128 Tbs value`, `example.com. 300 IN CAA 128 tbs "value"`},
		{"other types generic", `@ IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m`, `example.com. 300 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m`},
		{"generic quoted token", `@ IN URI 10 1 "https://example.com/"`, `example.com. 300 IN URI 10 1 "https://example.com/"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := canon(t, "example.com", "$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n"+tt.rr+"\n")
			for _, l := range c.Lines {
				if !strings.Contains(l, " SOA ") {
					if l != tt.want {
						t.Fatalf("got  %s\nwant %s", l, tt.want)
					}
					return
				}
			}
			t.Fatal("record missing")
		})
	}
}

func TestCanonicalErrors(t *testing.T) {
	tests := []struct{ name, text, want string }{
		{"no SOA", "$TTL 1\n@ IN A 192.0.2.1\n", "no SOA"},
		{"two SOAs", "$TTL 1\n@ IN SOA a b 1 2 3 4 5\n@ IN SOA a b 2 2 3 4 5\n", "more than one SOA"},
		{"SOA below apex", "$TTL 1\nx IN SOA a b 1 2 3 4 5\n", "not the zone apex"},
		{"bad serial", "$TTL 1\n@ IN SOA a b x 2 3 4 5\n", "SOA serial"},
		{"SOA too short", "$TTL 1\n@ IN SOA a b 1 2 3 4\n", "7 fields"},
		{"empty label", "$TTL 1\n@ IN SOA a b 1 2 3 4 5\na..b IN A 192.0.2.1\n", "empty label"},
		{"long label", "$TTL 1\n@ IN SOA a b 1 2 3 4 5\n" + strings.Repeat("a", 64) + " IN A 192.0.2.1\n", "63"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrs, err := Parse([]byte(tt.text), Options{Origin: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = MakeCanonical(rrs, "example.com")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
}
