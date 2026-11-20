package zonefile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toks(rr RR) string {
	var s []string
	for _, t := range rr.Data {
		if t.Quoted {
			s = append(s, `"`+t.Text+`"`)
		} else {
			s = append(s, t.Text)
		}
	}
	return strings.Join(s, " ")
}

func TestParseUglyZone(t *testing.T) {
	rrs, err := Parse(readFixture(t, "ugly.example.com.db"), Options{
		Origin:     "example.com",
		File:       "ugly.example.com.db",
		IncludeDir: "testdata",
		ReadFile:   os.ReadFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, ttl, typ, data string }{
		{"example.com.", "3600", "SOA", "ns1.example.com. hostmaster.example.com. 2026112001 3600 15m 1W 300"},
		{"example.com.", "3600", "NS", "ns1"},
		{"example.com.", "3600", "NS", "ns2.example.net."},
		{"example.com.", "300", "MX", "10 mail"},
		{"example.com.", "300", "MX", "20 mail2.example.net."},
		{"www.example.com.", "3600", "CNAME", "@"},
		{"mail.example.com.", "3600", "A", "192.0.2.10"},
		{"mail.example.com.", "3600", "AAAA", "2001:DB8:0:0::10"},
		{"mail.example.com.", "3600", "TXT", `"indented: owner is mail"`},
		{"txt.example.com.", "3600", "TXT", `"v=spf1 ip4:192.0.2.0/24" " -all"`},
		{"quote.example.com.", "3600", "TXT", `"say \"hi\"; not a comment" "\\backslash" "tab\009x"`},
		{"unq.example.com.", "3600", "TXT", `unquoted\ word`},
		{"_sip._tcp.example.com.", "3600", "SRV", "0 5 5060 sip"},
		{"sub.example.com.", "3600", "NS", "ns1.sub"},
		{"ns1.sub.example.com.", "3600", "A", "192.0.2.53"},
		{"host.sub2.example.com.", "3600", "A", "192.0.2.20"},
		{"inc1.sub2.example.com.", "3600", "A", "192.0.2.30"},
		{"inc2.deep.example.com.", "3600", "A", "192.0.2.31"},
		{"inc3.other.example.com.", "300", "A", "192.0.2.32"},
		// The include's $ORIGIN did not leak back.
		{"after.sub2.example.com.", "3600", "A", "192.0.2.21"},
		{"*.sub2.example.com.", "3600", "A", "192.0.2.99"},
		{"caa.sub2.example.com.", "3600", "CAA", `0 issue "letsencrypt.example"`},
	}
	if len(rrs) != len(want) {
		for _, rr := range rrs {
			t.Logf("%s %d %s %s", rr.Name, rr.TTL, rr.Type, toks(rr))
		}
		t.Fatalf("got %d records, want %d", len(rrs), len(want))
	}
	for i, w := range want {
		rr := rrs[i]
		got := []string{rr.Name, itoa(rr.TTL), rr.Type, toks(rr)}
		exp := []string{w.name, w.ttl, w.typ, w.data}
		for j := range got {
			if got[j] != exp[j] {
				t.Errorf("record %d (line %d): got %q, want %q", i, rr.Line, got, exp)
				break
			}
		}
		if rr.Class != "IN" {
			t.Errorf("record %d class %q", i, rr.Class)
		}
	}
	if rrs[0].Line != 4 {
		t.Errorf("SOA line = %d, want 4", rrs[0].Line)
	}
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func TestParseCRLF(t *testing.T) {
	rrs, err := Parse(readFixture(t, "crlf.example.net.db"), Options{Origin: "example.net."})
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 2 || rrs[1].Type != "A" || rrs[1].Data[0].Text != "192.0.2.1" {
		t.Fatalf("got %+v", rrs)
	}
}

func TestParseTTLDefaults(t *testing.T) {
	tests := []struct {
		name string
		text string
		ttls []uint32
	}{
		{"soa minimum when no $TTL", "@ IN SOA a. b. 1 2 3 4 600\n@ IN A 192.0.2.1\n", []uint32{600, 600}},
		{"last explicit TTL", "@ 100 IN SOA a. b. 1 2 3 4 600\nx IN A 192.0.2.1\ny 200 A 192.0.2.2\nz A 192.0.2.3\n", []uint32{100, 100, 200, 200}},
		{"$TTL wins over last explicit", "$TTL 50\n@ 100 IN SOA a. b. 1 2 3 4 600\nx IN A 192.0.2.1\n", []uint32{100, 50}},
		{"units", "$TTL 1d2h3m4s\n@ IN A 192.0.2.1\n", []uint32{93784}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrs, err := Parse([]byte(tt.text), Options{Origin: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if len(rrs) != len(tt.ttls) {
				t.Fatalf("got %d records", len(rrs))
			}
			for i, rr := range rrs {
				if rr.TTL != tt.ttls[i] {
					t.Errorf("record %d TTL %d, want %d", i, rr.TTL, tt.ttls[i])
				}
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, text, want string
	}{
		{"no ttl", "@ IN A 192.0.2.1\n", "no TTL"},
		{"other class", "$TTL 1\n@ CH TXT \"x\"\n", "only IN"},
		{"generate refused", "$TTL 1\n$GENERATE 1-2 h$ A 192.0.2.$\n", "$GENERATE"},
		{"include refused without reader", "$INCLUDE /etc/passwd\n", "not allowed"},
		{"unknown directive", "$FOO bar\n", "unknown directive"},
		{"unbalanced close", "$TTL 1\n@ IN A 192.0.2.1 )\n", "unbalanced"},
		{"unbalanced open", "$TTL 1\n@ IN SOA a. b. ( 1 2 3 4 5\n", "unbalanced"},
		{"unterminated quote", "$TTL 1\n@ IN TXT \"abc\n", "quoted string"},
		{"indented first record", "$TTL 1\n  IN A 192.0.2.1\n", "without an owner"},
		{"no type", "$TTL 1\n@ IN 300\n", "no type"},
		{"bad type token", "$TTL 1\n@ IN 192.0.2.1\n", "bad TTL"},
		{"ttl too large", "$TTL 4294967296\n", "too large"},
		{"bad ttl unit", "$TTL 5x\n", "unit"},
		{"trailing number after unit", "$TTL 1h30\n", "without unit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.text), Options{Origin: "example.com"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestParseIncludeDepthAndMaxRecords(t *testing.T) {
	loop := func(string) ([]byte, error) { return []byte("$INCLUDE self.db\n"), nil }
	_, err := Parse([]byte("$INCLUDE self.db\n"), Options{Origin: "example.com", ReadFile: loop})
	if err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Fatalf("got %v", err)
	}
	_, err = Parse([]byte("$TTL 1\na A 192.0.2.1\nb A 192.0.2.2\nc A 192.0.2.3\n"), Options{Origin: "example.com", MaxRecords: 2})
	if err == nil || !strings.Contains(err.Error(), "more than 2") {
		t.Fatalf("got %v", err)
	}
}

func TestEscapedTrailingDot(t *testing.T) {
	rrs, err := Parse([]byte("$TTL 1\nweird\\. A 192.0.2.1\nok\\\\. A 192.0.2.2\n"), Options{Origin: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if rrs[0].Name != `weird\..example.com.` {
		t.Errorf("escaped dot is not absolute: %q", rrs[0].Name)
	}
	if rrs[1].Name != `ok\\.` {
		t.Errorf("escaped backslash then dot is absolute: %q", rrs[1].Name)
	}
}

func TestStrip(t *testing.T) {
	text := `$TTL 300
@ IN SOA ns1.example.com. h.example.com. 1 2 3 4 5
@ IN DNSKEY 257 3 13 AAAA
@ IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.com. AAAA
@ IN NSEC www.example.com. A RRSIG NSEC
@ IN NSEC3PARAM 1 0 0 -
@ IN CDS 1 13 2 AA
@ IN CDNSKEY 257 3 13 AA
@ IN TYPE65534 \# 5 0D2B4C0000
@ IN TYPE65280 \# 0
@ IN TYPE65535 \# 0
@ IN A 192.0.2.1
@ IN DS 1 13 2 AA
`
	rrs, err := Parse([]byte(text), Options{Origin: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	out, res := Strip(rrs)
	var kept []string
	for _, rr := range out {
		kept = append(kept, rr.Type)
	}
	if got := strings.Join(kept, ","); got != "SOA,TYPE65535,A,DS" {
		t.Fatalf("kept %s", got)
	}
	if res.Removed != 8 || !res.SignedAtSource {
		t.Fatalf("result %+v", res)
	}
	_, res = Strip([]RR{{Type: "NSEC3PARAM"}})
	if res.SignedAtSource {
		t.Fatal("NSEC3PARAM alone is not 'signed'")
	}
	_, res = Strip([]RR{{Type: "TYPE46"}})
	if !res.SignedAtSource {
		t.Fatal("TYPE46 is RRSIG")
	}
}
