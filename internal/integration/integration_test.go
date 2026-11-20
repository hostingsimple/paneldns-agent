//go:build integration

// Package integration runs the agent's readers against real software:
// named-compilezone and named (BIND 9) and the PowerDNS HTTP API. It runs
// in CI (.github/workflows/integration.yml), not in `go test ./...`:
//
//	go test -tags integration ./internal/integration/ -v
//
// Each test skips itself when its software or environment is missing.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// setup copies testdata into a temp dir and renders named.conf.
func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel("testdata", p)
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".in") {
			dst = strings.TrimSuffix(dst, ".in")
			b = bytes.ReplaceAll(b, []byte("@DIR@"), []byte(dir))
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "keys"), 0o755)
	return dir
}

func need(t *testing.T, bins ...string) {
	t.Helper()
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
}

func listing(t *testing.T, b *source.BIND) map[string]source.ZoneRef {
	t.Helper()
	l, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]source.ZoneRef{}
	for _, z := range l.Zones {
		out[z.Name] = z
	}
	return out
}

func hasRecord(c *zonefile.Canonical, line string) bool {
	for _, l := range c.Lines {
		if l == line {
			return true
		}
	}
	return false
}

func TestCompilezone(t *testing.T) {
	need(t, "named-compilezone")
	dir := setup(t)
	b := &source.BIND{ConfFile: filepath.Join(dir, "named.conf")}
	zones := listing(t, b)
	if _, ok := zones["secondary.example.net"]; ok {
		t.Fatal("secondary zone listed")
	}
	ctx := context.Background()
	c, _, err := engine.Prepare(ctx, b, zones["inc.example.com"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"www.inc.example.com. 300 IN A 192.0.2.80",
		"host1.inc.example.com. 300 IN A 192.0.2.1",
		"host3.inc.example.com. 300 IN A 192.0.2.3",
		`txt.inc.example.com. 300 IN TXT "part one" "part \"two\""`,
	} {
		if !hasRecord(c, want) {
			t.Errorf("missing %q in\n%s", want, c.Text)
		}
	}
	// The built-in parser gives the same hash where it can read the zone,
	// and refuses $GENERATE.
	nb := &source.BIND{ConfFile: filepath.Join(dir, "named.conf"), NoCompilezone: true}
	nz := listing(t, nb)
	if _, _, err := engine.Prepare(ctx, nb, nz["inc.example.com"]); err == nil || !strings.Contains(err.Error(), "$GENERATE") {
		t.Fatalf("built-in parser and $GENERATE: %v", err)
	}
	cs, _, err := engine.Prepare(ctx, b, zones["signed.example.net"])
	if err != nil {
		t.Fatal(err)
	}
	ns, _, err := engine.Prepare(ctx, nb, nz["signed.example.net"])
	if err != nil || ns.Hash != cs.Hash {
		t.Fatalf("named-compilezone and the built-in parser disagree: %v\n%s\n%s", err, cs.HashInput(), ns.HashInput())
	}
	// A zone named would refuse (check-names fail) is reported, not pushed.
	if _, _, err := engine.Prepare(ctx, b, zones["bad.example.net"]); err == nil || !strings.Contains(err.Error(), "bad_name") {
		t.Fatalf("check-names failure not passed through: %v", err)
	}
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never opened", addr)
}

func TestNamedJournalAndSigning(t *testing.T) {
	need(t, "named", "nsupdate", "named-compilezone")
	dir := setup(t)
	conf := filepath.Join(dir, "named.conf")
	// bad.example.net would stop named from loading; drop it here.
	b, _ := os.ReadFile(conf)
	b = bytes.Replace(b, []byte(`zone "bad.example.net"`), []byte(`zone "unused.bad.example.net"`), 1)
	os.WriteFile(conf, b, 0o644)
	os.WriteFile(filepath.Join(dir, "bad.example.net.db"), []byte("$TTL 300\n@ IN SOA ns1.example.net. h.example.net. 1 1 1 1 1\n@ IN NS ns1.example.net.\n"), 0o644)
	var logb bytes.Buffer
	named := exec.Command("named", "-g", "-c", conf)
	named.Stdout, named.Stderr = &logb, &logb
	if err := named.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		named.Process.Kill()
		named.Wait()
		if t.Failed() {
			t.Logf("named log:\n%s", logb.String())
		}
	}()
	waitPort(t, "127.0.0.1:5300")

	upd := exec.Command("nsupdate", "-p", "5300")
	upd.Stdin = strings.NewReader("server 127.0.0.1 5300\nzone dyn.example.com\nupdate add new.dyn.example.com. 300 IN A 192.0.2.77\nsend\n")
	if out, err := upd.CombinedOutput(); err != nil {
		t.Fatalf("nsupdate: %v: %s", err, out)
	}
	src := &source.BIND{ConfFile: conf}
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	var journalOK, signedOK bool
	for time.Now().Before(deadline) && !(journalOK && signedOK) {
		zones := listing(t, src)
		if c, _, err := engine.Prepare(ctx, src, zones["dyn.example.com"]); err == nil && hasRecord(c, "new.dyn.example.com. 300 IN A 192.0.2.77") {
			journalOK = true
		}
		if c, sr, err := engine.Prepare(ctx, src, zones["signed.example.net"]); err == nil && sr.SignedAtSource {
			for _, l := range c.Lines {
				for _, typ := range []string{" RRSIG ", " DNSKEY ", " NSEC "} {
					if strings.Contains(l, typ) {
						t.Fatalf("DNSSEC record not stripped: %s", l)
					}
				}
			}
			signedOK = true
		}
		time.Sleep(time.Second)
	}
	if !journalOK {
		t.Error("the update in the journal was never seen (named-compilezone -j)")
	}
	if !signedOK {
		t.Error("the zone signed by named was never reported as signed at the source")
	}
	if r, d := src.Running(ctx); r != source.RunningYes {
		t.Errorf("named running check: %v %s", r, d)
	}
}

func pdns(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, os.Getenv("PDNS_TEST_URL")+path, rd)
	req.Header.Set("X-API-Key", os.Getenv("PDNS_TEST_KEY"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func TestPowerDNS(t *testing.T) {
	if os.Getenv("PDNS_TEST_URL") == "" {
		t.Skip("PDNS_TEST_URL not set")
	}
	keyFile := filepath.Join(t.TempDir(), "key")
	os.WriteFile(keyFile, []byte(os.Getenv("PDNS_TEST_KEY")), 0o600)
	rr := func(name, typ string, ttl int, content ...string) map[string]any {
		var recs []map[string]any
		for _, c := range content {
			recs = append(recs, map[string]any{"content": c, "disabled": false})
		}
		return map[string]any{"name": name, "type": typ, "ttl": ttl, "records": recs, "changetype": "REPLACE"}
	}
	zone := map[string]any{
		"name": "pdns.example.com.", "kind": "Native", "nameservers": []string{},
		"rrsets": []any{
			rr("pdns.example.com.", "SOA", 3600, "ns1.example.net. hostmaster.example.net. 2026112001 3600 900 604800 300"),
			rr("pdns.example.com.", "NS", 3600, "ns1.example.net."),
			rr("www.pdns.example.com.", "A", 300, "192.0.2.10"),
			rr("pdns.example.com.", "TXT", 300, `"v=spf1 -all"`),
			rr("pdns.example.com.", "MX", 300, "10 mail.pdns.example.com."),
		},
	}
	pdns(t, "DELETE", "/api/v1/servers/localhost/zones/pdns.example.com.", nil)
	pdns(t, "DELETE", "/api/v1/servers/localhost/zones/sec.example.net.", nil)
	if code, body := pdns(t, "POST", "/api/v1/servers/localhost/zones", zone); code != 201 {
		t.Fatalf("create zone: %d %s", code, body)
	}
	if code, body := pdns(t, "POST", "/api/v1/servers/localhost/zones", map[string]any{"name": "sec.example.net.", "kind": "Slave", "masters": []string{"192.0.2.53"}}); code != 201 {
		t.Fatalf("create secondary: %d %s", code, body)
	}
	src := &source.PowerDNS{BaseURL: os.Getenv("PDNS_TEST_URL"), KeyFile: keyFile}
	ctx := context.Background()
	l, err := src.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var ref *source.ZoneRef
	for i, z := range l.Zones {
		if z.Name == "sec.example.net" {
			t.Fatal("secondary zone listed")
		}
		if z.Name == "pdns.example.com" {
			ref = &l.Zones[i]
		}
	}
	if ref == nil {
		t.Fatalf("zone not listed: %+v", l.Zones)
	}
	c, _, err := engine.Prepare(ctx, src, *ref)
	if err != nil {
		t.Fatal(err)
	}
	local := "$ORIGIN pdns.example.com.\n@ 3600 IN SOA ns1.example.net. hostmaster.example.net. 2026112001 3600 900 604800 300\n@ 3600 IN NS ns1.example.net.\nwww 300 IN A 192.0.2.10\n@ 300 IN TXT \"v=spf1 -all\"\n@ 300 IN MX 10 mail\n"
	rrs, err := zonefile.Parse([]byte(local), zonefile.Options{Origin: "pdns.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := zonefile.MakeCanonical(rrs, "pdns.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash != want.Hash {
		t.Fatalf("PowerDNS export hash differs from the zone file's:\n%s\n---\n%s", c.HashInput(), want.HashInput())
	}
	// Turning on DNSSEC makes the export carry DNSSEC records (or not, by
	// version); either way none may survive the strip.
	pdns(t, "PUT", "/api/v1/servers/localhost/zones/pdns.example.com.", map[string]any{"dnssec": true})
	l, _ = src.List(ctx)
	for _, z := range l.Zones {
		if z.Name == "pdns.example.com" {
			c2, _, err := engine.Prepare(ctx, src, z)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range c2.Lines {
				if strings.Contains(line, " DNSKEY ") || strings.Contains(line, " RRSIG ") {
					t.Fatalf("DNSSEC record not stripped: %s", line)
				}
			}
		}
	}
	if r, _ := src.Running(ctx); r != source.RunningYes {
		t.Fatalf("running %v", r)
	}
}

// TestACLAccess runs as the paneldns-agent user after the workflow has set
// the ACLs that enrol would set (tools/aclplan). The agent reads every
// zone but not the rndc key.
func TestACLAccess(t *testing.T) {
	conf := os.Getenv("PANELDNS_ACL_TEST_CONF")
	if conf == "" {
		t.Skip("PANELDNS_ACL_TEST_CONF not set")
	}
	src := &source.BIND{ConfFile: conf}
	l, err := src.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Zones) == 0 {
		t.Fatal("no zones listed")
	}
	for _, z := range l.Zones {
		if z.Name == "bad.example.net" {
			continue
		}
		if _, _, err := engine.Prepare(context.Background(), src, z); err != nil {
			t.Errorf("%s: %v", z.Name, err)
		}
	}
	key := filepath.Join(filepath.Dir(conf), "rndc.key")
	if _, err := os.ReadFile(key); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("the agent user can read %s (err=%v)", key, err)
	}
	found := false
	for _, u := range l.Unreadable {
		found = found || u == key
	}
	if !found {
		t.Fatalf("unreadable rndc.key not reported: %v", l.Unreadable)
	}
}
