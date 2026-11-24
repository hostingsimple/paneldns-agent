package source

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeFile struct {
	data  string
	mtime time.Time
	deny  bool
}

type fakeFI struct {
	name string
	f    *fakeFile
}

func (fi fakeFI) Name() string       { return path.Base(fi.name) }
func (fi fakeFI) Size() int64        { return int64(len(fi.f.data)) }
func (fi fakeFI) Mode() fs.FileMode  { return 0o644 }
func (fi fakeFI) ModTime() time.Time { return fi.f.mtime }
func (fi fakeFI) IsDir() bool        { return false }
func (fi fakeFI) Sys() any           { return nil }

type memFS map[string]*fakeFile

func (m memFS) put(p, data string) { m[p] = &fakeFile{data: data, mtime: time.Unix(1795000000, 0)} }

func (m memFS) bind(b *BIND) *BIND {
	b.ReadFile = func(p string) ([]byte, error) {
		f, ok := m[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		if f.deny {
			return nil, os.ErrPermission
		}
		return []byte(f.data), nil
	}
	b.Stat = func(p string) (fs.FileInfo, error) {
		f, ok := m[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return fakeFI{p, f}, nil
	}
	b.Glob = func(string) ([]string, error) { return nil, nil }
	return b
}

const namedConf = `
include "/etc/rndc.key";
options { directory "/var/named"; check-names master warn; };
zone "example.com" { type master; file "example.com.db"; };
zone "example.net" { type master; file "example.net.db"; check-integrity no; };
zone "secondary.example.net" { type slave; file "s.db"; masters { 192.0.2.1; }; };
zone "localhost" { type master; file "named.localhost"; };
`

const exampleCom = `$TTL 300
@ IN SOA ns1.example.com. hostmaster.example.com. ( 2026112001 3600 900 604800 300 )
@ IN NS ns1
ns1 IN A 192.0.2.1
$INCLUDE inc/www.db
`

func newFS() memFS {
	m := memFS{}
	m.put("/etc/named.conf", namedConf)
	m["/etc/rndc.key"] = &fakeFile{deny: true}
	m.put("/var/named/example.com.db", exampleCom)
	m.put("/var/named/inc/www.db", "www IN A 192.0.2.80\n")
	m.put("/var/named/example.net.db", "$TTL 60\n@ IN SOA ns1.example.net. h.example.net. 7 1 1 1 1\n@ IN A 192.0.2.2\n")
	m.put("/var/named/named.localhost", "$TTL 1\n@ IN SOA @ root 1 1 1 1 1\n@ IN A 127.0.0.1\n")
	return m
}

func TestBINDListAndFingerprint(t *testing.T) {
	m := newFS()
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true})
	ctx := context.Background()
	l, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	fp := map[string]string{}
	for _, z := range l.Zones {
		names = append(names, z.Name)
		fp[z.Name] = z.Fingerprint
	}
	// The source lists every primary zone; system zones are filtered later.
	if !reflect.DeepEqual(names, []string{"example.com", "example.net", "localhost"}) {
		t.Fatalf("zones %v", names)
	}
	if l.Skipped != 1 || !reflect.DeepEqual(l.Unreadable, []string{"/etc/rndc.key"}) || len(l.Warnings) != 0 {
		t.Fatalf("listing %+v", l)
	}

	relist := func() map[string]string {
		l, err := b.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, z := range l.Zones {
			out[z.Name] = z.Fingerprint
		}
		return out
	}
	if got := relist(); !reflect.DeepEqual(got, fp) {
		t.Fatal("fingerprints changed without a change")
	}
	// Touching an $INCLUDEd file changes only that zone's fingerprint.
	m["/var/named/inc/www.db"].mtime = time.Unix(1795000100, 0)
	got := relist()
	if got["example.com"] == fp["example.com"] || got["example.net"] != fp["example.net"] {
		t.Fatalf("include change not detected precisely: %v vs %v", got, fp)
	}
	fp = got
	// A new journal changes the fingerprint.
	m.put("/var/named/example.net.db.jnl", "binary")
	got = relist()
	if got["example.net"] == fp["example.net"] {
		t.Fatal("journal not in fingerprint")
	}
}

func TestBINDFallbackRead(t *testing.T) {
	m := newFS()
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true})
	ctx := context.Background()
	l, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := b.Read(ctx, l.Zones[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 4 || rrs[3].Name != "www.example.com." {
		t.Fatalf("records %+v", rrs)
	}
	m.put("/var/named/example.com.db.jnl", "x")
	if _, err := b.Read(ctx, l.Zones[0]); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("journal not refused: %v", err)
	}
	if _, err := b.Read(ctx, ZoneRef{Name: "nope.example.com", key: "/x"}); err == nil {
		t.Fatal("unknown zone read")
	}
}

func TestBINDCompilezoneArgs(t *testing.T) {
	m := newFS()
	var argv [][]string
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", Compilezone: "/usr/sbin/named-compilezone"})
	b.Run = func(ctx context.Context, a []string) ([]byte, []byte, error) {
		argv = append(argv, a)
		out := "zone example.net/IN: loaded serial 7\n" +
			"example.net.  60 IN SOA ns1.example.net. h.example.net. 7 1 1 1 1\n" +
			"example.net.  60 IN A 192.0.2.2\n" +
			"OK\n"
		return []byte(out), nil, nil
	}
	ctx := context.Background()
	l, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := b.Read(ctx, l.Zones[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(rrs) != 2 {
		t.Fatalf("status lines not filtered: %+v", rrs)
	}
	want := []string{"/usr/sbin/named-compilezone", "-w", "/var/named", "-j", "-k", "warn", "-i", "none", "-f", "text", "-F", "text", "-s", "full", "-o", "-", "example.net", "/var/named/example.net.db"}
	if !reflect.DeepEqual(argv[0], want) {
		t.Fatalf("argv %q\nwant %q", argv[0], want)
	}
	b.Run = func(ctx context.Context, a []string) ([]byte, []byte, error) {
		return nil, []byte("example.net:3: ns1.example.net: bad owner name (check-names)"), os.ErrInvalid
	}
	_, err = b.Read(ctx, l.Zones[1])
	if err == nil || !strings.Contains(err.Error(), "check-names") {
		t.Fatalf("compile error not passed through: %v", err)
	}
}

func TestBINDRunning(t *testing.T) {
	m := newFS()
	m.put("/run/named/named.pid", "4242\n")
	var asked int
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true, Alive: func(pid int) Running {
		asked = pid
		return RunningYes
	}})
	if r, _ := b.Running(context.Background()); r != RunningYes || asked != 4242 {
		t.Fatalf("running %v pid %d", r, asked)
	}
	delete(m, "/run/named/named.pid")
	active := false
	b.UnitActive = func(ctx context.Context, unit string) (bool, error) { return active && unit == "bind9.service", nil }
	if r, _ := b.Running(context.Background()); r != RunningUnknown {
		t.Fatalf("running %v", r)
	}
	active = true
	if r, d := b.Running(context.Background()); r != RunningYes || !strings.Contains(d, "bind9.service") {
		t.Fatalf("systemd fallback: %v %s", r, d)
	}
}

func TestPowerDNS(t *testing.T) {
	dir := t.TempDir()
	keyFile := path.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("secret-test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret-test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/servers/localhost":
			w.Write([]byte(`{"id":"localhost"}`))
		case "/api/v1/servers/localhost/zones":
			if r.URL.Query().Get("dnssec") != "false" {
				t.Errorf("dnssec=false missing")
			}
			w.Write([]byte(`[
				{"id":"example.com.","name":"example.com.","kind":"Native","serial":2026112001,"edited_serial":2026112002},
				{"id":"example.net.","name":"Example.NET.","kind":"Master","serial":1,"edited_serial":1},
				{"id":"secondary.example.net.","name":"secondary.example.net.","kind":"Slave","serial":1},
				{"id":"catalog.example.net.","name":"catalog.example.net.","kind":"Producer","serial":1}
			]`))
		case "/api/v1/servers/localhost/zones/example.com./export":
			w.Header().Set("Content-Type", "text/plain; charset=us-ascii")
			w.Write([]byte("example.com.\t3600\tIN\tSOA\tns1.example.com. h.example.com. 2026112001 10800 3600 604800 3600\nexample.com.\t3600\tIN\tTXT\t\"v=spf1 -all\"\n"))
		case "/api/v1/servers/localhost/zones/example.net./export":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"zone":"example.net.\t60\tIN\tSOA\tns1.example.net. h.example.net. 1 1 1 1 1\n"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Not Found"}`))
		}
	}))
	defer srv.Close()
	p := &PowerDNS{BaseURL: srv.URL, KeyFile: keyFile, CheckListener: noListenerCheck}
	ctx := context.Background()
	l, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Zones) != 2 || l.Skipped != 2 || l.Zones[1].Name != "example.net" || l.Zones[0].Fingerprint != "s=2026112001;e=2026112002" {
		t.Fatalf("listing %+v", l)
	}
	rrs, err := p.Read(ctx, l.Zones[0])
	if err != nil || len(rrs) != 2 || rrs[1].Data[0].Text != "v=spf1 -all" {
		t.Fatalf("read %+v %v", rrs, err)
	}
	rrs, err = p.Read(ctx, l.Zones[1])
	if err != nil || len(rrs) != 1 {
		t.Fatalf("json-wrapped read %+v %v", rrs, err)
	}
	if _, err := p.Read(ctx, ZoneRef{Name: "missing.example.com", key: "missing.example.com."}); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("missing zone: %v", err)
	}
	if r, _ := p.Running(ctx); r != RunningYes {
		t.Fatalf("running %v", r)
	}
	bad := &PowerDNS{BaseURL: srv.URL, KeyFile: path.Join(dir, "absent"), CheckListener: noListenerCheck}
	if _, err := bad.List(ctx); err == nil {
		t.Fatal("missing key file accepted")
	}
	os.WriteFile(keyFile, []byte("wrong"), 0o600)
	p2 := &PowerDNS{BaseURL: srv.URL, KeyFile: keyFile, CheckListener: noListenerCheck}
	if _, err := p2.List(ctx); err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("wrong key: %v", err)
	}
	down := &PowerDNS{BaseURL: "http://127.0.0.1:1", KeyFile: keyFile, CheckListener: noListenerCheck}
	if r, _ := down.Running(ctx); r != RunningNo {
		t.Fatalf("down server running %v", r)
	}
}

func TestBINDListingReportsInlineKey(t *testing.T) {
	m := newFS()
	m.put("/etc/named.conf", namedConf+`key "xfer-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };`+"\n")
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true})
	l, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.InlineKey == nil || !strings.Contains(l.InlineKey.Error(), `/etc/named.conf:8 (key "xfer-key")`) {
		t.Fatalf("inline key: %v", l.InlineKey)
	}
	// The separate, unreadable /etc/rndc.key of newFS is not inline.
	m.put("/etc/named.conf", namedConf)
	if l, _ := b.List(context.Background()); l.InlineKey != nil {
		t.Fatalf("false positive: %v", l.InlineKey)
	}
}

// A zone file's $INCLUDE may only reach named's directory and the zone
// directories (the files enrol grants access to), never the agent's own
// state directory or key material, whether named-compilezone or the
// built-in parser reads the zone.
func TestBINDRefusesIncludesOutsideZoneDirectories(t *testing.T) {
	for _, tt := range []struct{ name, include, want string }{
		{"agent key", "$INCLUDE /var/lib/paneldns-agent/agent.key\n", "never reads"},
		{"etc", "$INCLUDE /etc/passwd\n", "outside named's directory"},
		{"dot-dot", "$INCLUDE ../../etc/passwd\n", "outside named's directory"},
		{"nested", "$INCLUDE inc/www.db\n", "outside named's directory"},
		{"dnssec key", "$INCLUDE \"Kexample.com.+013+12345.private\"\n", "never reads"},
	} {
		for _, compile := range []bool{false, true} {
			m := newFS()
			m.put("/var/named/example.com.db", strings.Replace(exampleCom, "$INCLUDE inc/www.db\n", tt.include, 1))
			if tt.name == "nested" {
				m.put("/var/named/inc/www.db", "$INCLUDE /home/someone/public_html/wp-config.php\n")
			}
			m.put("/var/lib/paneldns-agent/agent.key", "-----BEGIN PRIVATE KEY-----\n")
			m.put("/etc/passwd", "root:x:0:0::/root:/bin/sh\n")
			b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: !compile, Compilezone: "/usr/sbin/named-compilezone"})
			ran := false
			b.Run = func(context.Context, []string) ([]byte, []byte, error) { ran = true; return nil, nil, os.ErrInvalid }
			l, err := b.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, err = b.Read(context.Background(), l.Zones[0])
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("%s (compile %v): got %v, want %q", tt.name, compile, err, tt.want)
			}
			if ran {
				t.Errorf("%s: named-compilezone ran on a zone with a refused $INCLUDE", tt.name)
			}
		}
	}
	// An include inside the zone directories still works.
	m := newFS()
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true})
	l, _ := b.List(context.Background())
	if _, err := b.Read(context.Background(), l.Zones[0]); err != nil {
		t.Fatal(err)
	}
}

// The PowerDNS API key is read-write: a redirect must not carry it to
// another address.
func TestPowerDNSDoesNotFollowRedirects(t *testing.T) {
	dir := t.TempDir()
	keyFile := path.Join(dir, "key")
	os.WriteFile(keyFile, []byte("secret-test-key\n"), 0o600)
	leaked := ""
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-API-Key")
		w.Write([]byte(`[]`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.RequestURI(), http.StatusFound)
	}))
	defer srv.Close()
	p := &PowerDNS{BaseURL: srv.URL, KeyFile: keyFile, CheckListener: noListenerCheck}
	if _, err := p.List(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect not refused: %v", err)
	}
	if leaked != "" {
		t.Fatalf("the API key reached the redirect target: %q", leaked)
	}
}

// A zone name is a positional argument of named-compilezone; one starting
// with "-" must not reach it as an option.
func TestBINDRefusesZoneNameLikeAnOption(t *testing.T) {
	m := newFS()
	m.put("/etc/named.conf", `options { directory "/var/named"; };
zone "-o/var/lib/paneldns-agent/x" { type master; file "example.com.db"; };`)
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", Compilezone: "/usr/sbin/named-compilezone"})
	ran := false
	b.Run = func(context.Context, []string) ([]byte, []byte, error) { ran = true; return nil, nil, nil }
	l, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(context.Background(), l.Zones[0]); err == nil || ran {
		t.Fatalf("zone %q read (named-compilezone ran: %v): %v", l.Zones[0].Name, ran, err)
	}
}

// The built-in parser holds the zone in memory: a file over the cap is
// refused instead of risking the unit's MemoryMax.
func TestBINDFallbackCapsZoneSize(t *testing.T) {
	m := newFS()
	big := "$TTL 60\n@ IN SOA ns1.example.net. h.example.net. 7 1 1 1 1\n" + strings.Repeat("a IN A 192.0.2.1\n", MaxCompiledSize/17+1)
	m.put("/var/named/example.net.db", big)
	b := m.bind(&BIND{ConfFile: "/etc/named.conf", NoCompilezone: true})
	l, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(context.Background(), l.Zones[1]); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized zone: %v", err)
	}
}
