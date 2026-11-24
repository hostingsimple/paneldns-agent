package enrol

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/namedconf"
)

type modeFI struct{ mode fs.FileMode }

func (m modeFI) Name() string       { return "" }
func (m modeFI) Size() int64        { return 0 }
func (m modeFI) Mode() fs.FileMode  { return m.mode }
func (m modeFI) ModTime() time.Time { return time.Time{} }
func (m modeFI) IsDir() bool        { return m.mode.IsDir() }
func (m modeFI) Sys() any           { return nil }

func TestPlanACLs(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/named.conf": `include "/etc/rndc.key"; include "/etc/named.zones.conf";
options { directory "/var/named"; };
zone "example.com" { type master; file "example.com.db"; };
zone "example.net" { type master; file "/var/named/hosted/example.net.db"; };`,
		"/etc/rndc.key":                     `key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
		"/etc/named.zones.conf":             `zone "zones.example.com" { type master; file "z/zones.example.com.db"; };`,
		"/var/named/example.com.db":         "",
		"/var/named/example.com.db.jnl":     "",
		"/var/named/hosted/example.net.db":  "",
		"/var/named/z/zones.example.com.db": "",
		"/etc/virtual/domainowners":         "",
	})
	// /var/named is 0750 root:named; /etc and /var are world-searchable.
	statFunc = func(p string) (fs.FileInfo, error) {
		rel := strings.TrimPrefix(filepath.ToSlash(p), Root)
		switch rel {
		case "/var/named", "/etc/virtual":
			return modeFI{fs.ModeDir | 0o750}, nil
		}
		return os.Stat(p)
	}
	defer func() { statFunc = os.Stat }()
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	cfg.OwnersFile = "/etc/virtual/domainowners"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantRead := []string{
		"/etc/named.conf", "/etc/named.zones.conf", "/etc/virtual/domainowners",
		"/var/named/example.com.db", "/var/named/example.com.db.jnl",
		"/var/named/hosted/example.net.db", "/var/named/z/zones.example.com.db",
	}
	if !reflect.DeepEqual(p.Read, wantRead) {
		t.Fatalf("read %v", p.Read)
	}
	if !reflect.DeepEqual(p.Dirs, []string{"/var/named", "/var/named/hosted", "/var/named/z"}) {
		t.Fatalf("dirs %v", p.Dirs)
	}
	if !reflect.DeepEqual(p.Traverse, []string{"/etc/virtual"}) {
		t.Fatalf("traverse %v", p.Traverse)
	}
	if !reflect.DeepEqual(p.Skipped, []string{"/etc/rndc.key"}) {
		t.Fatalf("skipped %v", p.Skipped)
	}
	var ran []string
	if err := ApplyACLs(p, func(argv []string) error { ran = append(ran, strings.Join(argv[:4], " ")); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"setfacl -m u:paneldns-agent:x /etc/virtual",
		"setfacl -m u:paneldns-agent:rx /var/named",
		"setfacl -d -m u:paneldns-agent:r",
		"setfacl -m u:paneldns-agent:r /etc/named.conf",
	}
	if !reflect.DeepEqual(ran, want) {
		t.Fatalf("commands %q", ran)
	}
	for _, c := range p.Commands() {
		for _, a := range c {
			if a == "/etc/rndc.key" {
				t.Fatal("ACL granted on the rndc key")
			}
		}
	}
}

func TestInlineKeysRefused(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string // "" = accepted
	}{
		{"key in named.conf", map[string]string{
			"/etc/named.conf": `options { directory "/var/named"; };
key "rndc-key" { secret "c2VjcmV0"; };`,
		}, `/etc/named.conf:2 (key "rndc-key")`},
		{"key in an include with zones", map[string]string{
			"/etc/named.conf": `include "/etc/named.zones.conf";`,
			"/etc/named.zones.conf": `zone "example.com" { type master; file "a.db"; };
key "tsig-example" { secret "c2VjcmV0"; };`,
		}, `/etc/named.zones.conf:2 (key "tsig-example")`},
		{"key inside a view", map[string]string{
			"/etc/named.conf": `view "external" { key "xfer" { secret "c2VjcmV0"; }; zone "example.com" { type master; file "a.db"; }; };`,
		}, `(key "xfer")`},
		{"separate key file is fine", map[string]string{
			"/etc/named.conf": `include "/etc/rndc.key"; controls { inet 127.0.0.1 allow { 127.0.0.1; } keys { "rndc-key"; key; }; };`,
			"/etc/rndc.key":   `key "rndc-key" { secret "c2VjcmV0"; };`,
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRoot(t, tt.files)
			cfg := config.Defaults()
			cfg.ZonesFile = "/etc/named.conf"
			errs := []error{RefuseInlineKeys(cfg)}
			_, err := PlanACLs(cfg)
			errs = append(errs, err)
			for i, err := range errs {
				if tt.want == "" {
					if err != nil {
						t.Fatalf("%d: %v", i, err)
					}
					continue
				}
				if !errors.Is(err, namedconf.ErrInlineKey) || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "separate file") {
					t.Fatalf("%d: want inline-key error naming %s, got %v", i, tt.want, err)
				}
			}
		})
	}
}

func TestEnrolRefusesInlineKeyBeforeContactingPanelDNS(t *testing.T) {
	withRoot(t, map[string]string{"/etc/named.conf": `key "k" { secret "c2VjcmV0"; }; zone "example.com" { type master; file "a.db"; };`})
	dir := t.TempDir()
	_, err := Run(context.Background(), Options{
		URL: "https://app.example.com", Code: "x", ConfigPath: filepath.Join(dir, "c.conf"), StateDir: filepath.Join(dir, "s"),
		SkipRootTest: true,
		Detect:       func() (Detected, error) { return Detected{ZoneSource: "bind", ZonesFile: "/etc/named.conf"}, nil },
	})
	if !errors.Is(err, namedconf.ErrInlineKey) || !strings.Contains(err.Error(), "/etc/named.conf:1") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "s")); err == nil {
		t.Fatal("state directory created although enrolment was refused")
	}
}

func TestPlanACLsFollowsZoneIncludes(t *testing.T) {
	conf := `options { directory "/var/named"; };
zone "example.com" { type master; file "example.com.db"; };`
	soa := "$TTL 300\n@ IN SOA ns1.example.net. h.example.net. 1 1 1 1 1\n"
	tests := []struct {
		name      string
		zone      string
		extra     map[string]string
		read      []string // included files expected in the plan
		dirs      []string
		warn      string
		refusedAs string
	}{
		{name: "nested relative includes", zone: soa + "$INCLUDE inc/www.db\n; $INCLUDE commented/out.db\n$INCLUDE \"inc/quoted.db\" sub\n",
			extra: map[string]string{
				"/var/named/inc/www.db":      "www IN A 192.0.2.80\n$INCLUDE inc/deeper/x.db\n",
				"/var/named/inc/deeper/x.db": "x IN A 192.0.2.81\n$INCLUDE inc/www.db\n", // loop back: followed once
				"/var/named/inc/quoted.db":   "q IN A 192.0.2.82\n",
			},
			read: []string{"/var/named/inc/deeper/x.db", "/var/named/inc/quoted.db", "/var/named/inc/www.db"},
			dirs: []string{"/var/named", "/var/named/inc", "/var/named/inc/deeper"}},
		{name: "absolute include inside directory", zone: soa + "$INCLUDE /var/named/shared/ns.db\n",
			extra: map[string]string{"/var/named/shared/ns.db": "@ IN NS ns1.example.net.\n"},
			read:  []string{"/var/named/shared/ns.db"}, dirs: []string{"/var/named", "/var/named/shared"}},
		{name: "outside", zone: soa + "$INCLUDE /etc/passwd\n", refusedAs: "outside named's directory"},
		{name: "dot-dot escape", zone: soa + "$INCLUDE ../../etc/shadow\n", refusedAs: "resolves to /etc/shadow"},
		{name: "rndc key", zone: soa + "$INCLUDE /etc/rndc.key\n", refusedAs: "outside"},
		{name: "tsig key in a zone fragment", zone: soa + "$INCLUDE tsig.db\n",
			extra:     map[string]string{"/var/named/tsig.db": "key \"xfer\" {\n algorithm hmac-sha256;\n secret \"c2VjcmV0\";\n};\n"},
			refusedAs: "holds key material"},
		{name: "dnssec private key", zone: soa + "$INCLUDE Kexample.com.+013+12345.private\n",
			extra:     map[string]string{"/var/named/Kexample.com.+013+12345.private": "Private-key-format: v1.3\n"},
			refusedAs: "key material"},
		{name: "dnssec public key is fine", zone: soa + "$INCLUDE Kexample.com.+013+12345.key\n",
			extra: map[string]string{"/var/named/Kexample.com.+013+12345.key": "example.com. IN DNSKEY 257 3 13 dGVzdA==\n"},
			read:  []string{"/var/named/Kexample.com.+013+12345.key"}, dirs: []string{"/var/named"}},
		{name: "missing include warns", zone: soa + "$INCLUDE inc/missing.db\n", dirs: []string{"/var/named"}, warn: "missing.db"},
		{name: "too deep", zone: soa + "$INCLUDE d1.db\n", extra: func() map[string]string {
			m := map[string]string{}
			for i := 1; i <= 9; i++ {
				m["/var/named/d"+strconv.Itoa(i)+".db"] = "$INCLUDE d" + strconv.Itoa(i+1) + ".db\n"
			}
			m["/var/named/d10.db"] = ""
			return m
		}(), refusedAs: "nested deeper than 8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"/etc/named.conf": conf, "/var/named/example.com.db": tt.zone}
			for k, v := range tt.extra {
				files[k] = v
			}
			withRoot(t, files)
			cfg := config.Defaults()
			cfg.ZonesFile = "/etc/named.conf"
			p, err := PlanACLs(cfg)
			if tt.refusedAs != "" {
				if !errors.Is(err, ErrIncludeRefused) || !strings.Contains(err.Error(), tt.refusedAs) || !(strings.Contains(err.Error(), "/var/named/example.com.db:3: $INCLUDE") || strings.Contains(err.Error(), ".db:1: $INCLUDE")) {
					t.Fatalf("want refusal %q naming file and line, got %v", tt.refusedAs, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range tt.read {
				if !contains(p.Read, f) {
					t.Errorf("no read ACL for %s: %v", f, p.Read)
				}
			}
			if !reflect.DeepEqual(p.Dirs, tt.dirs) {
				t.Errorf("dirs %v, want %v", p.Dirs, tt.dirs)
			}
			if tt.warn != "" && (len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], tt.warn)) {
				t.Errorf("warnings %v", p.Warnings)
			}
		})
	}
}

func TestZoneIncludesChroot(t *testing.T) {
	withRoot(t, map[string]string{
		"/var/named/run-root/var/named/example.com.db": "$INCLUDE /var/named/inc/a.db\n",
		"/var/named/run-root/var/named/inc/a.db":       "a IN A 192.0.2.1\n",
	})
	files, warns, err := zoneIncludes("/var/named/run-root/var/named/example.com.db", "/var/named/run-root/var/named", "/var/named/run-root", []string{"/var/named/run-root/var/named"})
	if err != nil || len(warns) != 0 || !reflect.DeepEqual(files, []string{"/var/named/run-root/var/named/inc/a.db"}) {
		t.Fatalf("files %v warns %v err %v", files, warns, err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Review A-7: a default ACL on a directory that also holds configuration
// or key files would give the agent read access to a key created there
// later (rndc-confgen -a, tsig-keygen > x.key). Such directories get rx
// only; key files in planned directories are listed for stripping.
func TestPlanACLsNoDefaultACLBesideKeys(t *testing.T) {
	const soa = "$TTL 300\n@ IN SOA ns1.example.net. h.example.net. 1 1 1 1 1\n"
	tests := []struct {
		name      string
		files     map[string]string
		zonesFile string
		dirs      []string
		noDefault []string
		strip     []string
	}{
		{name: "debian /etc/bind with the rndc key", zonesFile: "/etc/bind/named.conf", files: map[string]string{
			"/etc/bind/named.conf": `include "/etc/bind/rndc.key";
options { directory "/var/cache/bind"; };
zone "example.com" { type master; file "/etc/bind/db.example.com"; };`,
			"/etc/bind/rndc.key":       `key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
			"/etc/bind/db.example.com": soa,
		}, dirs: []string{"/etc/bind"}, noDefault: []string{"/etc/bind"}, strip: []string{"/etc/bind/rndc.key"}},
		{name: "debian /etc/bind before any key exists", zonesFile: "/etc/bind/named.conf", files: map[string]string{
			"/etc/bind/named.conf":     `zone "example.com" { type master; file "/etc/bind/db.example.com"; };`,
			"/etc/bind/db.example.com": soa,
		}, dirs: []string{"/etc/bind"}, noDefault: []string{"/etc/bind"}},
		{name: "directory of an included config file", zonesFile: "/etc/named.conf", files: map[string]string{
			"/etc/named.conf":                `include "/var/named/conf/zones.conf"; options { directory "/var/named"; };`,
			"/var/named/conf/zones.conf":     `zone "example.com" { type master; file "conf/example.com.db"; };`,
			"/var/named/conf/example.com.db": soa,
		}, dirs: []string{"/var/named/conf"}, noDefault: []string{"/var/named/conf"}},
		{name: "where the rndc key is written", zonesFile: "/etc/named.conf", files: map[string]string{
			"/etc/named.conf":           `zone "example.com" { type master; file "/etc/named/example.com.db"; };`,
			"/etc/named/example.com.db": soa,
		}, dirs: []string{"/etc/named"}, noDefault: []string{"/etc/named"}},
		{name: "tsig key and dnssec key beside zones", zonesFile: "/etc/named.conf", files: map[string]string{
			"/etc/named.conf": `options { directory "/var/named"; };
zone "a.example" { type master; file "keyed/a.example.db"; };
zone "b.example" { type master; file "dnssec/b.example.db"; };
zone "c.example" { type master; file "plain/c.example.db"; };`,
			"/var/named/keyed/a.example.db":                   soa,
			"/var/named/keyed/xfer.key":                       `key "xfer" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
			"/var/named/dnssec/b.example.db":                  soa,
			"/var/named/dnssec/Kb.example.+013+12345.private": "Private-key-format: v1.3\n",
			"/var/named/dnssec/Kb.example.+013+12345.key":     "b.example. IN DNSKEY 257 3 13 dGVzdA==\n",
			"/var/named/plain/c.example.db":                   soa,
			"/var/named/plain/c.example.db.jnl":               "",
		},
			dirs:      []string{"/var/named/dnssec", "/var/named/keyed", "/var/named/plain"},
			noDefault: []string{"/var/named/dnssec", "/var/named/keyed"},
			strip: []string{"/var/named/dnssec/Kb.example.+013+12345.key", "/var/named/dnssec/Kb.example.+013+12345.private",
				"/var/named/keyed/xfer.key"}},
		{name: "zone-only directory keeps the default", zonesFile: "/etc/named.conf", files: map[string]string{
			"/etc/named.conf":           `options { directory "/var/named"; }; zone "example.com" { type master; file "example.com.db"; };`,
			"/var/named/example.com.db": soa,
			"/var/named/named.ca":       "",
		}, dirs: []string{"/var/named"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRoot(t, tt.files)
			cfg := config.Defaults()
			cfg.ZonesFile = tt.zonesFile
			p, err := PlanACLs(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.Dirs, tt.dirs) || !reflect.DeepEqual(p.NoDefault, tt.noDefault) || !reflect.DeepEqual(p.Strip, tt.strip) {
				t.Fatalf("dirs %v no-default %v strip %v; want %v %v %v", p.Dirs, p.NoDefault, p.Strip, tt.dirs, tt.noDefault, tt.strip)
			}
			no := map[string]bool{}
			for _, d := range tt.noDefault {
				no[d] = true
			}
			defaults := 0
			for _, c := range p.Commands() {
				for _, a := range c[3:] {
					if contains(p.Strip, a) {
						t.Fatalf("%q grants on key file %s", c[:3], a)
					}
				}
				if c[1] != "-d" {
					continue
				}
				for _, d := range c[4:] {
					if no[d] {
						t.Fatalf("default ACL on %s, which holds configuration or keys", d)
					}
					defaults++
				}
			}
			if want := len(tt.dirs) - len(tt.noDefault); defaults != want {
				t.Fatalf("%d directories get the default ACL, want %d", defaults, want)
			}
		})
	}
}

// A symbolic link named like a key is not a key file in that directory:
// fix-acls must not follow it to strip (or touch) whatever it points at.
func TestPlanACLsKeyScanSkipsSymlinks(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/named.conf":           `options { directory "/var/named"; }; zone "example.com" { type master; file "example.com.db"; };`,
		"/var/named/example.com.db": "",
		"/srv/elsewhere":            "",
	})
	if err := os.Symlink(filepath.Join(Root, "srv", "elsewhere"), filepath.Join(Root, "var", "named", "x.key")); err != nil {
		t.Skip("symbolic links unavailable:", err)
	}
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Strip) != 0 || len(p.NoDefault) != 0 {
		t.Fatalf("strip %v no-default %v", p.Strip, p.NoDefault)
	}
}

// A key file others can read is reported: an ACL can't take that away.
func TestPlanACLsWarnsOnWorldReadableKey(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/bind/named.conf":     `zone "example.com" { type master; file "/etc/bind/db.example.com"; };`,
		"/etc/bind/db.example.com": "",
		"/etc/bind/xfer.key":       `key "xfer" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
		"/etc/bind/rndc.key":       `key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
	})
	statFunc = func(p string) (fs.FileInfo, error) {
		switch strings.TrimPrefix(filepath.ToSlash(p), Root) {
		case "/etc/bind/xfer.key":
			return modeFI{0o644}, nil
		case "/etc/bind/rndc.key":
			return modeFI{0o640}, nil
		}
		return os.Stat(p)
	}
	defer func() { statFunc = os.Stat }()
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/bind/named.conf"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(p.Warnings, "\n")
	if !strings.Contains(w, "key file /etc/bind/xfer.key has mode 0644") || strings.Contains(w, "rndc.key") {
		t.Fatalf("warnings %q", p.Warnings)
	}
}

// named.conf's key-directory folders (options, a view, a zone) are known to
// the plan: never rx or a default ACL, their private keys stripped of any
// agent entry, even when a zone $INCLUDEs a public key from one.
func TestPlanACLsKeyDirectory(t *testing.T) {
	soa := "$TTL 300\n@ IN SOA ns1.example.net. h.example.net. 1 1 1 1 1\n"
	withRoot(t, map[string]string{
		"/etc/named.conf": `options { directory "/var/named"; key-directory "keys"; };
zone "example.com" { type master; file "example.com.db"; };
zone "example.net" { type master; file "/srv/zones/example.net.db"; key-directory "/srv/zones"; };
zone "example.org" { type master; file "example.org.db"; key-directory "/etc/dnssec/org"; };`,
		"/var/named/example.com.db":                   soa + "$INCLUDE keys/Kexample.com.+013+1.key\n",
		"/var/named/example.org.db":                   soa,
		"/var/named/keys/Kexample.com.+013+1.key":     "example.com. IN DNSKEY 257 3 13 dGVzdA==\n",
		"/var/named/keys/Kexample.com.+013+1.private": "Private-key-format: v1.3\n",
		"/srv/zones/example.net.db":                   soa,
		"/srv/zones/Kexample.net.+013+2.private":      "Private-key-format: v1.3\n",
		"/etc/dnssec/org/Kexample.org.+013+3.private": "Private-key-format: v1.3\n",
	})
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/etc/dnssec/org", "/srv/zones", "/var/named/keys"}; !reflect.DeepEqual(p.KeyDirs, want) {
		t.Fatalf("key dirs %v, want %v", p.KeyDirs, want)
	}
	for _, d := range p.Dirs {
		if d == "/var/named/keys" || d == "/etc/dnssec/org" {
			t.Errorf("key directory %s planned as a zone directory", d)
		}
	}
	if !slices.Contains(p.Read, "/var/named/keys/Kexample.com.+013+1.key") {
		t.Errorf("the $INCLUDEd public key lost its read access: %v", p.Read)
	}
	// A zone directory that is also a key-directory: rx, no default ACL.
	if !slices.Contains(p.Dirs, "/srv/zones") || !slices.Contains(p.NoDefault, "/srv/zones") {
		t.Errorf("dirs %v no-default %v", p.Dirs, p.NoDefault)
	}
	for _, k := range []string{"/var/named/keys/Kexample.com.+013+1.private", "/srv/zones/Kexample.net.+013+2.private", "/etc/dnssec/org/Kexample.org.+013+3.private"} {
		if !slices.Contains(p.Strip, k) {
			t.Errorf("%s not stripped: %v", k, p.Strip)
		}
	}
	for _, c := range p.Commands() {
		for _, a := range c {
			if strings.HasPrefix(a, "/etc/dnssec") || strings.HasSuffix(a, ".private") {
				t.Errorf("setfacl on %s: %q", a, c)
			}
		}
	}
}
