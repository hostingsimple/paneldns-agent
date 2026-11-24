package namedconf

import (
	"errors"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// fakeFS maps host paths to fixture files; a nil value means "permission
// denied", like an rndc key the agent must not read.
type fakeFS map[string]*string

func fixture(t *testing.T, name string) *string {
	t.Helper()
	b, err := os.ReadFile(path.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	return &s
}

func (f fakeFS) loader(chroot string) *Loader {
	return &Loader{
		Chroot: chroot,
		ReadFile: func(p string) ([]byte, error) {
			v, ok := f[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			if v == nil {
				return nil, os.ErrPermission
			}
			return []byte(*v), nil
		},
		Glob: func(pattern string) ([]string, error) {
			var out []string
			for k := range f {
				if ok, _ := path.Match(pattern, k); ok {
					out = append(out, k)
				}
			}
			sort.Strings(out)
			return out, nil
		},
	}
}

func zoneNames(c *Conf) []string {
	var n []string
	for _, z := range c.Zones {
		n = append(n, z.Name)
	}
	return n
}

func TestCpanelStyleConfig(t *testing.T) {
	fs := fakeFS{
		"/etc/named.conf":         fixture(t, "cpanel-named.conf"),
		"/etc/rndc.key":           nil, // unreadable, as it must be
		"/etc/named.conf.zones":   fixture(t, "named.conf.zones"),
		"/etc/named.d/a.conf":     fixture(t, "glob-a.conf"),
		"/etc/named.d/b.conf":     fixture(t, "glob-b.conf"),
		"/etc/named.d/ignore.txt": fixture(t, "glob-a.conf"),
	}
	l := fs.loader("")
	c, err := Read(l, "/etc/named.conf", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Directory != "/var/named" || c.View != "" || c.PidFile != "/run/named/named.pid" {
		t.Fatalf("directory %q view %q pid %q", c.Directory, c.View, c.PidFile)
	}
	want := []string{"localhost", "0.0.127.in-addr.arpa", "example.com", "example.net", "included.example.com", "glob-a.example.com", "glob-b.example.net"}
	if got := zoneNames(c); !reflect.DeepEqual(got, want) {
		t.Fatalf("zones %v\nwant %v", got, want)
	}
	// hint, slave, forward and the file-less zone are skipped.
	if c.Skipped != 4 {
		t.Errorf("skipped %d, want 4", c.Skipped)
	}
	byName := map[string]Zone{}
	for _, z := range c.Zones {
		byName[z.Name] = z
	}
	ex := byName["example.com"]
	if ex.File != "/var/named/example.com.db" || ex.CheckNames != "warn" || ex.Integrity != "local" || ex.Format != "text" || ex.Journal != "/var/named/example.com.db.jnl" {
		t.Errorf("example.com: %+v", ex)
	}
	en := byName["example.net"]
	if en.File != "/var/named/example.net.db" || en.CheckNames != "ignore" || en.Integrity != "none" {
		t.Errorf("example.net: %+v", en)
	}
	inc := byName["included.example.com"]
	if inc.Format != "raw" || inc.Journal != "/var/named/journals/inc.jnl" || inc.DeclaredIn != "/etc/named.conf.zones" {
		t.Errorf("included: %+v", inc)
	}
	if g := byName["glob-a.example.com"]; g.Integrity != "local-sibling" {
		t.Errorf("glob-a: %+v", g)
	}
	var unreadable []string
	for _, i := range c.Includes {
		if !i.Readable {
			unreadable = append(unreadable, i.Path)
		}
	}
	if !reflect.DeepEqual(unreadable, []string{"/etc/rndc.key"}) {
		t.Errorf("unreadable includes %v", unreadable)
	}
}

func TestViews(t *testing.T) {
	fs := fakeFS{"/etc/bind/named.conf": fixture(t, "views-named.conf")}
	tests := []struct {
		view      string
		wantView  string
		zones     []string
		checks    []string
		otherView map[string][]string
		wantErr   string
	}{
		{view: "", wantView: "external", zones: []string{"only-external.example.com"}, checks: []string{"fail"},
			otherView: map[string][]string{"example.com": {"internal", "public"}, "intranet.example.com": {"internal"}, "both.example.net": {"internal", "public"}}},
		{view: "public", wantView: "public", zones: []string{"example.com", "both.example.net"}, checks: []string{"ignore", "warn"},
			otherView: map[string][]string{"intranet.example.com": {"internal"}, "only-external.example.com": {"external"}}},
		{view: "internal", wantView: "internal", zones: []string{"example.com", "intranet.example.com", "both.example.net"}, checks: []string{"fail", "fail", "fail"},
			otherView: map[string][]string{"only-external.example.com": {"external"}}},
		{view: "missing", wantErr: "not found"},
	}
	for _, tt := range tests {
		t.Run("view="+tt.view, func(t *testing.T) {
			c, err := Read(fs.loader(""), "/etc/bind/named.conf", tt.view)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.View != tt.wantView {
				t.Fatalf("view %q", c.View)
			}
			if got := zoneNames(c); !reflect.DeepEqual(got, tt.zones) {
				t.Fatalf("zones %v", got)
			}
			for i, z := range c.Zones {
				if z.CheckNames != tt.checks[i] {
					t.Errorf("%s check-names %s, want %s", z.Name, z.CheckNames, tt.checks[i])
				}
			}
			if !reflect.DeepEqual(c.OtherViews, tt.otherView) {
				t.Errorf("other views %v\nwant %v", c.OtherViews, tt.otherView)
			}
			if !strings.HasPrefix(c.Zones[0].File, "/etc/bind/") {
				t.Errorf("relative file not resolved: %s", c.Zones[0].File)
			}
		})
	}
}

func TestViewRuleOrder(t *testing.T) {
	cfg := func(s string) fakeFS { return fakeFS{"/etc/named.conf": &s} }
	tests := []struct {
		name, conf, want, wantErr string
	}{
		{"_default first", `view "external" { zone "a.example.com" { type master; file "a"; }; }; view "_default" { zone "b.example.com" { type master; file "b"; }; };`, "_default", ""},
		{"first matching any", `view "lan" { match-clients { 192.0.2.0/24; }; }; view "wan" { match-clients { any; }; }; view "wan2" { };`, "wan", ""},
		{"no match-clients means any", `view "lan" { match-clients { 192.0.2.0/24; }; }; view "all" { };`, "all", ""},
		{"none matches", `view "lan" { match-clients { 192.0.2.0/24; }; };`, "", "set VIEW"},
		{"VIEW without views", `zone "a.example.com" { type master; file "a"; };`, "", "no views"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := ""
			if tt.name == "VIEW without views" {
				view = "external"
			}
			c, err := Read(cfg(tt.conf).loader(""), "/etc/named.conf", view)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.View != tt.want {
				t.Fatalf("view %q, want %q", c.View, tt.want)
			}
		})
	}
}

func TestCheckconfOutput(t *testing.T) {
	fs := fakeFS{"/etc/named.conf": fixture(t, "checkconf-p.conf")}
	c, err := Read(fs.loader(""), "/etc/named.conf", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := zoneNames(c); !reflect.DeepEqual(got, []string{"example.com", "example.net"}) {
		t.Fatalf("zones %v", got)
	}
	if c.Zones[0].CheckNames != "warn" || c.Zones[1].CheckNames != "fail" {
		t.Fatalf("check-names %+v", c.Zones)
	}
}

func TestChroot(t *testing.T) {
	s := `include "/etc/zones.conf"; options { directory "/var/named"; };`
	z := `zone "example.com" { type master; file "example.com.db"; }; zone "example.net" { type master; file "/abs/example.net.db"; };`
	fs := fakeFS{"/var/named/run-root/etc/named.conf": &s, "/var/named/run-root/etc/zones.conf": &z}
	c, err := Read(fs.loader("/var/named/run-root"), "/var/named/run-root/etc/named.conf", "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Directory != "/var/named/run-root/var/named" {
		t.Fatalf("directory %s", c.Directory)
	}
	if c.Zones[0].File != "/var/named/run-root/var/named/example.com.db" || c.Zones[1].File != "/var/named/run-root/abs/example.net.db" {
		t.Fatalf("files %+v", c.Zones)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, conf, want string }{
		{"unterminated block", `options { directory "/x";`, "missing '}'"},
		{"stray close", `};`, "unexpected '}'"},
		{"unterminated string", `options { directory "/x; };`, "unterminated string"},
		{"unterminated comment", `/* never closed`, "unterminated /*"},
		{"include loop", `include "/etc/named.conf";`, "include loop"},
		{"include args", `include;`, "one file name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.conf
			fs := fakeFS{"/etc/named.conf": &s}
			_, err := Read(fs.loader(""), "/etc/named.conf", "")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
		})
	}
	// Missing main file is an error, not a skipped include.
	_, err := Read(fakeFS{}.loader(""), "/etc/named.conf", "")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestToleratesMissingSemicolons(t *testing.T) {
	s := "zone \"example.com\" { type master; file \"a.db\" }\nzone \"example.net\" { type master; file \"b.db\"; }"
	fs := fakeFS{"/etc/named.conf": &s}
	c, err := Read(fs.loader(""), "/etc/named.conf", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := zoneNames(c); !reflect.DeepEqual(got, []string{"example.com", "example.net"}) {
		t.Fatalf("zones %v", got)
	}
}

// Every key-directory, whichever view is read, relative to named's
// directory and inside the chroot.
func TestKeyDirectories(t *testing.T) {
	s := `options { directory "/var/named"; key-directory "keys"; };
view "internal" { match-clients { 10.0.0.0/8; }; key-directory "/etc/keys/internal";
  zone "a.example" { type master; file "a.db"; key-directory "/etc/keys/a"; }; };
view "external" { zone "b.example" { type master; file "b.db"; key-directory "keys/"; }; };`
	fs := fakeFS{"/var/named/run-root/etc/named.conf": &s}
	c, err := Read(fs.loader("/var/named/run-root"), "/var/named/run-root/etc/named.conf", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/var/named/run-root/etc/keys/a", "/var/named/run-root/etc/keys/internal", "/var/named/run-root/var/named/keys"}
	if !reflect.DeepEqual(c.KeyDirs, want) {
		t.Fatalf("key dirs %v, want %v", c.KeyDirs, want)
	}
	none := `options { directory "/var/named"; };`
	fs = fakeFS{"/etc/named.conf": &none}
	if c, _ := Read(fs.loader(""), "/etc/named.conf", ""); len(c.KeyDirs) != 0 {
		t.Fatalf("default key directory listed: %v", c.KeyDirs)
	}
}
