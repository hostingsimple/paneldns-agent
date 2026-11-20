package enrol

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
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

func TestPlanACLsInlineKeyWarns(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/named.conf": `key "rndc-key" { secret "c2VjcmV0"; }; options { directory "/var/named"; };`,
	})
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "key statement") {
		t.Fatalf("warnings %v", p.Warnings)
	}
}
