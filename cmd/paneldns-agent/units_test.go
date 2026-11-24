package main

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

// deniedNets must be what the packaged unit denies, or enrol would leave a
// needed resolver blocked (or allow one the unit never denied).
func TestDeniedNetsMatchUnit(t *testing.T) {
	got := unitSettings(t, "paneldns-agent.service")["IPAddressDeny"]
	if len(got) != 1 {
		t.Fatalf("IPAddressDeny %q", got)
	}
	keywords := map[string][]string{
		"localhost":  {"127.0.0.0/8", "::1/128"},
		"link-local": {"169.254.0.0/16", "fe80::/64"},
		"multicast":  {"224.0.0.0/4", "ff00::/8"},
	}
	var unit []string
	for _, f := range strings.Fields(got[0]) {
		if k, ok := keywords[f]; ok {
			unit = append(unit, k...)
		} else {
			unit = append(unit, f)
		}
	}
	var code []string
	for _, p := range deniedNets {
		code = append(code, p.String())
	}
	slices.Sort(unit)
	slices.Sort(code)
	if !reflect.DeepEqual(unit, code) {
		t.Fatalf("unit denies %v, code allows back from %v", unit, code)
	}
}

func TestNetworkAllow(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "resolv.conf"), []byte(`# resolvers
nameserver 127.0.0.53
nameserver 10.0.0.2
nameserver 169.254.169.253
nameserver 100.100.2.136
nameserver 8.8.8.8
nameserver fe80::1%eth0
nameserver 2001:db8::53
nameserver 127.0.0.53
search example.com
`), 0o644)
	enrol.Root = filepath.ToSlash(dir)
	defer func() { enrol.Root = "" }()
	oldL := lookupHost
	defer func() { lookupHost = oldL }()
	var asked []string
	lookupHost = func(h string) ([]netip.Addr, error) {
		asked = append(asked, h)
		return []netip.Addr{netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("203.0.113.9")}, nil
	}
	cfg := config.Defaults()
	cfg.URL = "https://paneldns.lan.example"
	cfg.ZoneSource = config.SourcePowerDNSAPI
	cfg.PDNSAPIURL = "http://[::1]:8081"
	got := networkAllow(cfg)
	want := []string{"::1", "127.0.0.53", "10.0.0.2", "169.254.169.253", "100.100.2.136", "fe80::1", "192.168.1.5"}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(asked, []string{"paneldns.lan.example"}) {
		t.Fatalf("allow %v (asked %v), want %v", got, asked, want)
	}
	// A public resolver and a public PanelDNS need no drop-in.
	os.WriteFile(filepath.Join(dir, "etc", "resolv.conf"), []byte("nameserver 9.9.9.9\n"), 0o644)
	lookupHost = func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil }
	cfg.ZoneSource = config.SourceBIND
	if got := networkAllow(cfg); len(got) != 0 {
		t.Fatalf("allow %v", got)
	}
}

func TestAgentDropIns(t *testing.T) {
	withUnits(t)
	var out bytes.Buffer
	want := agentDropIns([]string{"127.0.0.53", "10.0.0.2"}, true)
	if changed, err := syncAgentUnits(want, &out); err != nil || !changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	b, _ := os.ReadFile(agentNetDropIn)
	if !strings.Contains(string(b), "[Service]\nIPAddressAllow=127.0.0.53 10.0.0.2\n") {
		t.Fatalf("network drop-in %q", b)
	}
	b, _ = os.ReadFile(agentHomeDropIn)
	if !strings.Contains(string(b), "[Service]\nProtectHome=read-only\n") {
		t.Fatalf("home drop-in %q", b)
	}
	if s := staleDropIns(want); len(s) != 0 {
		t.Fatalf("stale right after writing: %v", s)
	}
	if changed, _ := syncAgentUnits(want, &out); changed {
		t.Fatal("rewrote unchanged drop-ins")
	}
	// Nothing needed: both go.
	none := agentDropIns(nil, false)
	if s := staleDropIns(none); len(s) != 2 {
		t.Fatalf("stale %v", s)
	}
	if _, err := syncAgentUnits(none, &out); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{agentNetDropIn, agentHomeDropIn} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", p, err)
		}
	}
}

func TestUpdateUnitsCommand(t *testing.T) {
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return 1000 }
	var out, errb bytes.Buffer
	if code := realMain([]string{"update-units"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("non-root: code %d %q", code, errb.String())
	}
	geteuid = func() int { return 0 }
	// The package's upgrade step on a server that was never enrolled.
	if code := realMain([]string{"update-units", "--if-enrolled", "--state-dir", t.TempDir(), "--config", filepath.Join(t.TempDir(), "none.conf")}, &out, &errb); code != 0 {
		t.Fatalf("not enrolled: code %d %q", code, errb.String())
	}
}

// A HestiaCP-style plan (zones under /home) gets the home drop-in; the
// watcher's drop-in follows the same rule.
func TestPlanHome(t *testing.T) {
	if planHome(&enrol.ACLPlan{Read: []string{"/var/named/a.db"}, Dirs: []string{"/var/named"}}) {
		t.Error("no home path")
	}
	if !planHome(&enrol.ACLPlan{Read: []string{"/home/admin/conf/dns/a.db"}, Dirs: []string{"/home/admin/conf/dns"}}) {
		t.Error("HestiaCP zones")
	}
	if planHome(nil) {
		t.Error("nil plan")
	}
}

// The package's upgrade step resolves no names (spec 7.1) and never takes
// an allowance away.
func TestNetworkAllowOffline(t *testing.T) {
	withUnits(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "resolv.conf"), []byte("nameserver 10.0.20.253\n"), 0o644)
	enrol.Root = filepath.ToSlash(dir)
	defer func() { enrol.Root = "" }()
	os.MkdirAll(filepath.Dir(agentNetDropIn), 0o755)
	os.WriteFile(agentNetDropIn, []byte("[Service]\nIPAddressAllow=127.0.0.53 192.168.1.5 203.0.113.9\n"), 0o644)
	keepAllowed = true
	defer func() { keepAllowed = false }()
	cfg := config.Defaults()
	cfg.URL = "https://paneldns.lan.example"
	lookupHost = func(string) ([]netip.Addr, error) { return nil, errors.New("offline") }
	got := networkAllow(cfg)
	if want := []string{"10.0.20.253", "127.0.0.53", "192.168.1.5"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("allow %v, want %v", got, want)
	}
}
