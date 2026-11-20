package host

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFilterPublic(t *testing.T) {
	var addrs []net.Addr
	for _, s := range []string{"192.0.2.10/24", "10.0.0.5/8", "127.0.0.1/8", "169.254.1.1/16", "2001:db8::10/64", "fe80::1/64", "fd00::1/8", "::1/128", "192.0.2.10/24"} {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		addrs = append(addrs, n)
	}
	addrs = append(addrs, &net.IPAddr{IP: net.ParseIP("192.0.2.11")})
	got := filterPublic(addrs)
	want := []string{"192.0.2.10", "192.0.2.11", "2001:db8::10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPanelAndOS(t *testing.T) {
	dir := t.TempDir()
	Root = dir
	defer func() { Root = "" }()
	if Panel() != PanelNone {
		t.Fatal("panel detected in empty root")
	}
	os.MkdirAll(filepath.Join(dir, "usr", "local", "directadmin"), 0o755)
	if Panel() != PanelDirectAdmin {
		t.Fatalf("panel %s", Panel())
	}
	os.MkdirAll(filepath.Join(dir, "usr", "local", "cpanel"), 0o755)
	if Panel() != PanelCPanel {
		t.Fatalf("panel %s", Panel())
	}
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("NAME=\"Test\"\nPRETTY_NAME=\"Test Linux 9\"\n"), 0o644)
	if OS() != "Test Linux 9" {
		t.Fatalf("os %q", OS())
	}
}
