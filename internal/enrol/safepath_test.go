package enrol

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
)

type fakeNode struct {
	mode   fs.FileMode
	uid    uint32
	target string // symbolic links
}

// fakeLinks replaces lstatOwner and readlink: paths in nodes (host paths)
// get the given mode, owner and link target; every other path is looked up
// under Root and owned by root.
func fakeLinks(t *testing.T, nodes map[string]fakeNode) {
	t.Helper()
	oldL, oldR := lstatOwner, readlink
	host := func(p string) string { return strings.TrimPrefix(filepath.ToSlash(p), Root) }
	lstatOwner = func(p string) (fs.FileMode, uint32, error) {
		if n, ok := nodes[host(p)]; ok {
			return n.mode, n.uid, nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return 0, 0, err
		}
		return fi.Mode(), 0, nil
	}
	readlink = func(p string) (string, error) {
		if n, ok := nodes[host(p)]; ok && n.mode&fs.ModeSymlink != 0 {
			return n.target, nil
		}
		return "", fs.ErrInvalid
	}
	t.Cleanup(func() { lstatOwner, readlink = oldL, oldR })
}

func TestTrustedPath(t *testing.T) {
	withRoot(t, map[string]string{"/var/named/example.com.db": "", "/etc/shadow": ""})
	link := fs.ModeSymlink | 0o777
	fakeLinks(t, map[string]fakeNode{
		"/":                       {mode: fs.ModeDir | 0o755},
		"/etc":                    {mode: fs.ModeDir | 0o755},
		"/etc/named.conf":         {mode: link, target: "/var/named/run-root/etc/named.conf"},
		"/var/named":              {mode: fs.ModeDir | 0o770, uid: 25},
		"/var/named/evil.db":      {mode: link, uid: 25, target: "/etc/shadow"},
		"/var/named/rootlink.db":  {mode: link, target: "example.com.db"},
		"/home":                   {mode: fs.ModeDir | 0o755},
		"/home/u":                 {mode: fs.ModeDir | 0o711, uid: 1001},
		"/home/u/conf":            {mode: link, uid: 1001, target: "/etc"},
		"/srv":                    {mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"/srv/z.db":               {mode: link, target: "/var/named/example.com.db"},
		"/etc/zones":              {mode: link, target: "/etc/zones"},
		"/etc/key.conf":           {mode: link, target: "/etc/rndc.key"},
		"/var/named/relative.db":  {mode: link, uid: 0, target: "../../etc/shadow"},
		"/etc/named.conf.d":       {mode: fs.ModeDir | 0o755},
		"/etc/named.conf.d/x.inc": {mode: link, target: "../named.conf"},
	})
	tests := []struct {
		path, want string
		err        string
	}{
		// A link root made in /etc (Plesk's /etc/named.conf) is followed.
		{path: "/etc/named.conf", want: "/var/named/run-root/etc/named.conf"},
		// A link in a directory named can write is not, even if root owns it.
		{path: "/var/named/evil.db", err: "symbolic link"},
		{path: "/var/named/rootlink.db", err: "symbolic link"},
		{path: "/var/named/relative.db", err: "symbolic link"},
		// A home directory component replaced by a link.
		{path: "/home/u/conf/dns/example.com.db", err: "symbolic link"},
		// A root-owned link in a sticky directory is followed.
		{path: "/srv/z.db", want: "/var/named/example.com.db"},
		{path: "/etc/zones/a.db", err: "too many"},
		{path: "/etc/key.conf", err: "key material"},
		// Links resolve through other trusted links.
		{path: "/etc/named.conf.d/x.inc", want: "/var/named/run-root/etc/named.conf"},
		// No links at all.
		{path: "/var/named/example.com.db", want: "/var/named/example.com.db"},
		{path: "/var/named/missing.db", want: "/var/named/missing.db"},
	}
	for _, tt := range tests {
		got, err := trustedPath(tt.path)
		if tt.err != "" {
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("%s: got %q, %v; want error %q", tt.path, got, err, tt.err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q, %v; want %q", tt.path, got, err, tt.want)
		}
	}
	if _, err := trustedPath("/home/u/conf/dns/x.db"); !errors.Is(err, ErrUntrustedSymlink) {
		t.Errorf("want ErrUntrustedSymlink, got %v", err)
	}
}

// A hosting user who owns /home/u replaces /home/u/conf with a link: enrol
// (root) must not grant the agent read access through it, while the other
// zones keep their ACLs.
func TestPlanACLsSkipsUntrustedSymlinks(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/named.conf": `options { directory "/var/named"; };
zone "example.com" { type master; file "/home/u/conf/dns/example.com.db"; };
zone "example.net" { type master; file "/var/named/example.net.db"; };`,
		"/home/u/conf/dns/example.com.db": "",
		"/var/named/example.net.db":       "",
	})
	fakeLinks(t, map[string]fakeNode{
		"/home":        {mode: fs.ModeDir | 0o755},
		"/home/u":      {mode: fs.ModeDir | 0o711, uid: 1001},
		"/home/u/conf": {mode: fs.ModeSymlink | 0o777, uid: 1001, target: "/etc"},
	})
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	p, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]string{p.Read, p.Dirs, p.Traverse} {
		for _, f := range list {
			if strings.HasPrefix(f, "/home/u/conf") {
				t.Errorf("plan grants %s through a user's symbolic link", f)
			}
		}
	}
	if !slices.Contains(p.Read, "/var/named/example.net.db") || !slices.Contains(p.Dirs, "/var/named") {
		t.Errorf("the other zone lost its ACLs: read %v dirs %v", p.Read, p.Dirs)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "symbolic link") {
		t.Errorf("no warning: %q", p.Warnings)
	}
}
