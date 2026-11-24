package enrol

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
)

func TestPlanWatch(t *testing.T) {
	tests := []struct {
		name     string
		plan     ACLPlan
		watch    []string
		writable []string
		home     bool
		rejected []string
	}{
		{name: "cPanel DNSOnly",
			plan: ACLPlan{
				Read:    []string{"/etc/named.conf", "/etc/userdomains", "/var/named/example.com.db", "/var/named/example.net.db"},
				Dirs:    []string{"/var/named"},
				Skipped: []string{"/etc/rndc.key"},
			},
			watch:    []string{"/etc", "/var/named"},
			writable: []string{"/etc/named.conf", "/etc/userdomains", "/var/named"}},
		{name: "DirectAdmin with subdirectories and a traversed owner directory",
			plan: ACLPlan{
				Read: []string{"/etc/named.conf", "/etc/named.zones.conf", "/etc/virtual/domainowners",
					"/var/named/example.com.db", "/var/named/hosted/example.net.db", "/var/named/z/zones.example.com.db"},
				Dirs:     []string{"/var/named", "/var/named/hosted", "/var/named/z"},
				Traverse: []string{"/etc/virtual"},
			},
			watch:    []string{"/etc", "/etc/virtual", "/var/named", "/var/named/hosted", "/var/named/z"},
			writable: []string{"/etc/named.conf", "/etc/named.zones.conf", "/etc/virtual", "/var/named", "/var/named/hosted", "/var/named/z"}},
		{name: "HestiaCP zones under /home",
			plan: ACLPlan{
				Read:     []string{"/etc/bind/named.conf", "/home/alice/conf/dns/example.com.db", "/home/bob/conf/dns/example.org.db"},
				Dirs:     []string{"/home/alice/conf/dns", "/home/bob/conf/dns"},
				Traverse: []string{"/home/alice", "/home/bob"},
			},
			watch:    []string{"/etc/bind", "/home/alice/conf/dns", "/home/bob/conf/dns"},
			writable: []string{"/etc/bind/named.conf", "/home/alice", "/home/alice/conf/dns", "/home/bob", "/home/bob/conf/dns"},
			home:     true},
		{name: "paths a unit file can't hold are left out",
			plan: ACLPlan{
				Read: []string{"/etc/named.conf", "/var/named/my zones/a.db", "/var/named/100%/b.db"},
				Dirs: []string{"/var/named/my zones", "/var/named/100%"},
			},
			watch:    []string{"/etc"},
			writable: []string{"/etc/named.conf"},
			rejected: []string{"/var/named/100%", "/var/named/100%/b.db", "/var/named/my zones", "/var/named/my zones/a.db"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := PlanWatch(&tt.plan)
			if !reflect.DeepEqual(w.Watch, tt.watch) || !reflect.DeepEqual(w.Writable, tt.writable) ||
				w.ProtectHomeReadOnly != tt.home || !reflect.DeepEqual(w.Rejected, emptyNil(tt.rejected)) {
				t.Fatalf("watch %q\nwritable %q\nhome %v\nrejected %q", w.Watch, w.Writable, w.ProtectHomeReadOnly, w.Rejected)
			}
			for _, k := range tt.plan.Skipped {
				if strings.Contains(w.PathDropIn()+w.ServiceDropIn(), k) {
					t.Fatalf("drop-ins name the key file %s", k)
				}
			}
		})
	}
}

func emptyNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestWatchDropIns(t *testing.T) {
	w := WatchList{
		Watch:               []string{"/etc", "/home/alice/conf/dns", "/var/named"},
		Writable:            []string{"/etc/named.conf", "/home/alice/conf/dns", "/var/named"},
		ProtectHomeReadOnly: true,
	}
	path := w.PathDropIn()
	if !strings.HasSuffix(path, "[Path]\nPathChanged=/etc\nPathChanged=/home/alice/conf/dns\nPathChanged=/var/named\n") {
		t.Fatalf("path drop-in:\n%s", path)
	}
	svc := w.ServiceDropIn()
	if !strings.HasSuffix(svc, "[Service]\nReadWritePaths=-/etc/named.conf\nReadWritePaths=-/home/alice/conf/dns\nReadWritePaths=-/var/named\n"+
		"# Zone files under a home directory: read-only, not hidden.\nProtectHome=read-only\n") {
		t.Fatalf("service drop-in:\n%s", svc)
	}
	for _, text := range []string{path, svc} {
		for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
			if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "[") && !strings.Contains(line, "=") {
				t.Fatalf("bad unit line %q", line)
			}
		}
	}
	w.ProtectHomeReadOnly = false
	if strings.Contains(w.ServiceDropIn(), "ProtectHome") {
		t.Fatal("ProtectHome set without home paths")
	}
}

// TestPlanThenFix runs the real planner on a cPanel-like tree and checks
// what fix-acls would do after cPanel added a zone with mode 0600. The zone
// directory also holds a DNSSEC private key, so it gets no default ACL and
// the one an older version set is removed (review A-7).
func TestPlanThenFix(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/named.conf": `include "/etc/rndc.key";
options { directory "/var/named"; };
zone "example.com" { type master; file "/var/named/example.com.db"; };
zone "new.example.com" { type master; file "/var/named/new.example.com.db"; };`,
		"/etc/rndc.key":                          `key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };`,
		"/var/named/example.com.db":              "",
		"/var/named/new.example.com.db":          "",
		"/var/named/Kexample.com.+013+1.private": "Private-key-format: v1.3\n",
	})
	cfg := config.Defaults()
	cfg.ZonesFile = "/etc/named.conf"
	plan, err := PlanACLs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fine := &ACL{UserObj: 6, GroupObj: 4, Mask: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4}}
	dirOK := &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 5}}
	defOK := &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 4}}
	read := func(p string) (*ACL, *ACL, error) {
		switch strings.TrimPrefix(p, Root) {
		case "/var/named":
			return dirOK, defOK, nil
		case "/var/named/new.example.com.db":
			// Created by cPanel with mode 0600: the inherited entry is masked.
			return &ACL{UserObj: 6, GroupObj: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 4}}, nil, nil
		case "/etc/rndc.key", "/var/named/Kexample.com.+013+1.private":
			return nil, nil, nil
		}
		return fine, nil, nil
	}
	if !reflect.DeepEqual(plan.NoDefault, []string{"/var/named"}) {
		t.Fatalf("no-default dirs %v", plan.NoDefault)
	}
	cmds, res := FixCommands(plan, FixOptions{UID: agentUID, Read: read})
	if len(cmds) != 2 || res.Fine != 4 {
		t.Fatalf("commands %q, fine %d", cmds, res.Fine)
	}
	c := cmds["/var/named/new.example.com.db"]
	if len(c) != 1 || strings.Join(c[0][:3], " ") != "setfacl -m u:990:r--,g::---,m::r--" || c[0][3] != Root+"/var/named/new.example.com.db" {
		t.Fatalf("command %q", c)
	}
	if c := cmds["/var/named"]; len(c) != 1 || strings.Join(c[0][:5], " ") != "setfacl -n -d -x u:990" {
		t.Fatalf("zone directory command %q", c)
	}
	w := PlanWatch(plan)
	if !reflect.DeepEqual(w.Watch, []string{"/etc", "/var/named"}) || !reflect.DeepEqual(w.Writable, []string{"/etc/named.conf", "/var/named"}) {
		t.Fatalf("watch %v writable %v", w.Watch, w.Writable)
	}
}

// /var/named linked into /home (a big /home partition): a unit with
// ProtectHome=yes couldn't follow the link, so it counts as under /home.
func TestUnderHomeFollowsLinks(t *testing.T) {
	withRoot(t, map[string]string{"/home/named/a.db": "", "/var/x/b.db": ""})
	if err := os.Symlink(filepath.Join(Root, "home", "named"), filepath.Join(Root, "var", "named")); err != nil {
		t.Skip("symbolic links not available:", err)
	}
	if UnderHome([]string{"/var/x/b.db", "/etc/named.conf"}) {
		t.Error("no home path")
	}
	if !UnderHome([]string{"/var/named/a.db"}) || !UnderHome([]string{"/root"}) {
		t.Error("home path missed")
	}
}
