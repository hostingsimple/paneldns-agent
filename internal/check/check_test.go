package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/namedconf"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

type fakeSrc struct {
	zones map[string]string
	other map[string][]string
}

func (f *fakeSrc) Kind() string { return "bind" }
func (f *fakeSrc) List(ctx context.Context) (*source.Listing, error) {
	l := &source.Listing{Backend: "bind", View: "external", Other: f.other, Skipped: 1}
	for _, n := range []string{"example.com", "example.net", "localhost", "broken.example.com"} {
		if _, ok := f.zones[n]; ok {
			l.Zones = append(l.Zones, source.ZoneRef{Name: n, Fingerprint: "x"})
		}
	}
	return l, nil
}
func (f *fakeSrc) Read(ctx context.Context, z source.ZoneRef) ([]zonefile.RR, error) {
	return zonefile.Parse([]byte(f.zones[z.Name]), zonefile.Options{Origin: z.Name})
}
func (f *fakeSrc) Running(ctx context.Context) (source.Running, string) {
	return source.RunningYes, "pid 1"
}

const zone = "$TTL 300\n@ IN SOA ns1.example.net. h.example.net. 5 1 1 1 1\n@ IN A 192.0.2.1\n@ IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.com. AA==\n"

func baseEnv(t *testing.T) Env {
	cfg := config.Defaults()
	cfg.URL = "https://app.example.com"
	dir := t.TempDir()
	ownersPath := filepath.Join(dir, "domainowners")
	os.WriteFile(ownersPath, []byte("example.com: exampleuser\n"), 0o644)
	st := state.New()
	st.Zones["example.net"] = &state.Zone{Status: protocol.StatusRefused, Reason: "public_suffix: refused"}
	st.Zones["broken.example.com"] = &state.Zone{Error: "named-compilezone failed: bad owner"}
	st.ScanCompletedAt = 1795000000
	return Env{
		ConfigPath: "/etc/paneldns-agent.conf", StateDir: "/var/lib/paneldns-agent",
		Config:   &cfg,
		Identity: &state.Identity{SourceID: "17", KeyID: "4"},
		State:    st,
		Source:   &fakeSrc{zones: map[string]string{"example.com": zone, "example.net": zone, "localhost": zone}, other: map[string][]string{"intranet.example.com": {"internal"}}},
		Owners:   &owners.File{Path: ownersPath},
		Heartbeat: func(ctx context.Context, r *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
			if !r.Check {
				t.Error("check heartbeat without check=true")
			}
			return &protocol.HeartbeatResponse{ClusterName: "Brand A", SourceName: "web1", LatestVersion: "0.1.0"}, nil
		},
		ServerDate: func() (time.Time, time.Time) {
			n := time.Unix(1795000000, 0)
			return n, n.Add(30 * time.Second)
		},
		Lookup: func(ctx context.Context, host string) error { return nil },
		Stat: func(p string) (FileMode, error) {
			if strings.HasSuffix(p, ".conf") {
				return FileMode{Mode: 0o640, User: "root", Group: "paneldns-agent"}, nil
			}
			return FileMode{Mode: 0o600, User: "paneldns-agent", Group: "paneldns-agent"}, nil
		},
	}
}

func messages(r *Result, st Status) string {
	var s []string
	for _, i := range r.Items {
		if i.Status == st {
			s = append(s, i.Message)
		}
	}
	return strings.Join(s, "\n")
}

func TestCheckHealthy(t *testing.T) {
	env := baseEnv(t)
	r := Run(context.Background(), env)
	fails := messages(r, Fail)
	// The only failure is the zone the service could not read.
	if !strings.Contains(fails, "1 zones failed to read") || strings.Count(fails, "\n") != 0 {
		t.Fatalf("failures:\n%s", fails)
	}
	var out bytes.Buffer
	r.WriteText(&out)
	text := out.String()
	for _, want := range []string{
		"view in use: external",
		"intranet.example.com (in view internal, not synced)",
		"system zones skipped",
		"signed at the source",
		"1 of 2 zones have an owner",
		"zones refused by PanelDNS: example.net: public_suffix",
		`setup "Brand A", server "web1"`,
		"clock skew 30s",
		"key accepted, epoch current, IP allowlist passed",
		"/etc/paneldns-agent.conf mode 0640",
		"Result: FAILED",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil || len(decoded.Items) != len(r.Items) {
		t.Fatalf("json round trip: %v", err)
	}
}

func TestCheckFailures(t *testing.T) {
	tests := []struct {
		name   string
		modify func(e *Env)
		want   string
	}{
		{"not enrolled", func(e *Env) { e.IdentErr = errors.New("this server is not enrolled") }, "not enrolled"},
		{"bad key", func(e *Env) { e.KeyErr = state.ErrKeyMode }, "key file must have mode 0600"},
		{"config mode", func(e *Env) {
			e.Stat = func(p string) (FileMode, error) { return FileMode{Mode: 0o644, User: "root", Group: "root"}, nil }
		}, "must be 0640 root:paneldns-agent"},
		{"ip refused", func(e *Env) {
			e.Heartbeat = func(context.Context, *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
				return nil, &protocol.APIError{Status: 403, Code: protocol.ErrIPRefused, IP: "192.0.2.77", Path: protocol.PathHeartbeat}
			}
		}, "came from 192.0.2.77"},
		{"unreachable", func(e *Env) {
			e.Heartbeat = func(context.Context, *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
				return nil, &protocol.APIError{Path: protocol.PathHeartbeat, Err: errors.New("connection refused")}
			}
		}, "not reachable over HTTPS"},
		{"dns", func(e *Env) { e.Lookup = func(context.Context, string) error { return errors.New("no such host") } }, "IPAddressAllow"},
		{"clock", func(e *Env) {
			e.ServerDate = func() (time.Time, time.Time) { n := time.Unix(1795000000, 0); return n, n.Add(-5 * time.Minute) }
		}, "clock skew 5m0s"},
		{"below minimum", func(e *Env) {
			e.Heartbeat = func(context.Context, *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
				return &protocol.HeartbeatResponse{MinimumVersion: "9.0.0", MinimumGraceUntil: 1796000000}, nil
			}
		}, "update required by 2026-11-30"},
		{"owner file missing", func(e *Env) { e.Owners = &owners.File{Path: "/nonexistent/domainowners"} }, "owner file"},
		{"acl reset", func(e *Env) {
			e.OpenCheck = func(string) error { return fs.ErrPermission }
			e.Source = &source.BIND{ConfFile: "/x"} // listing fails: no such file
		}, "listing zones"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := baseEnv(t)
			env.State.Zones = map[string]*state.Zone{}
			tt.modify(&env)
			r := Run(context.Background(), env)
			if !r.Failed() || !strings.Contains(messages(r, Fail), tt.want) {
				t.Fatalf("want a failure containing %q, got:\n%s", tt.want, messages(r, Fail))
			}
		})
	}
	r := Run(context.Background(), Env{ConfigPath: "/x.conf", ConfigErr: errors.New("PANELDNS_URL: not set")})
	if !r.Failed() || !strings.Contains(messages(r, Fail), "PANELDNS_URL") {
		t.Fatal("config error not reported")
	}
}

func TestCheckZone(t *testing.T) {
	env := baseEnv(t)
	env.Zone = "Example.COM."
	r := Run(context.Background(), env)
	if r.Failed() || r.Zone == nil {
		t.Fatalf("zone dump failed: %+v", r.Items)
	}
	if !strings.HasPrefix(r.Zone.Text, "$ORIGIN example.com.\n") || !r.Zone.SignedAtSource || r.Zone.Stripped != 1 || r.Zone.Serial != 5 || !strings.HasPrefix(r.Zone.Hash, "sha256:") {
		t.Fatalf("dump %+v", r.Zone)
	}
	env.Zone = "intranet.example.com"
	if r := Run(context.Background(), env); !strings.Contains(messages(r, Fail), "only in view internal") {
		t.Fatal("other-view zone not explained")
	}
	env.Zone = "missing.example.com"
	if r := Run(context.Background(), env); !strings.Contains(messages(r, Fail), "not a primary zone") {
		t.Fatal("missing zone not reported")
	}
}

type inlineKeySrc struct{ *fakeSrc }

func (s inlineKeySrc) List(ctx context.Context) (*source.Listing, error) {
	l, err := s.fakeSrc.List(ctx)
	if err == nil {
		l.InlineKey = namedconf.InlineKeyError([]namedconf.KeyRef{{File: "/etc/named.conf", Line: 12, Name: "rndc-key"}})
	}
	return l, err
}

func TestCheckRefusesInlineKey(t *testing.T) {
	env := baseEnv(t)
	env.State.Zones = map[string]*state.Zone{}
	env.Source = inlineKeySrc{env.Source.(*fakeSrc)}
	r := Run(context.Background(), env)
	if !r.Failed() || !strings.Contains(messages(r, Fail), `/etc/named.conf:12 (key "rndc-key")`) || !strings.Contains(messages(r, Fail), "separate file") {
		t.Fatalf("inline key not refused:\n%s", messages(r, Fail))
	}
}

func TestCheckACLWatcher(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	os.MkdirAll(dir+"/hosted", 0o755)
	os.WriteFile(dir+"/named.conf", []byte(`options { directory "`+dir+`"; };
zone "example.com" { type master; file "example.com.db"; };
zone "example.net" { type master; file "`+dir+`/hosted/example.net.db"; };`), 0o644)
	os.WriteFile(dir+"/example.com.db", []byte(zone), 0o644)
	os.WriteFile(dir+"/hosted/example.net.db", []byte(zone), 0o644)
	dropIn := dir + "/watch.conf"
	tests := []struct {
		name            string
		active, enabled string
		err             error
		watched         string // drop-in contents ("" = missing)
		status          Status
		want            string
	}{
		{"active and watching all", "active", "enabled", nil, "[Path]\nPathChanged=" + dir + "\nPathChanged=" + dir + "/hosted\n", OK, "ACL watcher paneldns-agent-acl.path: active, enabled"},
		{"inactive", "inactive", "disabled", errors.New("exit status 3"), "", Warn, "inactive, disabled; zone files the panel creates may stay unreadable"},
		{"not installed", "inactive", "Failed to get unit file state for paneldns-agent-acl.path: No such file or directory", errors.New("exit 1"), "", Warn, "inactive, not installed"},
		{"failed (trigger limit)", "failed", "enabled", errors.New("exit status 3"), "", Warn, "systemctl enable --now paneldns-agent-acl.path"},
		{"a zone directory not watched", "active", "enabled", nil, "[Path]\nPathChanged=" + dir + "\n", Warn, "zone directories the ACL watcher doesn't watch: " + dir + "/hosted; as root run: paneldns-agent fix-acls"},
		{"no systemd", "", "", errors.New(`exec: "systemctl": executable file not found`), "", Info, "can't ask systemd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tt.watched != "" {
				t.Skip("named.conf paths with a drive letter don't resolve like Unix paths")
			}
			env := baseEnv(t)
			env.Source = &source.BIND{ConfFile: dir + "/named.conf"}
			env.Systemctl = func(args ...string) (string, error) {
				if args[1] != ACLPathUnit {
					t.Errorf("asked about %v", args)
				}
				if args[0] == "is-active" {
					return tt.active, tt.err
				}
				return tt.enabled, tt.err
			}
			os.Remove(dropIn)
			if tt.watched != "" {
				os.WriteFile(dropIn, []byte(tt.watched), 0o644)
			}
			env.WatchDropIn, env.ReadFile = dropIn, os.ReadFile
			r := Run(context.Background(), env)
			if got := messages(r, tt.status); !strings.Contains(got, tt.want) {
				t.Fatalf("%s messages lack %q:\n%s", tt.status, tt.want, got)
			}
			for _, i := range r.Items {
				if i.Status == Fail && strings.Contains(i.Message, "ACL watcher") {
					t.Fatalf("watcher state must not fail --check: %s", i.Message)
				}
			}
		})
	}
}

func TestCheckUnreadableHintNamesFixACLs(t *testing.T) {
	env := baseEnv(t)
	dir := filepath.ToSlash(t.TempDir())
	os.WriteFile(dir+"/named.conf", []byte(`options { directory "`+dir+`"; };
zone "example.com" { type master; file "example.com.db"; };`), 0o644)
	os.WriteFile(dir+"/example.com.db", []byte(zone), 0o644)
	env.Source = &source.BIND{ConfFile: dir + "/named.conf"}
	env.OpenCheck = func(string) error { return fs.ErrPermission }
	r := Run(context.Background(), env)
	if !strings.Contains(messages(r, Fail), "1 zone files are not readable by the agent") || !strings.Contains(messages(r, Fail), "as root run: paneldns-agent fix-acls") {
		t.Fatalf("failures:\n%s", messages(r, Fail))
	}
}
