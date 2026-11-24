package main

import (
	"bufio"
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

func TestFixACLsRefusesNonRoot(t *testing.T) {
	old := geteuid
	geteuid = func() int { return 1000 }
	defer func() { geteuid = old }()
	var out, errb bytes.Buffer
	if code := realMain([]string{"fix-acls", "--config", filepath.Join(t.TempDir(), "c.conf")}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "must run as root") {
		t.Fatalf("code %d: %q %q", code, out.String(), errb.String())
	}
}

// withUnits points the drop-ins at a temp dir and records systemctl.
func withUnits(t *testing.T) (calls *[]string) {
	t.Helper()
	dir := t.TempDir()
	oldP, oldS, oldU, oldR := aclPathDropIn, aclServiceDropIn, unitsSupported, runSystemctl
	aclPathDropIn = filepath.Join(dir, "paneldns-agent-acl.path.d", "watch.conf")
	aclServiceDropIn = filepath.Join(dir, "paneldns-agent-acl.service.d", "watch.conf")
	oldN, oldH, oldL := agentNetDropIn, agentHomeDropIn, lookupHost
	agentNetDropIn = filepath.Join(dir, "paneldns-agent.service.d", "10-paneldns-network.conf")
	agentHomeDropIn = filepath.Join(dir, "paneldns-agent.service.d", "20-paneldns-home.conf")
	lookupHost = func(string) ([]netip.Addr, error) { return nil, errors.New("no lookups in tests") }
	t.Cleanup(func() { agentNetDropIn, agentHomeDropIn, lookupHost = oldN, oldH, oldL })
	unitsSupported = true
	calls = &[]string{}
	runSystemctl = func(args ...string) ([]byte, error) {
		*calls = append(*calls, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() { aclPathDropIn, aclServiceDropIn, unitsSupported, runSystemctl = oldP, oldS, oldU, oldR })
	return calls
}

func TestRunFixACLs(t *testing.T) {
	plan := &enrol.ACLPlan{Read: []string{"/etc/named.conf", "/var/named/a.db"}, Dirs: []string{"/var/named"}}
	planFn := func(config.Config) (*enrol.ACLPlan, error) { return plan, nil }

	t.Run("watcher passes again after a fix, never touches units", func(t *testing.T) {
		calls := withUnits(t)
		var slept []time.Duration
		pass := 0
		var out bytes.Buffer
		code := runFixACLs(config.Defaults(), 990, fixOptions{
			settle: 3 * time.Second, maxPasses: 5, noUnits: true, out: &out,
			sleep: func(d time.Duration) { slept = append(slept, d) },
			plan:  planFn,
			fix: func(p *enrol.ACLPlan, o enrol.FixOptions) *enrol.FixResult {
				pass++
				if o.UID != 990 {
					t.Errorf("uid %d", o.UID)
				}
				if pass == 1 {
					return &enrol.FixResult{Fixed: []string{"/var/named/a.db"}, Fine: 2}
				}
				return &enrol.FixResult{Fine: 3}
			},
		})
		if code != 0 || pass != 2 || len(slept) != 2 || len(*calls) != 0 {
			t.Fatalf("code %d passes %d slept %v systemctl %v\n%s", code, pass, slept, *calls, out.String())
		}
		text := out.String()
		if !strings.Contains(text, "fix-acls: 1 fixed (/var/named/a.db), 3 already fine\n") ||
			!strings.Contains(text, "watch list in") || !strings.Contains(text, "out of date") {
			t.Fatalf("output:\n%s", text)
		}
		if _, err := os.Stat(aclPathDropIn); err == nil {
			t.Fatal("--no-units wrote a drop-in")
		}
	})

	t.Run("by hand: one pass, nothing to do, drop-ins written then left alone", func(t *testing.T) {
		calls := withUnits(t)
		run := func() (int, string) {
			var out bytes.Buffer
			code := runFixACLs(config.Defaults(), 990, fixOptions{maxPasses: 5, out: &out, plan: planFn,
				fix: func(*enrol.ACLPlan, enrol.FixOptions) *enrol.FixResult { return &enrol.FixResult{Fine: 3} }})
			return code, out.String()
		}
		code, text := run()
		if code != 0 || !strings.Contains(text, "fix-acls: 0 fixed, 3 already fine\n") || !strings.Contains(text, "watching /etc /var/named") {
			t.Fatalf("code %d:\n%s", code, text)
		}
		if !reflect.DeepEqual(*calls, []string{"daemon-reload", "try-restart paneldns-agent-acl.path"}) {
			t.Fatalf("systemctl %v", *calls)
		}
		b, err := os.ReadFile(aclPathDropIn)
		if err != nil || !strings.Contains(string(b), "PathChanged=/var/named\n") {
			t.Fatalf("path drop-in %q %v", b, err)
		}
		if b, _ := os.ReadFile(aclServiceDropIn); !strings.Contains(string(b), "ReadWritePaths=-/var/named\n") {
			t.Fatalf("service drop-in %q", b)
		}
		*calls = nil
		if code, text := run(); code != 0 || len(*calls) != 0 || strings.Contains(text, "drop-ins updated") {
			t.Fatalf("second run: code %d systemctl %v\n%s", code, *calls, text)
		}
		// Up to date now: the watcher has nothing to report.
		var out bytes.Buffer
		runFixACLs(config.Defaults(), 990, fixOptions{noUnits: true, out: &out, plan: planFn,
			fix: func(*enrol.ACLPlan, enrol.FixOptions) *enrol.FixResult { return &enrol.FixResult{} }})
		if strings.Contains(out.String(), "out of date") {
			t.Fatalf("stale reported:\n%s", out.String())
		}
	})

	t.Run("errors exit 1", func(t *testing.T) {
		withUnits(t)
		var out bytes.Buffer
		code := runFixACLs(config.Defaults(), 990, fixOptions{noUnits: true, out: &out, plan: planFn,
			fix: func(*enrol.ACLPlan, enrol.FixOptions) *enrol.FixResult {
				return &enrol.FixResult{Fine: 2, Errors: []error{os.ErrPermission}}
			}})
		if code != 1 || !strings.Contains(out.String(), "1 failed") {
			t.Fatalf("code %d:\n%s", code, out.String())
		}
	})
}

func unitSettings(t *testing.T, name string) map[string][]string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "packaging", "systemd", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad unit line %q", line)
		}
		got[k] = append(got[k], v)
	}
	return got
}

// TestACLUnitHardening pins the root helper's sandbox (DECISIONS D-30).
func TestACLUnitHardening(t *testing.T) {
	svc := unitSettings(t, enrol.ACLServiceUnit)
	want := map[string]string{
		"Type":                    "oneshot",
		"ExecStart":               "/usr/bin/paneldns-agent fix-acls --settle 3s --no-units",
		"User":                    "root",
		"CapabilityBoundingSet":   "CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID",
		"AmbientCapabilities":     "",
		"NoNewPrivileges":         "yes",
		"ProtectSystem":           "strict",
		"ProtectHome":             "yes",
		"PrivateTmp":              "yes",
		"PrivateDevices":          "yes",
		"PrivateNetwork":          "yes",
		"IPAddressDeny":           "any",
		"RestrictAddressFamilies": "none",
		"StartLimitIntervalSec":   "0",
	}
	for k, v := range want {
		if len(svc[k]) != 1 || svc[k][0] != v {
			t.Errorf("%s: %s=%q, want %q", enrol.ACLServiceUnit, k, svc[k], v)
		}
	}
	if _, ok := svc["ReadWritePaths"]; ok {
		t.Error("ReadWritePaths belongs in the enrol drop-in")
	}
	if strings.Contains(svc["CapabilityBoundingSet"][0], "DAC_OVERRIDE") {
		t.Error("CAP_DAC_OVERRIDE granted")
	}
	path := unitSettings(t, enrol.ACLPathUnit)
	if !reflect.DeepEqual(path["Unit"], []string{enrol.ACLServiceUnit}) || !reflect.DeepEqual(path["PathChanged"], []string{config.DefaultPath}) ||
		len(path["TriggerLimitIntervalSec"]) != 1 || len(path["TriggerLimitBurst"]) != 1 || !reflect.DeepEqual(path["WantedBy"], []string{"paths.target"}) {
		t.Errorf("path unit %v", path)
	}
}
