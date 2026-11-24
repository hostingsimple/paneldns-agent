package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/version"
)

func TestCLI(t *testing.T) {
	tests := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"version"}, 0, version.Version},
		{[]string{"--help"}, 0, "Usage:"},
		{nil, 2, "Usage:"},
		{[]string{"bogus"}, 2, "unknown command"},
		{[]string{"run", "--config", filepath.Join(t.TempDir(), "missing.conf")}, 1, "missing.conf"},
		{[]string{"--check", "--config", filepath.Join(t.TempDir(), "missing.conf")}, 1, "FAIL"},
		{[]string{"enrol", "--url", "http://app.example.com", "--code", "x", "--config", filepath.Join(t.TempDir(), "c.conf"), "--state-dir", t.TempDir()}, 1, ""},
	}
	for _, tt := range tests {
		var out, errb bytes.Buffer
		code := realMain(tt.args, &out, &errb)
		if code != tt.code || !strings.Contains(out.String()+errb.String(), tt.out) {
			t.Errorf("%v: code %d, output %q %q", tt.args, code, out.String(), errb.String())
		}
	}
}

func TestCheckNotEnrolled(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "paneldns-agent.conf")
	os.WriteFile(conf, []byte("PANELDNS_URL=https://app.example.com\nZONES_FILE=/nonexistent/named.conf\n"), 0o640)
	var out bytes.Buffer
	code := realMain([]string{"--check", "--config", conf, "--state-dir", dir}, &out, &out)
	if code != 1 || !strings.Contains(out.String(), "not enrolled") || !strings.Contains(out.String(), "listing zones") {
		t.Fatalf("code %d:\n%s", code, out.String())
	}
}

// TestUnitHardening pins the systemd hardening of spec 7.9.
func TestUnitHardening(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "packaging", "systemd", "paneldns-agent.service"))
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
	want := map[string]string{
		"User":                    "paneldns-agent",
		"Group":                   "paneldns-agent",
		"ExecStart":               "/usr/bin/paneldns-agent run",
		"NoNewPrivileges":         "yes",
		"ProtectSystem":           "strict",
		"ProtectHome":             "yes",
		"PrivateTmp":              "yes",
		"ReadWritePaths":          config.StateDir,
		"CapabilityBoundingSet":   "",
		"AmbientCapabilities":     "",
		"SystemCallFilter":        "@system-service",
		"RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
		"IPAddressDeny":           "localhost link-local multicast 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7",
		"MemoryMax":               "128M",
		"Nice":                    "10",
		"IOSchedulingClass":       "idle",
	}
	for k, v := range want {
		if len(got[k]) != 1 || got[k][0] != v {
			t.Errorf("%s=%q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["IPAddressAllow"]; ok {
		t.Error("IPAddressAllow belongs in the enrol drop-in, not the packaged unit")
	}
	if !strings.Contains(strings.Join(got["InaccessiblePaths"], " "), "/etc/rndc.key") {
		t.Error("rndc key not made inaccessible")
	}
}
