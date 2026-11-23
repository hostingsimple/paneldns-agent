package enrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withRoot(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	for p, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(content), 0o644)
	}
	Root = filepath.ToSlash(dir)
	t.Cleanup(func() { Root = "" })
}

func TestDetectSource(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		source  string
		file    string
		chroot  string
		api     string
		key     string
		wantErr string
	}{
		{name: "rhel named", files: map[string]string{"/etc/named.conf": ""}, source: "bind", file: "/etc/named.conf"},
		{name: "debian named", files: map[string]string{"/etc/bind/named.conf": ""}, source: "bind", file: "/etc/bind/named.conf"},
		{name: "sysconfig chroot", files: map[string]string{
			"/etc/sysconfig/named":                 "ROOTDIR=\"/var/named/run-root\"\n",
			"/var/named/run-root/etc/named.conf":   "",
			"/etc/named.conf.placeholder-not-used": "",
		}, source: "bind", file: "/var/named/run-root/etc/named.conf", chroot: "/var/named/run-root"},
		{name: "named-chroot unit", files: map[string]string{
			"/etc/systemd/system/multi-user.target.wants/named-chroot.service": "",
			"/var/named/chroot/etc/named.conf":                                 "",
			"/etc/named.conf":                                                  "",
		}, source: "bind", file: "/var/named/chroot/etc/named.conf", chroot: "/var/named/chroot"},
		{name: "pdns bind backend", files: map[string]string{
			"/etc/pdns/pdns.conf": "launch=bind\nbind-config=/etc/named.conf\n",
			"/etc/named.conf":     "",
		}, source: "bind", file: "/etc/named.conf"},
		{name: "pdns api", files: map[string]string{
			"/etc/powerdns/pdns.conf":     "api=yes\napi-key=plainkey\nwebserver-address=0.0.0.0\nwebserver-port=8082\ninclude-dir=/etc/powerdns/pdns.d\n",
			"/etc/powerdns/pdns.d/x.conf": "webserver-port=8083\n",
		}, source: "powerdns-api", api: "http://127.0.0.1:8083", key: "plainkey"},
		{name: "pdns api off", files: map[string]string{"/etc/powerdns/pdns.conf": "api=no\n"}, wantErr: "api=no"},
		{name: "pdns hashed key", files: map[string]string{"/etc/powerdns/pdns.conf": "api=yes\napi-key=$scrypt$ln=10,p=1,r=8$abc\n"}, wantErr: "hashed"},
		{name: "pdns non-loopback", files: map[string]string{"/etc/powerdns/pdns.conf": "api=yes\napi-key=k\nwebserver-address=192.0.2.5\n"}, wantErr: "loopback"},
		{name: "nothing", files: map[string]string{}, wantErr: "no named.conf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRoot(t, tt.files)
			d, err := DetectSource()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want %q, got %v (%+v)", tt.wantErr, err, d)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.ZoneSource != tt.source || d.ZonesFile != tt.file || d.Chroot != tt.chroot || d.PDNSAPIURL != tt.api || d.PDNSAPIKey != tt.key {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

// P1 on fusion: a stale DirectAdmin /etc/named.conf next to the /etc/bind/named.conf the running
// named (no -c) reads by its compiled-in default.
func TestDetectSourcePrefersRunningNamed(t *testing.T) {
	stubVersion := func(t *testing.T, out string) {
		t.Helper()
		old := namedVersionOutput
		namedVersionOutput = func() ([]byte, error) { return []byte(out), nil }
		t.Cleanup(func() { namedVersionOutput = old })
	}
	tests := []struct {
		name, cmdline, version, want, note string
	}{
		{"compiled-in default", "/usr/sbin/named\x00-f\x00-u\x00bind\x00",
			"BIND 9.18.39-0ubuntu0.24.04.9-Ubuntu\n  named configuration:  /etc/bind/named.conf\n  rndc configuration:   /etc/bind/rndc.conf\n",
			"/etc/bind/named.conf", "also found, not used: /etc/named.conf"},
		{"explicit -c", "/usr/sbin/named\x00-u\x00named\x00-c\x00/etc/named.conf\x00",
			"  named configuration:  /etc/bind/named.conf\n", "/etc/named.conf", "also found, not used: /etc/bind/named.conf"},
		{"joined -c", "named\x00-c/etc/bind/named.conf\x00", "", "/etc/bind/named.conf", "(named -c)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withRoot(t, map[string]string{
				"/etc/named.conf":      "options { directory \"/var/named\"; };",
				"/etc/bind/named.conf": "",
				"/proc/2831/comm":      "named\n",
				"/proc/2831/cmdline":   tt.cmdline,
				"/proc/2831/status":    "Name:\tnamed\nUid:\t0\t0\t0\t0\n",
				"/proc/77/comm":        "sshd\n",
			})
			stubVersion(t, tt.version)
			d, err := DetectSource()
			if err != nil {
				t.Fatal(err)
			}
			if d.ZoneSource != "bind" || d.ZonesFile != tt.want {
				t.Fatalf("got %s %s, want bind %s", d.ZoneSource, d.ZonesFile, tt.want)
			}
			if !strings.Contains(strings.Join(d.Notes, "\n"), tt.note) {
				t.Fatalf("notes %q lack %q", d.Notes, tt.note)
			}
		})
	}
}

// A local user can start a process called "named" with a -c of their own;
// only a named running as root or as the named/bind user counts. Here the
// real named (no -c, Debian) runs as bind and an impostor as uid 1001.
func TestDetectSourceIgnoresImpostorNamed(t *testing.T) {
	withRoot(t, map[string]string{
		"/etc/passwd":             "root:x:0:0::/root:/bin/sh\nbind:x:113:118::/var/cache/bind:/usr/sbin/nologin\nmallory:x:1001:1001::/home/mallory:/bin/bash\n",
		"/etc/bind/named.conf":    "",
		"/home/mallory/evil.conf": "zone \"example.com\" { type primary; file \"/etc/shadow\"; };",
		"/proc/1001/comm":         "named\n",
		"/proc/1001/cmdline":      "/home/mallory/named\x00-c\x00/home/mallory/evil.conf\x00",
		"/proc/1001/status":       "Name:\tnamed\nUid:\t1001\t1001\t1001\t1001\n",
		"/proc/2831/comm":         "named\n",
		"/proc/2831/cmdline":      "/usr/sbin/named\x00-f\x00-u\x00bind\x00",
		"/proc/2831/status":       "Name:\tnamed\nUid:\t113\t113\t113\t113\n",
	})
	old := namedVersionOutput
	namedVersionOutput = func() ([]byte, error) { return []byte("  named configuration:  /etc/bind/named.conf\n"), nil }
	t.Cleanup(func() { namedVersionOutput = old })
	d, err := DetectSource()
	if err != nil {
		t.Fatal(err)
	}
	if d.ZonesFile != "/etc/bind/named.conf" {
		t.Fatalf("ZONES_FILE %s: an impostor named chose the config", d.ZonesFile)
	}
}

func TestDetectSourceNamedNotRunningNotesTheChoice(t *testing.T) {
	withRoot(t, map[string]string{"/etc/named.conf": "", "/etc/bind/named.conf": "", "/proc/77/comm": "sshd\n"})
	d, err := DetectSource()
	if err != nil {
		t.Fatal(err)
	}
	if d.ZonesFile != "/etc/named.conf" || !strings.Contains(strings.Join(d.Notes, "\n"), "check ZONES_FILE") {
		t.Fatalf("got %s, notes %q", d.ZonesFile, d.Notes)
	}
}
