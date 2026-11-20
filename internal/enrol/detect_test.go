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
