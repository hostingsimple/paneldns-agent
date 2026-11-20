package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSampleConfigParses(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "packaging", "paneldns-agent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		URL: "https://app.paneldns.example", Interval: 60, Resync: 21600,
		LogLevel: "info", ZoneSource: "bind", ZonesFile: "/etc/named.conf",
		PDNSAPIURL: "http://127.0.0.1:8081", PDNSAPIKeyFile: "/var/lib/paneldns-agent/pdns-api-key",
		OwnersFile: "/etc/userdomains", Exclude: []string{"*.local", "server-hostname.example.net"},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v\nwant %+v", c, want)
	}
}

func TestParse(t *testing.T) {
	base := "PANELDNS_URL=https://app.example.com\n"
	tests := []struct {
		name    string
		text    string
		wantErr string
		check   func(t *testing.T, c Config)
	}{
		{name: "defaults", text: base, check: func(t *testing.T, c Config) {
			if c.Interval != 60 || c.Resync != 21600 || c.ZoneSource != "bind" {
				t.Fatalf("defaults wrong: %+v", c)
			}
		}},
		{name: "quoted value with hash", text: base + `VIEW="a#b"   # comment` + "\n", check: func(t *testing.T, c Config) {
			if c.View != "a#b" {
				t.Fatalf("view %q", c.View)
			}
		}},
		{name: "hash without space is part of value", text: base + "VIEW=a#b\n", check: func(t *testing.T, c Config) {
			if c.View != "a#b" {
				t.Fatalf("view %q", c.View)
			}
		}},
		{name: "crlf", text: "PANELDNS_URL=https://app.example.com\r\nINTERVAL=30\r\n", check: func(t *testing.T, c Config) {
			if c.Interval != 30 {
				t.Fatalf("interval %d", c.Interval)
			}
		}},
		{name: "unknown key warns", text: base + "FOO=1\n", check: func(t *testing.T, c Config) {
			if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "FOO") {
				t.Fatalf("warnings %v", c.Warnings)
			}
		}},
		{name: "http refused", text: "PANELDNS_URL=http://app.example.com\n", wantErr: "https"},
		{name: "url missing", text: "INTERVAL=60\n", wantErr: "not set"},
		{name: "url with query", text: "PANELDNS_URL=https://app.example.com/?a=b\n", wantErr: "query"},
		{name: "url with userinfo", text: "PANELDNS_URL=https://u:p@app.example.com\n", wantErr: "user info"},
		{name: "interval too low", text: base + "INTERVAL=5\n", wantErr: "at least 15"},
		{name: "interval not a number", text: base + "INTERVAL=1m\n", wantErr: "whole number"},
		{name: "resync below interval", text: base + "INTERVAL=600\nRESYNC=60\n", wantErr: "RESYNC"},
		{name: "bad log level", text: base + "LOG_LEVEL=trace\n", wantErr: "LOG_LEVEL"},
		{name: "pdnsutil not yet", text: base + "ZONE_SOURCE=pdnsutil\n", wantErr: "later version"},
		{name: "pdns api must be loopback", text: base + "ZONE_SOURCE=powerdns-api\nPDNS_API_URL=http://192.0.2.1:8081\n", wantErr: "loopback"},
		{name: "pdns api loopback v6", text: base + "ZONE_SOURCE=powerdns-api\nPDNS_API_URL=http://[::1]:8081\n"},
		{name: "relative zones file", text: base + "ZONES_FILE=named.conf\n", wantErr: "absolute"},
		{name: "bad exclude", text: base + "EXCLUDE=[a\n", wantErr: "EXCLUDE"},
		{name: "no equals", text: base + "JUNK\n", wantErr: "KEY=VALUE"},
		{name: "unterminated quote", text: base + "VIEW=\"abc\n", wantErr: "quote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(tt.text)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestSetValuesKeepsCommentsAndAppends(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "paneldns-agent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	out := SetValues(string(b), map[string]string{
		"PANELDNS_URL": "https://app.example.net",
		"OWNERS_FILE":  "/etc/virtual/domainowners",
	})
	if !strings.Contains(out, "PANELDNS_URL=https://app.example.net   # HTTPS only") {
		t.Fatalf("url line not rewritten with comment:\n%s", out)
	}
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if c.URL != "https://app.example.net" || c.OwnersFile != "/etc/virtual/domainowners" || c.Interval != 60 {
		t.Fatalf("got %+v", c)
	}
	out2 := SetValues("PANELDNS_URL=https://a.example.com", map[string]string{"VIEW": "external"})
	if !strings.HasSuffix(out2, "\nVIEW=external\n") {
		t.Fatalf("append failed: %q", out2)
	}
}
