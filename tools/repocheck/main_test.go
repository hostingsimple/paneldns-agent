package main

import (
	"strings"
	"testing"
)

func TestScanText(t *testing.T) {
	tests := []struct {
		text string
		bad  []string
	}{
		{"www.example.com. 300 IN A 192.0.2.10", nil},
		{"mail IN AAAA 2001:db8::10 ; and ::1 and 127.0.0.1", nil},
		{"zone \"0.0.127.in-addr.arpa\" { file \"named.loopback\"; };", nil},
		{"zone \"168.192.in-addr.arpa\"; zone \"2.0.192.in-addr.arpa\";", nil},
		{"letsencrypt.example app.paneldns.example printer.local", nil},
		{"files: named.conf cache_dump.db README.md root.hints x.jnl", nil},
		{"version 1.2.3 and 10.20.30 and serial 2026112001", nil},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", nil},
		{"customer.com. IN A 192.0.2.1", []string{"name customer.com"}},
		{"shop.example.org", []string{"name shop.example.org"}},
		{"host.example.co.uk", []string{"name host.example.co.uk"}},
		{"A 203.0.113.5", []string{"address 203.0.113.5"}},
		{"A 8.8.8.8", []string{"address 8.8.8.8"}},
		{"AAAA 2606:4700::1111", []string{"address 2606:4700::1111"}},
		{"zone \"113.0.203.in-addr.arpa\"", []string{"name 113.0.203.in-addr.arpa"}},
		{`"text": "$ORIGIN example.com.\nexample.com. 300 IN A 192.0.2.1\nother.org."`, []string{"name other.org"}},
	}
	for _, tt := range tests {
		got := scanText(tt.text)
		if strings.Join(got, "|") != strings.Join(tt.bad, "|") {
			t.Errorf("%q: got %v, want %v", tt.text, got, tt.bad)
		}
	}
}

func TestLintWorkflow(t *testing.T) {
	good := `name: ci
on: [push, pull_request]
permissions: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ./local-action
`
	if p := lintWorkflow("ci.yml", good); len(p) != 0 {
		t.Fatalf("good workflow: %v", p)
	}
	bad := `on:
  pull_request_target:
jobs:
  a:
    environment: release-signing
    steps:
      - uses: actions/checkout@v7
`
	p := strings.Join(lintWorkflow(".github/workflows/ci.yml", bad), "\n")
	for _, want := range []string{"not pinned", "pull_request_target", "only release.yml", "no top-level permissions"} {
		if !strings.Contains(p, want) {
			t.Errorf("missing %q in:\n%s", want, p)
		}
	}
	if p := lintWorkflow(".github/workflows/release.yml", "permissions: {}\njobs:\n  s:\n    environment: release-signing\n"); len(p) != 0 {
		t.Fatalf("release.yml may name the environment: %v", p)
	}
}
