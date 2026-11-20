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

func wantAll(t *testing.T, problems []string, wants ...string) {
	t.Helper()
	p := strings.Join(problems, "\n")
	for _, w := range wants {
		if !strings.Contains(p, w) {
			t.Errorf("missing %q in:\n%s", w, p)
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
    permissions:
      contents: read
    env:
      DEBIAN_IMAGE: debian:13@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-go@d8cbb8045d7f43706b9177cceb36c1f91a6644d5 # v7.1.0
        with:
          cache: false
      - uses: ./local-action
      - run: echo "${{ secrets.GITHUB_TOKEN }}"
`
	if p := lintWorkflow(".github/workflows/ci.yml", good); len(p) != 0 {
		t.Fatalf("good workflow: %v", p)
	}
	bad := `on:
  pull_request_target:
jobs:
  a:
    environment: release-signing
    services:
      db:
        image: postgres:17
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@d8cbb8045d7f43706b9177cceb36c1f91a6644d5
        with:
          go-version: "1.27"
      - run: echo ${{ secrets.PACKAGES_DEPLOY_KEY }}
`
	wantAll(t, lintWorkflow(".github/workflows/ci.yml", bad),
		"not pinned by a 40", "pull_request_target", "only release.yml", "no top-level permissions",
		"job a has no permissions", "image postgres:17 is not pinned by digest", "cache: false",
		"secrets.PACKAGES_DEPLOY_KEY may only")
}

const goodRelease = `name: release

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

permissions: {}

jobs:
  build:
    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: read
    steps:
      - run: true
  sign-and-publish:
    needs: build
    if: >-
      !cancelled() &&
      startsWith(github.ref, 'refs/tags/v')
    environment: release-signing
    permissions:
      contents: write
    steps:
      - env:
          K: ${{ secrets.PACKAGES_SIGNING_KEY }}
        run: true
`

func TestLintReleaseWorkflow(t *testing.T) {
	if p := lintWorkflow(".github/workflows/release.yml", goodRelease); len(p) != 0 {
		t.Fatalf("good release workflow: %v", p)
	}
	bad := strings.NewReplacer(
		"  workflow_dispatch:", "  pull_request:",
		"    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')", "    if: always()",
		"  sign-and-publish:", "  publish:",
	).Replace(goodRelease) + `  leak:
    if: startsWith(github.ref, 'refs/tags/v')
    permissions: {}
    steps:
      - run: echo ${{ secrets.PACKAGES_SIGNING_PASSPHRASE }}
`
	wantAll(t, lintWorkflow(".github/workflows/release.yml", bad),
		"must not run for pull requests",
		"job build must be guarded",
		"job publish names an environment",
		"secrets.PACKAGES_SIGNING_KEY may only",
		"secrets.PACKAGES_SIGNING_PASSPHRASE may only")
	branches := strings.Replace(goodRelease, "  push:\n    tags:", "  push:\n    branches:", 1)
	wantAll(t, lintWorkflow(".github/workflows/release.yml", branches), "trigger on push of tags")
}

// TestRepositoryWorkflows applies the rules to this repository's own
// workflows, so a change that breaks one fails the unit tests too.
func TestRepositoryWorkflows(t *testing.T) {
	p, err := checkWorkflows("../../.github/workflows")
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 0 {
		t.Fatalf("the repository's workflows break the rules:\n%s", strings.Join(p, "\n"))
	}
}
