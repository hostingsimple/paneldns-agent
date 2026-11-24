package main

import (
	"bytes"
	"strings"
	"testing"
)

// The code must be able to reach enrol without appearing in the process
// list, where any local user can read it while enrol runs.
func TestEnrolCodeFromStdin(t *testing.T) {
	var warn bytes.Buffer
	got, err := enrolCode("-", "", strings.NewReader("abcd-efgh\nrest\n"), &warn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != "abcd-efgh" {
		t.Fatalf("code %q, want the first line of standard input", got)
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warning: %s", warn.String())
	}
	if _, err := enrolCode("-", "", strings.NewReader("\n"), &warn); err == nil {
		t.Fatal("an empty line on standard input was accepted")
	}
	if got, _ := enrolCode("", "from-env", nil, &warn); got != "from-env" || warn.Len() != 0 {
		t.Fatalf("env: %q, warning %q", got, warn.String())
	}
	if got, _ := enrolCode("on-argv", "", nil, &warn); got != "on-argv" || !strings.Contains(warn.String(), "process list") {
		t.Fatalf("argv: %q, warning %q", got, warn.String())
	}
}
