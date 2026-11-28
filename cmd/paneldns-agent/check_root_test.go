package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// stubCheckRoot replaces the root seams for one test.
func stubCheckRoot(t *testing.T, euid int, run func(stdout, stderr io.Writer, args []string) (int, error)) *[]string {
	t.Helper()
	oldEuid, oldRun, oldRepair := geteuid, checkAsAgent, repairState
	t.Cleanup(func() { geteuid, checkAsAgent, repairState = oldEuid, oldRun, oldRepair })
	var repaired []string
	geteuid = func() int { return euid }
	checkAsAgent = run
	repairState = func(dir string, _ io.Writer) error {
		repaired = append(repaired, dir)
		return nil
	}
	return &repaired
}

// TestCheckAsRootRunsAsAgent: as root, --check repairs the state files and
// re-runs itself as the agent user with the same arguments, returning its
// exit status (t105, D-34).
func TestCheckAsRootRunsAsAgent(t *testing.T) {
	dir := t.TempDir()
	var gotArgs []string
	repaired := stubCheckRoot(t, 0, func(stdout, _ io.Writer, args []string) (int, error) {
		gotArgs = args
		io.WriteString(stdout, "child ran")
		return 3, nil
	})
	args := []string{"--config", "/etc/x.conf", "--state-dir", dir, "--json"}
	var out, errb bytes.Buffer
	code := realMain(append([]string{"--check"}, args...), &out, &errb)
	if code != 3 || out.String() != "child ran" {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
	if !reflect.DeepEqual(gotArgs, args) {
		t.Fatalf("child args %v, want %v", gotArgs, args)
	}
	if !reflect.DeepEqual(*repaired, []string{dir}) {
		t.Fatalf("repaired %v, want [%s]", *repaired, dir)
	}
}

// TestCheckAsRootWithoutAgentUser: with no agent user, --check warns and
// runs in-process (as before).
func TestCheckAsRootWithoutAgentUser(t *testing.T) {
	stubCheckRoot(t, 0, func(io.Writer, io.Writer, []string) (int, error) { return 0, errNoAgentUser })
	var out, errb bytes.Buffer
	code := realMain([]string{"--check", "--config", filepath.Join(t.TempDir(), "missing.conf")}, &out, &errb)
	if code != 1 || !strings.Contains(out.String(), "FAIL") || !strings.Contains(errb.String(), "runs as root") {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
}

// TestCheckAsRootChildError: a child that can't start is an error, never
// a silent root run.
func TestCheckAsRootChildError(t *testing.T) {
	stubCheckRoot(t, 0, func(io.Writer, io.Writer, []string) (int, error) { return 0, errors.New("exec failed") })
	var out, errb bytes.Buffer
	code := realMain([]string{"--check", "--config", filepath.Join(t.TempDir(), "missing.conf")}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "exec failed") {
		t.Fatalf("code %d, out %q, err %q", code, out.String(), errb.String())
	}
}

// TestCheckNotRootRunsInProcess: an unprivileged --check (the service user,
// or enrol's self-check) never re-runs itself.
func TestCheckNotRootRunsInProcess(t *testing.T) {
	called := false
	repaired := stubCheckRoot(t, 1000, func(io.Writer, io.Writer, []string) (int, error) {
		called = true
		return 0, nil
	})
	var out bytes.Buffer
	code := realMain([]string{"--check", "--config", filepath.Join(t.TempDir(), "missing.conf")}, &out, &out)
	if code != 1 || called || len(*repaired) != 0 {
		t.Fatalf("code %d, called %v, repaired %v", code, called, *repaired)
	}
}
