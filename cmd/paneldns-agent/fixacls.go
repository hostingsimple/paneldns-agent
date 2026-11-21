package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// Seams for tests.
var (
	geteuid        = os.Geteuid
	lookupAgentUID = func() (uint32, error) {
		u, err := user.Lookup(enrol.User)
		if err != nil {
			return 0, fmt.Errorf("user %s not found (the package creates it): %w", enrol.User, err)
		}
		n, err := strconv.ParseUint(u.Uid, 10, 32)
		return uint32(n), err
	}
	runSystemctl = func(args ...string) ([]byte, error) {
		return exec.Command("systemctl", args...).CombinedOutput()
	}
	// unitsSupported: drop-ins are only written where systemd runs.
	unitsSupported   = runtime.GOOS == "linux"
	aclPathDropIn    = enrol.ACLPathDropIn
	aclServiceDropIn = enrol.ACLServiceDropIn
)

type fixOptions struct {
	settle    time.Duration // wait before each pass (the watcher: let the panel finish)
	maxPasses int
	noUnits   bool // the watcher: never rewrite unit files, only report
	noWatch   bool // enrol: it writes the drop-ins itself
	out       io.Writer
	sleep     func(time.Duration)
	plan      func(config.Config) (*enrol.ACLPlan, error)
	fix       func(*enrol.ACLPlan, enrol.FixOptions) *enrol.FixResult
}

func cmdFixACLs(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("fix-acls", stderr)
	configPath := fs.String("config", config.DefaultPath, "config file")
	settle := fs.Duration("settle", 0, "wait this long before each pass, and pass again while files keep needing a fix (the watcher unit)")
	noUnits := fs.Bool("no-units", false, "don't rewrite the ACL watcher's drop-ins; report when they are out of date (the watcher unit)")
	if fs.Parse(args) != nil {
		return 2
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "paneldns-agent fix-acls must run as root (it sets ACLs on named's files for the agent user)")
		return 1
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent fix-acls:", err)
		return 1
	}
	uid, err := lookupAgentUID()
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent fix-acls:", err)
		return 1
	}
	return runFixACLs(cfg, uid, fixOptions{settle: *settle, maxPasses: 5, noUnits: *noUnits, out: stdout})
}

// runFixACLs re-grants the agent's read access where it was lost. With a
// settle time (the watcher) it passes again after any fix, so files the
// panel wrote while a pass ran are caught by the next one.
func runFixACLs(cfg config.Config, uid uint32, o fixOptions) int {
	if o.sleep == nil {
		o.sleep = time.Sleep
	}
	if o.plan == nil {
		o.plan = enrol.PlanACLs
	}
	if o.fix == nil {
		o.fix = enrol.FixACLs
	}
	var (
		plan   *enrol.ACLPlan
		fixed  []string
		fine   int
		failed []error
	)
	for pass := 1; pass <= max(1, o.maxPasses); pass++ {
		if o.settle > 0 {
			o.sleep(o.settle)
		}
		var err error
		plan, err = o.plan(cfg)
		if err != nil {
			fmt.Fprintln(o.out, "fix-acls: working out read access:", err)
			return 1
		}
		res := o.fix(plan, enrol.FixOptions{UID: uid})
		fixed = append(fixed, res.Fixed...)
		fine = res.Fine
		failed = append(failed, res.Errors...)
		if len(res.Fixed) == 0 || o.settle == 0 {
			break
		}
	}
	for _, w := range plan.Warnings {
		fmt.Fprintln(o.out, "fix-acls: warning:", w)
	}
	for _, err := range failed {
		fmt.Fprintln(o.out, "fix-acls: error:", err)
	}
	line := fmt.Sprintf("fix-acls: %d fixed", len(fixed))
	if len(fixed) > 0 {
		line += " (" + limitPaths(fixed, 5) + ")"
	}
	line += fmt.Sprintf(", %d already fine", fine)
	if len(failed) > 0 {
		line += fmt.Sprintf(", %d failed", len(failed))
	}
	fmt.Fprintln(o.out, line)

	if o.noWatch {
		if len(failed) > 0 {
			return 1
		}
		return 0
	}
	w := enrol.PlanWatch(plan)
	for _, r := range w.Rejected {
		fmt.Fprintf(o.out, "fix-acls: warning: %s is not watched (characters a unit file can't hold)\n", r)
	}
	if o.noUnits {
		if stale, _ := watchStale(w); stale {
			fmt.Fprintf(o.out, "fix-acls: warning: the watch list in %s is out of date (zone directories changed); run paneldns-agent fix-acls as root to update it\n", aclPathDropIn)
		}
	} else if _, err := syncWatchUnits(w, o.out, true); err != nil {
		fmt.Fprintln(o.out, "fix-acls: error:", err)
		return 1
	}
	if len(failed) > 0 {
		return 1
	}
	return 0
}

func limitPaths(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(" and %d more", len(s)-n)
}

// watchStale reports whether the installed drop-ins differ from w.
func watchStale(w enrol.WatchList) (bool, error) {
	for _, f := range []struct{ path, text string }{
		{aclPathDropIn, w.PathDropIn()}, {aclServiceDropIn, w.ServiceDropIn()},
	} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			return true, err
		}
		if !bytes.Equal(b, []byte(f.text)) {
			return true, nil
		}
	}
	return false, nil
}

// syncWatchUnits writes the ACL watcher's drop-ins when they changed. With
// reload it then reloads systemd and restarts the path unit if it runs, so
// it watches the new list.
func syncWatchUnits(w enrol.WatchList, out io.Writer, reload bool) (changed bool, err error) {
	if !unitsSupported {
		return false, nil
	}
	for _, f := range []struct{ path, text string }{
		{aclPathDropIn, w.PathDropIn()}, {aclServiceDropIn, w.ServiceDropIn()},
	} {
		if b, err := os.ReadFile(f.path); err == nil && bytes.Equal(b, []byte(f.text)) {
			continue
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return changed, err
		}
		if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
			return changed, err
		}
		if err := state.WriteAtomic(f.path, []byte(f.text), 0o644); err != nil {
			return changed, err
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	fmt.Fprintf(out, "ACL watcher drop-ins updated: watching %s\n", strings.Join(w.Watch, " "))
	if !reload {
		return true, nil
	}
	// Not fatal: the ACLs are fixed, and the watcher (if installed) picks
	// the list up at the next reload.
	if b, err := runSystemctl("daemon-reload"); err != nil {
		fmt.Fprintf(out, "warning: systemctl daemon-reload: %v: %s\n", err, strings.TrimSpace(string(b)))
	} else if b, err := runSystemctl("try-restart", enrol.ACLPathUnit); err != nil {
		fmt.Fprintf(out, "warning: systemctl try-restart %s: %v: %s\n", enrol.ACLPathUnit, err, strings.TrimSpace(string(b)))
	}
	return true, nil
}
