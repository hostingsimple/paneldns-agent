package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/check"
	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
	"github.com/hostingsimple/paneldns-agent/internal/host"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// checkAsAgent re-runs this binary's --check as the agent user (a seam
// for tests).
var checkAsAgent = func(stdout, stderr io.Writer, args []string) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(stderr, "running --check as %s, the service's user\n", enrol.User)
	return execAsAgent(stdout, stderr, self, append([]string{"--check"}, args...)...)
}

// repairState is repairCheckState (a seam for tests).
var repairState = repairCheckState

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("--check", stderr)
	configPath := fs.String("config", config.DefaultPath, "config file")
	stateDir := fs.String("state-dir", config.StateDir, "state directory")
	zone := fs.String("zone", "", "print the canonical text and hash of one zone")
	asJSON := fs.Bool("json", false, "write the report as JSON")
	if fs.Parse(args) != nil {
		return 2
	}
	// AGENT-CHECK-ROOT-01 (D-34): as root, --check re-runs itself as the
	// agent user. A root run would leave sequence.json (and its lock)
	// owned by root, and the service could then no longer sign a request;
	// it would also read files the service can't.
	if geteuid() == 0 {
		if err := repairState(*stateDir, stderr); err != nil {
			fmt.Fprintln(stderr, "warning:", err)
		}
		code, err := checkAsAgent(stdout, stderr, args)
		if err == nil {
			return code
		}
		if !errors.Is(err, errNoAgentUser) {
			fmt.Fprintf(stderr, "error: running --check as %s: %v\n", enrol.User, err)
			return 1
		}
		fmt.Fprintf(stderr, "warning: user %s not found, so --check runs as root and can't show the service's access\n", enrol.User)
	}
	env := buildCheckEnv(*configPath, *stateDir)
	env.Zone = *zone
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res := check.Run(ctx, env)
	if *asJSON {
		res.WriteJSON(stdout)
	} else {
		res.WriteText(stdout)
	}
	if res.Failed() {
		return 1
	}
	return 0
}

// buildCheckEnv loads each piece on its own, so one missing piece is a
// reported failure rather than an early exit.
func buildCheckEnv(configPath, stateDir string) check.Env {
	env := check.Env{
		ConfigPath: configPath, StateDir: stateDir,
		Stat: statFile, OpenCheck: check.DefaultOpenCheck, Lookup: check.DefaultLookup,
		Hostname: host.Hostname(),
	}
	if unitsSupported {
		env.Systemctl = func(args ...string) (string, error) {
			b, err := runSystemctl(args...)
			return strings.TrimSpace(string(b)), err
		}
		env.WatchDropIn, env.ReadFile = aclPathDropIn, os.ReadFile
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		env.ConfigErr = err
		return env
	}
	env.Config = &cfg
	if unitsSupported {
		env.UnitDropIns = func(zonePaths []string) []string {
			home := enrol.UnderHome(zonePaths)
			want := agentDropIns(networkAllow(cfg), home)
			if !home {
				// Only the zones are known here, not every planned path
				// ($INCLUDE files): a home drop-in may still be needed.
				delete(want, agentHomeDropIn)
			}
			return staleDropIns(want)
		}
	}
	if src, err := newSource(cfg); err == nil {
		env.Source = src
	}
	if cfg.OwnersFile != "" {
		env.Owners = &owners.File{Path: cfg.OwnersFile}
	}
	p := func(n string) string { return filepath.Join(stateDir, n) }
	env.Identity, env.IdentErr = state.LoadIdentity(p(state.IdentityFile))
	if errors.Is(env.IdentErr, fs.ErrNotExist) {
		env.IdentErr = errNotEnrolled
	}
	if st, _, err := state.Load(p(state.StateFile)); err == nil {
		env.State = st
	}
	env.Sequence = &state.Sequence{Path: p(state.SequenceFile)}
	if env.IdentErr != nil {
		return env
	}
	key, err := state.LoadKey(p(state.KeyFile))
	if err != nil {
		env.KeyErr = err
		return env
	}
	client := &protocol.Client{BaseURL: cfg.URL, HTTP: protocol.NewHTTPClient(), Seq: env.Sequence}
	client.SetKey(key, env.Identity.SourceID, env.Identity.KeyID)
	env.Heartbeat = client.Heartbeat
	env.ServerDate = client.ServerDate
	return env
}
