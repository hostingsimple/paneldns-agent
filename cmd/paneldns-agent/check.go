package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/check"
	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/host"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("--check", stderr)
	configPath := fs.String("config", config.DefaultPath, "config file")
	stateDir := fs.String("state-dir", config.StateDir, "state directory")
	zone := fs.String("zone", "", "print the canonical text and hash of one zone")
	asJSON := fs.Bool("json", false, "write the report as JSON")
	if fs.Parse(args) != nil {
		return 2
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
	cfg, err := config.Load(configPath)
	if err != nil {
		env.ConfigErr = err
		return env
	}
	env.Config = &cfg
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
