package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/host"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/version"
)

// agent is everything a running agent needs, shared by run and --check.
type agent struct {
	cfg      config.Config
	stateDir string
	id       *state.Identity
	key      ed25519.PrivateKey
	seq      *state.Sequence
	st       *state.State
	stExists bool
	src      source.Source
	client   *protocol.Client
	owners   engine.Owners
	log      *slog.Logger
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	switch level {
	case "error":
		l = slog.LevelError
	case "warn":
		l = slog.LevelWarn
	case "debug":
		l = slog.LevelDebug
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l}))
}

// newSource builds the zone source the config names.
func newSource(cfg config.Config) (source.Source, error) {
	switch cfg.ZoneSource {
	case config.SourceBIND:
		return &source.BIND{ConfFile: cfg.ZonesFile, Chroot: cfg.Chroot, View: cfg.View}, nil
	case config.SourcePowerDNSAPI:
		return &source.PowerDNS{BaseURL: cfg.PDNSAPIURL, KeyFile: cfg.PDNSAPIKeyFile}, nil
	}
	return nil, fmt.Errorf("ZONE_SOURCE %q is not supported", cfg.ZoneSource)
}

// loadAgent reads config, identity, key and state. needKey=false lets
// --check report a missing enrolment instead of failing.
func loadAgent(configPath, stateDir string, log *slog.Logger) (*agent, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = newLogger(cfg.LogLevel, os.Stderr)
	}
	for _, w := range cfg.Warnings {
		log.Warn("config", "file", configPath, "warning", w)
	}
	a := &agent{cfg: cfg, stateDir: stateDir, log: log}
	p := func(n string) string { return filepath.Join(stateDir, n) }
	a.id, err = state.LoadIdentity(p(state.IdentityFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return a, errNotEnrolled
		}
		return a, err
	}
	a.key, err = state.LoadKey(p(state.KeyFile))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return a, fmt.Errorf("%s is missing; the key can't be recovered: re-enrol with a new code from the dashboard", p(state.KeyFile))
		}
		return a, err
	}
	a.seq = &state.Sequence{Path: p(state.SequenceFile)}
	a.st, a.stExists, err = state.Load(p(state.StateFile))
	if err != nil {
		return a, err
	}
	if a.id.URL != "" && a.id.URL != cfg.URL {
		log.Warn("PANELDNS_URL differs from the URL used at enrolment; using PANELDNS_URL", "config", cfg.URL, "enrolled", a.id.URL)
	}
	a.src, err = newSource(cfg)
	if err != nil {
		return a, err
	}
	a.client = &protocol.Client{BaseURL: cfg.URL, HTTP: protocol.NewHTTPClient(), Seq: a.seq}
	a.client.SetKey(a.key, a.id.SourceID, a.id.KeyID)
	a.owners = newOwners(cfg)
	return a, nil
}

var errNotEnrolled = errors.New("this server is not enrolled: run paneldns-agent enrol --url URL --code CODE as root")

func (a *agent) engine() *engine.Engine {
	e := engine.New(engine.Config{
		Interval:  time.Duration(a.cfg.Interval) * time.Second,
		Resync:    time.Duration(a.cfg.Resync) * time.Second,
		Exclude:   a.cfg.Exclude,
		StatePath: filepath.Join(a.stateDir, state.StateFile),
		Host:      engine.Host{Hostname: host.Hostname(), OS: host.OS(), Panel: host.Panel(), PublicIPs: host.PublicIPs},
		// Spec 8.2: a missing state file means the server must issue a
		// new epoch and get a full inventory.
		NeedEpoch: !a.seq.Exists() || !a.stExists,
	}, a.src, a.client, a.owners, a.st, a.log)
	e.Rotate = a.rotate
	return e
}

// rotate replaces the key pair (spec 8.1 routine rotation): write the new
// key to agent.key.next, register it with /rotate signed by the old key,
// then rename it into place. A crash in between leaves the old key
// working; the server asks again.
func (a *agent) rotate(ctx context.Context) error {
	next := filepath.Join(a.stateDir, state.NextKeyFile)
	key, err := state.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := state.WriteKey(next, key); err != nil {
		return err
	}
	resp, err := a.client.Rotate(ctx, key.Public().(ed25519.PublicKey))
	if err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, filepath.Join(a.stateDir, state.KeyFile)); err != nil {
		return err
	}
	a.id.KeyID = string(resp.KeyID)
	if err := a.id.Save(filepath.Join(a.stateDir, state.IdentityFile)); err != nil {
		return err
	}
	a.key = key
	a.client.SetKey(key, a.id.SourceID, a.id.KeyID)
	a.log.Info("key rotated", "key_id", a.id.KeyID)
	return nil
}

func cmdRun(args []string, stderr io.Writer) int {
	fs := newFlagSet("run", stderr)
	configPath := fs.String("config", config.DefaultPath, "config file")
	stateDir := fs.String("state-dir", config.StateDir, "state directory")
	if fs.Parse(args) != nil {
		return 2
	}
	a, err := loadAgent(*configPath, *stateDir, nil)
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent:", err)
		return 1
	}
	os.Remove(filepath.Join(*stateDir, state.NextKeyFile)) // an interrupted rotation
	a.log.Info("starting", "version", version.Version, "source", a.src.Kind(), "url", a.cfg.URL,
		"source_id", a.id.SourceID, "interval", a.cfg.Interval, "resync", a.cfg.Resync)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.engine().Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		a.log.Error("stopped", "err", err)
		return 1
	}
	a.log.Info("stopped")
	return 0
}
