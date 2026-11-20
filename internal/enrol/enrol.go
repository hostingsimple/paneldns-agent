package enrol

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/host"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/version"
)

// User is the system user the service runs as.
const User = "paneldns-agent"

// Options configures Run.
type Options struct {
	URL        string
	Code       string
	ConfigPath string
	StateDir   string
	Out        io.Writer

	// Seams for tests.
	HTTP         *http.Client
	Detect       func() (Detected, error)
	SkipRootTest bool
	// After runs once the source is enrolled (ACLs, --check, unit).
	After func(ctx context.Context, cfg config.Config, d Detected) error
}

// Result is what enrolment produced.
type Result struct {
	Identity *state.Identity
	Detected Detected
	Epoch    uint64
}

// Run enrols this server.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.ConfigPath == "" {
		o.ConfigPath = config.DefaultPath
	}
	if o.StateDir == "" {
		o.StateDir = config.StateDir
	}
	if !o.SkipRootTest && runtime.GOOS == "linux" && os.Geteuid() != 0 {
		return nil, errors.New("enrol must run as root (it reads named's files and sets read ACLs for the agent user)")
	}
	if err := config.ValidateURL(o.URL); err != nil {
		return nil, fmt.Errorf("--url: %w", err)
	}
	code := strings.Join(strings.Fields(o.Code), "")
	if code == "" {
		return nil, errors.New("--code is required: copy it from the PanelDNS dashboard (valid 15 minutes, single use)")
	}
	detect := o.Detect
	if detect == nil {
		detect = DetectAll
	}
	d, err := detect()
	if err != nil {
		return nil, fmt.Errorf("detecting the zone source: %w", err)
	}
	fmt.Fprintf(o.Out, "Zone source: %s", d.ZoneSource)
	if d.ZonesFile != "" {
		fmt.Fprintf(o.Out, " (%s)", d.ZonesFile)
	}
	fmt.Fprintln(o.Out)
	for _, n := range d.Notes {
		fmt.Fprintln(o.Out, "  "+n)
	}

	// Build and validate the config before contacting PanelDNS.
	text := ""
	if b, err := os.ReadFile(o.ConfigPath); err == nil {
		text = string(b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	vals := map[string]string{
		"PANELDNS_URL": strings.TrimRight(o.URL, "/"),
		"ZONE_SOURCE":  d.ZoneSource,
		"OWNERS_FILE":  d.OwnersFile,
	}
	switch d.ZoneSource {
	case config.SourceBIND:
		vals["ZONES_FILE"], vals["CHROOT"] = d.ZonesFile, d.Chroot
	case config.SourcePowerDNSAPI:
		vals["PDNS_API_URL"] = d.PDNSAPIURL
		vals["PDNS_API_KEY_FILE"] = filepath.ToSlash(filepath.Join(o.StateDir, "pdns-api-key"))
	}
	newText := config.SetValues(text, vals)
	cfg, err := config.Parse(newText)
	if err != nil {
		return nil, fmt.Errorf("the detected configuration is not valid: %w", err)
	}

	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return nil, err
	}
	key, err := state.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	client := &protocol.Client{BaseURL: cfg.URL, HTTP: o.HTTP}
	resp, err := client.Enrol(ctx, &protocol.EnrolRequest{
		Code:         code,
		PublicKey:    protocol.EncodePublicKey(key.Public().(ed25519.PublicKey)),
		Hostname:     host.Hostname(),
		OS:           host.OS(),
		Backend:      d.ZoneSource,
		Panel:        host.Panel(),
		PublicIPs:    host.PublicIPs(),
		AgentVersion: version.Version,
	})
	if err != nil {
		var ae *protocol.APIError
		if errors.As(err, &ae) {
			switch {
			case ae.Status == http.StatusForbidden && ae.Code == protocol.ErrIPRefused:
				return nil, errors.New(ae.Explain())
			case ae.Status == http.StatusUnauthorized || ae.Status == http.StatusNotFound || ae.Status == http.StatusGone:
				return nil, fmt.Errorf("PanelDNS did not accept the enrolment code (expired, used, or mistyped; codes last 15 minutes): %s", ae.Error())
			case ae.Status == http.StatusTooManyRequests:
				return nil, fmt.Errorf("too many enrolment attempts; wait a minute and try again with a fresh code")
			}
		}
		return nil, fmt.Errorf("enrolment failed: %w", err)
	}

	// Write the files. A re-enrol replaces the key and starts a new epoch
	// with an empty state, so the first run sends a full inventory.
	p := func(n string) string { return filepath.Join(o.StateDir, n) }
	id := &state.Identity{
		URL: cfg.URL, SourceID: string(resp.SourceID), KeyID: string(resp.KeyID),
		ClusterName: resp.ClusterName, SourceName: resp.SourceName, EnrolledAt: time.Now().Unix(),
	}
	os.Remove(p(state.NextKeyFile))
	if err := state.WriteKey(p(state.KeyFile), key); err != nil {
		return nil, err
	}
	if err := id.Save(p(state.IdentityFile)); err != nil {
		return nil, err
	}
	seq := &state.Sequence{Path: p(state.SequenceFile)}
	if err := seq.SetEpoch(resp.Epoch); err != nil {
		return nil, err
	}
	if err := state.New().Save(p(state.StateFile)); err != nil {
		return nil, err
	}
	if d.ZoneSource == config.SourcePowerDNSAPI && d.PDNSAPIKey != "" {
		if err := state.WriteAtomic(p("pdns-api-key"), []byte(d.PDNSAPIKey+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	if err := writeConfig(o.ConfigPath, newText); err != nil {
		return nil, err
	}
	if err := chownState(o.StateDir); err != nil {
		fmt.Fprintf(o.Out, "warning: %v\n", err)
	}
	fmt.Fprintf(o.Out, "Enrolled as source %s", id.SourceID)
	if id.SourceName != "" {
		fmt.Fprintf(o.Out, " (%s)", id.SourceName)
	}
	if id.ClusterName != "" {
		fmt.Fprintf(o.Out, " in setup %q", id.ClusterName)
	}
	fmt.Fprintln(o.Out, ".")
	if len(resp.AllowedIPs) > 0 {
		fmt.Fprintf(o.Out, "IP allowlist: %s (change it in the dashboard if this server sends from other addresses)\n", strings.Join(resp.AllowedIPs, ", "))
	}
	res := &Result{Identity: id, Detected: d, Epoch: resp.Epoch}
	if o.After != nil {
		if err := o.After(ctx, cfg, d); err != nil {
			return res, err
		}
	}
	return res, nil
}

// writeConfig writes the config file 0640 root:paneldns-agent.
func writeConfig(path, text string) error {
	if err := state.WriteAtomic(path, []byte(text), 0o640); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return nil
	}
	if g, err := user.LookupGroup(User); err == nil {
		gid, _ := strconv.Atoi(g.Gid)
		return os.Chown(path, 0, gid)
	}
	return nil
}

// chownState gives the state directory and its files to the agent user.
func chownState(dir string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	u, err := user.Lookup(User)
	if err != nil {
		return fmt.Errorf("user %s not found (the package creates it); files in %s stay owned by root", User, dir)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// DetectAll detects the zone source and the panel's owner file.
var DetectAll = func() (Detected, error) {
	d, err := DetectSource()
	if err != nil {
		return d, err
	}
	panel := host.Panel()
	d.OwnersFile = owners.Detect(panel, Root)
	if d.OwnersFile != "" {
		d.Notes = append(d.Notes, fmt.Sprintf("owner file %s (%s)", d.OwnersFile, panel))
	} else {
		d.Notes = append(d.Notes, fmt.Sprintf("no owner file for panel %q; zones are sent without an owner", panel))
	}
	return d, nil
}
