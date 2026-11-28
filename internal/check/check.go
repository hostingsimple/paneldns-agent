// Package check implements `paneldns-agent --check` (spec 7.7): a
// read-only self-test. It reads the config, zone data and owner file, and
// calls only the heartbeat endpoint; it pushes nothing and writes no
// state other than taking one sequence number.
package check

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/filter"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/version"
)

// Status of one check.
type Status string

// Statuses.
const (
	OK   Status = "ok"
	Info Status = "info"
	Warn Status = "warn"
	Fail Status = "fail"
)

// Item is one line of the report.
type Item struct {
	Section string `json:"section"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

// ZoneDump is the output of --check --zone.
type ZoneDump struct {
	Name           string `json:"name"`
	Hash           string `json:"hash"`
	Serial         uint32 `json:"serial"`
	SignedAtSource bool   `json:"signed_at_source"`
	Stripped       int    `json:"stripped_records"`
	Records        int    `json:"records"`
	Text           string `json:"text"`
}

// Result is the whole report.
type Result struct {
	Version string    `json:"version"`
	Items   []Item    `json:"checks"`
	Zone    *ZoneDump `json:"zone,omitempty"`
}

// Failed reports whether any check failed.
func (r *Result) Failed() bool {
	for _, i := range r.Items {
		if i.Status == Fail {
			return true
		}
	}
	return false
}

func (r *Result) add(section string, st Status, format string, a ...any) {
	r.Items = append(r.Items, Item{Section: section, Status: st, Message: fmt.Sprintf(format, a...)})
}

// WriteText prints the report for a person.
func (r *Result) WriteText(w io.Writer) {
	fmt.Fprintf(w, "paneldns-agent %s self-check\n", r.Version)
	section := ""
	for _, i := range r.Items {
		if i.Section != section {
			section = i.Section
			fmt.Fprintf(w, "\n[%s]\n", section)
		}
		fmt.Fprintf(w, "  %-4s %s\n", strings.ToUpper(string(i.Status)), i.Message)
	}
	if r.Zone != nil {
		fmt.Fprintf(w, "\n[zone %s]\n  hash %s  serial %d  records %d  stripped %d  signed_at_source %v\n\n%s",
			r.Zone.Name, r.Zone.Hash, r.Zone.Serial, r.Zone.Records, r.Zone.Stripped, r.Zone.SignedAtSource, r.Zone.Text)
	}
	if r.Failed() {
		fmt.Fprintln(w, "\nResult: FAILED")
	} else {
		fmt.Fprintln(w, "\nResult: OK")
	}
}

// WriteJSON prints the report as JSON (a support bundle).
func (r *Result) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// FileMode describes a file for the mode checks.
type FileMode struct {
	Mode       fs.FileMode
	User       string // owner name ("" when unknown)
	Group      string
	Accessible bool
}

// Env is everything --check looks at; the command fills it in.
type Env struct {
	ConfigPath string
	StateDir   string
	Config     *config.Config
	ConfigErr  error
	Identity   *state.Identity
	IdentErr   error
	KeyErr     error
	State      *state.State
	Sequence   *state.Sequence
	Source     source.Source
	Owners     *owners.File
	// Upload sends the report to PanelDNS (D-35); nil when not enrolled.
	Upload func(ctx context.Context, r *protocol.CheckReportRequest) (*protocol.CheckReportResponse, error)
	// Heartbeat sends the --check heartbeat; nil skips the network checks.
	Heartbeat  func(ctx context.Context, r *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error)
	ServerDate func() (server, local time.Time)
	Lookup     func(ctx context.Context, host string) error
	Stat       func(path string) (FileMode, error)
	OpenCheck  func(path string) error // can the agent read this file?
	Hostname   string
	// Systemctl runs systemctl and returns its output, trimmed; nil skips
	// the ACL watcher check (not a systemd host).
	Systemctl func(args ...string) (string, error)
	// WatchDropIn is the ACL watcher's drop-in; ReadFile reads it.
	WatchDropIn string
	ReadFile    func(string) ([]byte, error)
	// UnitDropIns returns the agent unit's drop-ins that differ from what
	// `update-units` would write for these zone paths (resolvers or zone
	// locations changed since enrol); nil skips the check.
	UnitDropIns func(zonePaths []string) []string
	Zone        string // --zone
	Sample      int    // zones read and parsed (default 5)
	Now         func() time.Time
}

// Run performs the checks.
func Run(ctx context.Context, env Env) *Result {
	r := &Result{Version: version.Version}
	if env.Sample == 0 {
		env.Sample = 5
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Config == nil {
		r.add("config", Fail, "%s: %v", env.ConfigPath, env.ConfigErr)
		return r
	}
	cfg := *env.Config
	if env.Zone != "" {
		zoneOnly(ctx, r, env)
		return r
	}
	checkConfig(r, env)
	listing := checkBackend(ctx, r, env, cfg)
	checkACLWatcher(r, env, listing)
	checkUnitDropIns(r, env, cfg, listing)
	checkOwners(r, env, listing)
	checkLastRun(r, env)
	checkServer(ctx, r, env, cfg, listing)
	return r
}

func checkConfig(r *Result, env Env) {
	r.add("config", OK, "%s parsed (zone source %s, interval %ds, resync %ds)", env.ConfigPath, env.Config.ZoneSource, env.Config.Interval, env.Config.Resync)
	for _, w := range env.Config.Warnings {
		r.add("config", Warn, "%s", w)
	}
	if env.Stat == nil {
		return
	}
	modeCheck := func(path string, want fs.FileMode, user, group string) {
		fm, err := env.Stat(path)
		if err != nil {
			r.add("config", Fail, "%s: %v", path, err)
			return
		}
		ok := fm.Mode.Perm() == want && (user == "" || fm.User == "" || fm.User == user) && (group == "" || fm.Group == "" || fm.Group == group)
		owner := ""
		if fm.User != "" {
			owner = fmt.Sprintf(", owner %s:%s", fm.User, fm.Group)
		}
		if ok {
			r.add("config", OK, "%s mode %04o%s", path, fm.Mode.Perm(), owner)
		} else {
			r.add("config", Fail, "%s mode %04o%s; must be %04o %s:%s", path, fm.Mode.Perm(), owner, want, user, group)
		}
	}
	modeCheck(env.ConfigPath, 0o640, "root", "paneldns-agent")
	if env.IdentErr == nil {
		modeCheck(env.StateDir+"/"+state.KeyFile, 0o600, "paneldns-agent", "")
	}
}

func checkBackend(ctx context.Context, r *Result, env Env, cfg config.Config) *source.Listing {
	if env.Source == nil {
		r.add("zones", Fail, "no zone source")
		return nil
	}
	listing, err := env.Source.List(ctx)
	if err != nil {
		r.add("zones", Fail, "listing zones (%s): %v", env.Source.Kind(), err)
		return nil
	}
	switch b := env.Source.(type) {
	case *source.BIND:
		r.add("zones", OK, "backend bind: %s, directory %s", cfg.ZonesFile, listing.Directory)
		if cfg.Chroot != "" {
			r.add("zones", Info, "chroot %s", cfg.Chroot)
		}
		if p := b.CompilezonePath(); p != "" {
			r.add("zones", OK, "reader: %s", p)
		} else {
			r.add("zones", Warn, "reader: built-in parser (named-compilezone not found: journals and $GENERATE can't be read)")
		}
	case *source.PowerDNS:
		r.add("zones", OK, "backend powerdns-api: %s", cfg.PDNSAPIURL)
	}
	if listing.View != "" {
		r.add("zones", Info, "view in use: %s", listing.View)
	}
	run, detail := env.Source.Running(ctx)
	st := OK
	if run != source.RunningYes {
		st = Warn
	}
	r.add("zones", st, "DNS server %s (%s)", run, detail)
	for _, w := range listing.Warnings {
		r.add("zones", Warn, "%s", w)
	}
	if listing.InlineKey != nil {
		r.add("zones", Fail, "%v", listing.InlineKey)
	}
	for _, u := range listing.Unreadable {
		r.add("zones", Info, "not readable (expected for key files): %s", u)
	}

	ex := filter.NewExcluder(cfg.Exclude)
	var synced []source.ZoneRef
	system, excluded := 0, 0
	for _, z := range listing.Zones {
		switch {
		case filter.IsSystem(z.Name):
			system++
		case ex.Match(z.Name) != "":
			excluded++
		default:
			synced = append(synced, z)
		}
	}
	r.add("zones", OK, "%d zones to sync, %d excluded locally, %d system zones skipped, %d non-primary zones skipped", len(synced), excluded, system, listing.Skipped)
	if len(listing.Other) > 0 {
		var names []string
		for n, views := range listing.Other {
			names = append(names, fmt.Sprintf("%s (in view %s, not synced)", n, strings.Join(views, ", ")))
		}
		sort.Strings(names)
		r.add("zones", Info, "%d zones only in other views: %s", len(names), limitList(names, 10))
	}
	if b, ok := env.Source.(*source.BIND); ok && env.OpenCheck != nil {
		var denied []string
		for _, z := range synced {
			if err := env.OpenCheck(b.ZoneFile(z)); err != nil && errors.Is(err, fs.ErrPermission) {
				denied = append(denied, z.Name)
			}
		}
		if len(denied) > 0 {
			r.add("zones", Fail, "%d zone files are not readable by the agent (ACL missing, or reset or masked by the panel?): %s; as root run: paneldns-agent fix-acls (the %s watcher does this automatically when enabled)", len(denied), limitList(denied, 10), ACLPathUnit)
		}
	}
	n := min(env.Sample, len(synced))
	for _, z := range synced[:n] {
		c, sr, err := engine.Prepare(ctx, env.Source, z)
		if err != nil {
			r.add("zones", Fail, "%s: %v", z.Name, err)
			continue
		}
		note := ""
		if sr.SignedAtSource {
			note = ", signed at the source (DNSSEC records stripped)"
		}
		r.add("zones", OK, "%s: %d records, serial %d, %s%s", z.Name, len(c.Lines), c.Serial, c.Hash, note)
	}
	return listing
}

// ACLPathUnit is the root ACL watcher (docs/DECISIONS.md D-30).
const ACLPathUnit = "paneldns-agent-acl.path"

// checkACLWatcher reports whether the root ACL watcher runs, and whether
// it watches every zone directory.
func checkACLWatcher(r *Result, env Env, listing *source.Listing) {
	if env.Systemctl == nil {
		return
	}
	active, aerr := env.Systemctl("is-active", ACLPathUnit)
	enabled, _ := env.Systemctl("is-enabled", ACLPathUnit)
	if aerr != nil && active == "" {
		r.add("zones", Info, "ACL watcher %s: can't ask systemd (%v)", ACLPathUnit, aerr)
		return
	}
	firstLine := func(s string) string {
		s, _, _ = strings.Cut(s, "\n")
		if strings.Contains(s, "No such file") || strings.Contains(s, "not found") {
			return "not installed"
		}
		return s
	}
	active, enabled = firstLine(active), firstLine(enabled)
	if active != "active" || enabled != "enabled" {
		r.add("zones", Warn, "ACL watcher %s: %s, %s; zone files the panel creates may stay unreadable by the agent. As root run: paneldns-agent fix-acls && systemctl enable --now %s", ACLPathUnit, active, enabled, ACLPathUnit)
		return
	}
	r.add("zones", OK, "ACL watcher %s: active, enabled", ACLPathUnit)
	b, ok := env.Source.(*source.BIND)
	if !ok || listing == nil || env.ReadFile == nil || env.WatchDropIn == "" {
		return
	}
	text, err := env.ReadFile(env.WatchDropIn)
	if err != nil {
		r.add("zones", Warn, "ACL watcher: %v", err)
		return
	}
	watched := map[string]bool{}
	for _, line := range strings.Split(string(text), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PathChanged="); ok {
			watched[v] = true
		}
	}
	missing := map[string]bool{}
	for _, z := range listing.Zones {
		if d := path.Dir(b.ZoneFile(z)); !watched[d] {
			missing[d] = true
		}
	}
	if len(missing) > 0 {
		var dirs []string
		for d := range missing {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)
		r.add("zones", Warn, "zone directories the ACL watcher doesn't watch: %s; as root run: paneldns-agent fix-acls (it updates %s)", limitList(dirs, 10), env.WatchDropIn)
	}
}

// checkUnitDropIns warns when the agent unit's drop-ins are out of date:
// --check runs outside the unit, so it can read what the service can't
// when a resolver moved into a denied range or zones live under /home.
func checkUnitDropIns(r *Result, env Env, cfg config.Config, listing *source.Listing) {
	if env.UnitDropIns == nil {
		return
	}
	var paths []string
	if b, ok := env.Source.(*source.BIND); ok && listing != nil {
		paths = append(paths, cfg.ZonesFile, listing.Directory)
		for _, z := range listing.Zones {
			paths = append(paths, b.ZoneFile(z))
		}
	}
	if cfg.OwnersFile != "" {
		paths = append(paths, cfg.OwnersFile)
	}
	if stale := env.UnitDropIns(paths); len(stale) > 0 {
		r.add("config", Warn, "unit drop-ins out of date for this server (resolvers, PanelDNS address or zone locations changed): %s; as root run: paneldns-agent update-units && systemctl restart paneldns-agent", strings.Join(stale, ", "))
	}
}

func limitList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, "; ")
	}
	return strings.Join(s[:n], "; ") + fmt.Sprintf("; and %d more", len(s)-n)
}

func checkOwners(r *Result, env Env, listing *source.Listing) {
	if env.Owners == nil {
		r.add("owners", Info, "no OWNERS_FILE set: zones are sent without an owner")
		return
	}
	if err := env.Owners.Reload(); err != nil {
		r.add("owners", Fail, "%v", err)
		return
	}
	st, _ := env.Owners.Stats()
	r.add("owners", OK, "%s readable: %d entries (%d lines skipped)", env.Owners.Path, st.Entries, st.Skipped)
	if listing != nil {
		have, total := 0, 0
		for _, z := range listing.Zones {
			if filter.IsSystem(z.Name) {
				continue
			}
			total++
			if _, ok := env.Owners.Owner(z.Name); ok {
				have++
			}
		}
		r.add("owners", Info, "%d of %d zones have an owner", have, total)
	}
}

// checkLastRun reports what the running service recorded.
func checkLastRun(r *Result, env Env) {
	if env.State == nil {
		return
	}
	var failed, refused, skipped, signed []string
	for name, zs := range env.State.Zones {
		switch {
		case zs.Error != "":
			failed = append(failed, name+": "+zs.Error)
		case zs.Status == protocol.StatusRefused:
			refused = append(refused, name+": "+zs.Reason)
		case zs.Status == protocol.StatusSkippedRecords:
			skipped = append(skipped, name+": "+zs.Reason)
		}
		if zs.Signed {
			signed = append(signed, name)
		}
	}
	for _, l := range [][]string{failed, refused, skipped, signed} {
		sort.Strings(l)
	}
	if env.State.ScanCompletedAt > 0 {
		r.add("last run", Info, "last scan completed %s", time.Unix(env.State.ScanCompletedAt, 0).UTC().Format(time.RFC3339))
	} else {
		r.add("last run", Info, "the service has not completed a scan yet")
	}
	if env.State.LastInventoryAt > 0 {
		r.add("last run", Info, "last inventory acknowledged %s (%d zones)", time.Unix(env.State.LastInventoryAt, 0).UTC().Format(time.RFC3339), env.State.LastInventoryCount)
	}
	if len(failed) > 0 {
		r.add("last run", Fail, "%d zones failed to read: %s", len(failed), limitList(failed, 10))
	}
	if len(refused) > 0 {
		r.add("last run", Warn, "%d zones refused by PanelDNS: %s", len(refused), limitList(refused, 10))
	}
	if len(skipped) > 0 {
		r.add("last run", Warn, "%d zones had records skipped by PanelDNS: %s", len(skipped), limitList(skipped, 10))
	}
	if len(signed) > 0 {
		r.add("last run", Info, "%d zones signed at the source (DNSSEC records stripped): %s", len(signed), limitList(signed, 10))
	}
	if n := len(env.State.Deletions); n > 0 {
		r.add("last run", Info, "%d deletions waiting to be sent", n)
	}
}

func checkServer(ctx context.Context, r *Result, env Env, cfg config.Config, listing *source.Listing) {
	if env.IdentErr != nil {
		r.add("panel sync", Fail, "%v", env.IdentErr)
		return
	}
	if env.KeyErr != nil {
		r.add("panel sync", Fail, "key: %v", env.KeyErr)
		return
	}
	id := env.Identity
	r.add("panel sync", Info, "enrolled as source %s, key %s", id.SourceID, id.KeyID)
	if env.Sequence != nil {
		if e, s, err := env.Sequence.Current(); err != nil {
			r.add("panel sync", Warn, "sequence: %v (the service asks for a new epoch)", err)
		} else {
			r.add("panel sync", Info, "epoch %d, last sequence %d", e, s)
		}
	}
	u, _ := url.Parse(cfg.URL)
	if env.Lookup != nil && u != nil {
		if err := env.Lookup(ctx, u.Hostname()); err != nil {
			r.add("panel sync", Fail, "can't resolve %s: %v (if /etc/resolv.conf names a loopback, link-local or private resolver, the unit needs IPAddressAllow= for it: as root run paneldns-agent update-units)", u.Hostname(), err)
			return
		}
	}
	if env.Heartbeat == nil {
		return
	}
	hb := &protocol.HeartbeatRequest{
		AgentVersion: version.Version, Hostname: env.Hostname, Backend: cfg.ZoneSource,
		Errors: []protocol.ZoneError{}, PublicIPs: []string{}, Check: true,
	}
	if env.State != nil {
		hb.ScanStartedAt, hb.ScanCompletedAt = env.State.ScanStartedAt, env.State.ScanCompletedAt
		for _, zs := range env.State.Zones {
			if zs.Excluded != "" {
				hb.ExcludedCount++
			} else {
				hb.ZoneCount++
			}
		}
	}
	if listing != nil {
		hb.View = listing.View
	}
	resp, err := env.Heartbeat(ctx, hb)
	if err != nil {
		var ae *protocol.APIError
		var cert *x509.UnknownAuthorityError
		var host x509.HostnameError
		var inv x509.CertificateInvalidError
		switch {
		case errors.As(err, &cert) || errors.As(err, &host) || errors.As(err, &inv) || strings.Contains(err.Error(), "certificate"):
			r.add("panel sync", Fail, "TLS certificate of %s not valid: %v", cfg.URL, err)
		case errors.As(err, &ae) && ae.Status == 0:
			r.add("panel sync", Fail, "%s not reachable over HTTPS: %v", cfg.URL, ae.Err)
		case errors.As(err, &ae):
			r.add("panel sync", Fail, "%s", ae.Explain())
		default:
			r.add("panel sync", Fail, "heartbeat: %v", err)
		}
		return
	}
	r.add("panel sync", OK, "%s reachable over HTTPS, certificate valid", cfg.URL)
	r.add("panel sync", OK, "key accepted, epoch current, IP allowlist passed")
	if resp.ClusterName != "" || resp.SourceName != "" {
		r.add("panel sync", Info, "setup %q, server %q", resp.ClusterName, resp.SourceName)
	}
	if env.ServerDate != nil {
		srv, local := env.ServerDate()
		if !srv.IsZero() {
			skew := local.Sub(srv)
			if skew < 0 {
				skew = -skew
			}
			if skew > 2*time.Minute {
				r.add("panel sync", Fail, "clock skew %s against PanelDNS (must be under 2 minutes)", skew.Round(time.Second))
			} else {
				r.add("panel sync", OK, "clock skew %s", skew.Round(time.Second))
			}
		}
	}
	switch {
	case resp.MinimumVersion != "" && version.Less(version.Version, resp.MinimumVersion):
		grace := "now"
		if resp.MinimumGraceUntil > 0 {
			grace = "by " + time.Unix(resp.MinimumGraceUntil, 0).UTC().Format("2006-01-02")
		}
		r.add("version", Fail, "%s is below the minimum %s: update required %s", version.Version, resp.MinimumVersion, grace)
	case resp.LatestVersion != "" && version.Less(version.Version, resp.LatestVersion):
		r.add("version", Warn, "%s; latest is %s", version.Version, resp.LatestVersion)
	default:
		latest := resp.LatestVersion
		if latest == "" {
			latest = "not reported"
		}
		r.add("version", OK, "%s (latest %s)", version.Version, latest)
	}
}

func zoneOnly(ctx context.Context, r *Result, env Env) {
	name := filter.Normalize(env.Zone)
	if env.Source == nil {
		r.add("zone", Fail, "no zone source")
		return
	}
	listing, err := env.Source.List(ctx)
	if err != nil {
		r.add("zone", Fail, "listing zones: %v", err)
		return
	}
	for _, z := range listing.Zones {
		if z.Name != name {
			continue
		}
		if filter.IsSystem(name) {
			r.add("zone", Warn, "%s is a system zone and is never sent", name)
		}
		c, sr, err := engine.Prepare(ctx, env.Source, z)
		if err != nil {
			r.add("zone", Fail, "%s: %v", name, err)
			return
		}
		r.Zone = &ZoneDump{Name: name, Hash: c.Hash, Serial: c.Serial, SignedAtSource: sr.SignedAtSource, Stripped: sr.Removed, Records: len(c.Lines), Text: c.Text}
		r.add("zone", OK, "%s read and canonicalised", name)
		return
	}
	if views, ok := listing.Other[name]; ok {
		r.add("zone", Fail, "%s is only in view %s, which is not synced", name, strings.Join(views, ", "))
		return
	}
	r.add("zone", Fail, "%s is not a primary zone of this server", name)
}

// DefaultLookup resolves a host name.
func DefaultLookup(ctx context.Context, host string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(ctx, host)
	return err
}

// DefaultOpenCheck opens a file for reading and closes it.
func DefaultOpenCheck(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	return f.Close()
}
