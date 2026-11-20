// Package engine is the agent's push cycle (spec 7.4, 7.5): scan the
// zones, work out what changed, and send zones, deletions, inventories
// and heartbeats with retries and backoff. It keeps only the latest state
// while PanelDNS is unreachable, never a backlog.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/backoff"
	"github.com/hostingsimple/paneldns-agent/internal/filter"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/version"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// API is the ingest API as the engine uses it (internal/protocol.Client).
type API interface {
	Epoch(ctx context.Context) (*protocol.EpochResponse, error)
	Heartbeat(ctx context.Context, r *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error)
	Inventory(ctx context.Context, r *protocol.InventoryRequest) (*protocol.InventoryResponse, error)
	Zones(ctx context.Context, r *protocol.ZonesRequest) (*protocol.ZonesResponse, error)
	Deletions(ctx context.Context, r *protocol.DeletionsRequest) (*protocol.DeletionsResponse, error)
}

// Owners maps zone names to panel account names (internal/owners).
type Owners interface {
	Reload() error
	Owner(zone string) (string, bool)
}

// Host describes this server in heartbeats.
type Host struct {
	Hostname  string
	OS        string
	Panel     string
	PublicIPs func() []string
}

// Config configures an Engine.
type Config struct {
	Interval  time.Duration
	Resync    time.Duration
	Exclude   []string
	StatePath string // "" keeps state in memory only (tests)
	Host      Host
	// NeedEpoch makes the first cycle call POST /epoch (state was lost).
	NeedEpoch bool
	// CacheBytes bounds zone text kept between a scan and its push;
	// zones beyond it are read again when sent.
	CacheBytes int
}

// Engine runs the push cycle. It is not safe for concurrent use.
type Engine struct {
	cfg    Config
	src    source.Source
	api    API
	owners Owners
	log    *slog.Logger

	// Now and Rotate may be set by the caller. Rotate is called when a
	// heartbeat answer asks for key rotation.
	Now    func() time.Time
	Rotate func(ctx context.Context) error

	st         *state.State
	overlay    protocol.Overlay
	refs       map[string]source.ZoneRef
	cache      map[string]*prepared
	cacheBytes int
	listing    *source.Listing
	listingOK  bool
	scanErr    error

	inventoryDue bool
	fullScanDone bool
	needEpoch    bool
	rotate       bool

	backoff     backoff.Backoff
	nextAttempt time.Time
	lastErr     error
	lastHB      *protocol.HeartbeatResponse
}

type prepared struct {
	hash   string
	text   string
	serial uint32
	signed bool
}

// New creates an Engine with st as its starting state.
func New(cfg Config, src source.Source, api API, owners Owners, st *state.State, log *slog.Logger) *Engine {
	if cfg.CacheBytes == 0 {
		cfg.CacheBytes = protocol.MaxBatchBytes
	}
	if st == nil {
		st = state.New()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Engine{
		cfg: cfg, src: src, api: api, owners: owners, log: log, st: st,
		refs: map[string]source.ZoneRef{}, cache: map[string]*prepared{},
		inventoryDue: true, needEpoch: cfg.NeedEpoch,
		Now: time.Now,
	}
}

// State returns the current state (for --check and tests).
func (e *Engine) State() *state.State { return e.st }

// LastError returns the last cycle error, or nil.
func (e *Engine) LastError() error { return e.lastErr }

// LastHeartbeat returns the last heartbeat answer.
func (e *Engine) LastHeartbeat() *protocol.HeartbeatResponse { return e.lastHB }

// NextAttempt is when the next cycle may run after a failure.
func (e *Engine) NextAttempt() time.Time { return e.nextAttempt }

// InventoryDue reports whether a full inventory is pending.
func (e *Engine) InventoryDue() bool { return e.inventoryDue }

func (e *Engine) interval() time.Duration {
	if e.overlay.Interval >= 15 {
		return time.Duration(e.overlay.Interval) * time.Second
	}
	return e.cfg.Interval
}

func (e *Engine) resync() time.Duration {
	if e.overlay.Resync >= 60 {
		return time.Duration(e.overlay.Resync) * time.Second
	}
	return e.cfg.Resync
}

func (e *Engine) save() {
	if e.cfg.StatePath == "" {
		return
	}
	if err := e.st.Save(e.cfg.StatePath); err != nil {
		e.log.Error("saving state", "path", e.cfg.StatePath, "err", err)
	}
}

// Scan lists the zones and reads every zone whose fingerprint changed
// (every zone when full is true, before an inventory). It updates the
// local state only; nothing is sent.
func (e *Engine) Scan(ctx context.Context, full bool) error {
	start := e.Now()
	err := e.scan(ctx, full, start)
	e.scanErr = err
	if err != nil {
		e.listingOK = false
		e.log.Error("scan failed; nothing is sent until a scan succeeds", "err", err)
		return err
	}
	e.listingOK = true
	if full {
		e.fullScanDone = true
	}
	e.st.ScanStartedAt = start.Unix()
	e.st.ScanCompletedAt = e.Now().Unix()
	e.save()
	return nil
}

func (e *Engine) scan(ctx context.Context, full bool, start time.Time) error {
	listing, err := e.src.List(ctx)
	if err != nil {
		return err
	}
	if e.owners != nil {
		if err := e.owners.Reload(); err != nil {
			e.log.Warn("owner file", "err", err)
		}
	}
	ex := filter.NewExcluder(e.cfg.Exclude, e.overlay.Exclude)
	present := map[string]source.ZoneRef{}
	excluded := map[string]string{}
	declared := map[string]bool{}
	for _, z := range listing.Zones {
		if filter.IsSystem(z.Name) {
			continue
		}
		if p := ex.Match(z.Name); p != "" {
			excluded[z.Name] = p
			continue
		}
		present[z.Name] = z
		if z.DeclaredIn != "" {
			declared[z.DeclaredIn] = true
		}
	}

	// D-14: a config file that declared zones last time and can't be read
	// now would make its zones look deleted.
	unreadable := map[string]bool{}
	for _, f := range listing.Unreadable {
		unreadable[f] = true
	}
	for _, f := range e.st.ConfigFiles {
		if unreadable[f] {
			return fmt.Errorf("%s declared zones in the last scan but can't be read now; not reporting until it is readable again", f)
		}
	}
	// Spec 7.4 empty-inventory guard.
	n, last := len(present), e.st.LastInventoryCount
	if n == 0 || (last > 0 && n*2 < last) {
		r, detail := e.src.Running(ctx)
		if r != source.RunningYes {
			return fmt.Errorf("found %d zones (last inventory had %d) and the DNS server is %s (%s); not reporting an inventory or deletions until this is resolved", n, last, r, detail)
		}
	}

	names := make([]string, 0, len(present))
	for name := range present {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ref := present[name]
		zs := e.st.Zones[name]
		if zs == nil {
			zs = &state.Zone{}
			e.st.Zones[name] = zs
		}
		if zs.Excluded != "" {
			zs.Excluded = ""
			e.inventoryDue = true
		}
		delete(e.st.Deletions, name)
		if e.owners != nil {
			owner, _ := e.owners.Owner(name)
			if zs.Acked != "" && owner != zs.Owner {
				zs.Acked = "" // resend so the server learns the new owner
			}
		}
		if !full && zs.Fingerprint == ref.Fingerprint && zs.Hash != "" && zs.Error == "" {
			continue
		}
		p, err := e.prepare(ctx, ref)
		if err != nil {
			if zs.Error != err.Error() {
				e.log.Warn("zone not read", "zone", name, "err", err)
			}
			zs.Error = err.Error()
			e.dropCache(name)
			continue
		}
		zs.Fingerprint, zs.Error = ref.Fingerprint, ""
		zs.Hash, zs.Serial, zs.Signed = p.hash, p.serial, p.signed
		if zs.Hash != zs.Acked && zs.Hash != zs.RefusedHash {
			e.putCache(name, p)
		} else {
			e.dropCache(name)
		}
	}
	for name, pattern := range excluded {
		zs := e.st.Zones[name]
		if zs == nil {
			zs = &state.Zone{}
			e.st.Zones[name] = zs
		}
		if zs.Excluded != pattern {
			zs.Excluded = pattern
			e.inventoryDue = true
		}
		delete(e.st.Deletions, name)
		e.dropCache(name)
	}
	for name, zs := range e.st.Zones {
		if _, ok := present[name]; ok {
			continue
		}
		if _, ok := excluded[name]; ok {
			continue
		}
		if zs.Acked != "" {
			e.st.Deletions[name] = true
		}
		if zs.Excluded != "" {
			e.inventoryDue = true
		}
		delete(e.st.Zones, name)
		e.dropCache(name)
	}
	e.st.ConfigFiles = e.st.ConfigFiles[:0]
	for f := range declared {
		e.st.ConfigFiles = append(e.st.ConfigFiles, f)
	}
	sort.Strings(e.st.ConfigFiles)
	e.refs = present
	e.listing = listing
	return nil
}

func (e *Engine) putCache(name string, p *prepared) {
	e.dropCache(name)
	if e.cacheBytes+len(p.text) > e.cfg.CacheBytes {
		return
	}
	e.cache[name] = p
	e.cacheBytes += len(p.text)
}

func (e *Engine) dropCache(name string) {
	if p, ok := e.cache[name]; ok {
		e.cacheBytes -= len(p.text)
		delete(e.cache, name)
	}
}

// Prepare reads one zone and returns its canonical form (also used by
// --check --zone).
func Prepare(ctx context.Context, src source.Source, ref source.ZoneRef) (*zonefile.Canonical, zonefile.StripResult, error) {
	rrs, err := src.Read(ctx, ref)
	if err != nil {
		return nil, zonefile.StripResult{}, err
	}
	rrs, sr := zonefile.Strip(rrs)
	c, err := zonefile.MakeCanonical(rrs, ref.Name)
	if err != nil {
		return nil, sr, err
	}
	if len(c.Text) > protocol.MaxZoneTextBytes {
		return nil, sr, fmt.Errorf("zone text is %d bytes, over the %d-byte limit", len(c.Text), protocol.MaxZoneTextBytes)
	}
	return c, sr, nil
}

func (e *Engine) prepare(ctx context.Context, ref source.ZoneRef) (*prepared, error) {
	c, sr, err := Prepare(ctx, e.src, ref)
	if err != nil {
		return nil, err
	}
	return &prepared{hash: c.Hash, text: c.Text, serial: c.Serial, signed: sr.SignedAtSource}, nil
}

// Cycle sends what the last scan found: the epoch request if needed, a
// full inventory when due, changed zones, deletions and a heartbeat. After
// a failure it does nothing until the backoff delay has passed.
func (e *Engine) Cycle(ctx context.Context) error {
	now := e.Now()
	if now.Before(e.nextAttempt) {
		return nil
	}
	err := e.cycle(ctx)
	if err == nil {
		e.backoff.Reset()
		e.nextAttempt = time.Time{}
		e.lastErr = nil
		e.save()
		return nil
	}
	e.lastErr = err
	e.save()
	var ae *protocol.APIError
	if errors.As(err, &ae) {
		e.log.Error("PanelDNS request failed", "err", ae.Error(), "what_to_do", ae.Explain())
		switch {
		case ae.Status == http.StatusUnauthorized || ae.Status == http.StatusUpgradeRequired:
			e.nextAttempt = now.Add(backoff.DefaultMax)
		default:
			e.nextAttempt = now.Add(e.backoff.After(ae.RetryAfter))
		}
	} else {
		e.log.Error("cycle failed", "err", err)
		e.nextAttempt = now.Add(e.backoff.After(0))
	}
	return err
}

func isEpochStale(err error) bool {
	var ae *protocol.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusConflict && ae.Code == protocol.ErrEpochStale
}

func (e *Engine) cycle(ctx context.Context) error {
	err := e.send(ctx)
	if isEpochStale(err) {
		e.log.Warn("PanelDNS reports a stale epoch; asking for a new one")
		e.needEpoch = true
		err = e.send(ctx)
	}
	return err
}

func (e *Engine) send(ctx context.Context) error {
	if e.needEpoch {
		if _, err := e.api.Epoch(ctx); err != nil {
			return err
		}
		e.needEpoch = false
		e.inventoryDue = true
		e.fullScanDone = false
		e.log.Info("new epoch issued; a full inventory follows")
	}
	if e.listingOK {
		if e.Now().Sub(time.Unix(e.st.LastInventoryAt, 0)) >= e.resync() {
			e.inventoryDue = true
		}
		if e.inventoryDue && e.fullScanDone {
			if err := e.sendInventory(ctx); err != nil {
				return err
			}
		}
		if err := e.pushZones(ctx); err != nil {
			return err
		}
		if err := e.sendDeletions(ctx); err != nil {
			return err
		}
	}
	if err := e.heartbeat(ctx, false); err != nil {
		return err
	}
	if e.rotate && e.Rotate != nil {
		if err := e.Rotate(ctx); err != nil {
			e.log.Error("key rotation failed; the old key keeps working", "err", err)
		} else {
			e.rotate = false
		}
	}
	return nil
}

// NeedsFullScan reports whether the next scan should re-read every zone.
func (e *Engine) NeedsFullScan() bool { return e.inventoryDue && !e.fullScanDone }

func sortedZones(m map[string]*state.Zone) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) sendInventory(ctx context.Context) error {
	var entries []protocol.InventoryEntry
	count := 0
	for _, name := range sortedZones(e.st.Zones) {
		zs := e.st.Zones[name]
		if zs.Excluded != "" {
			entries = append(entries, protocol.InventoryEntry{Name: name, Excluded: true})
			continue
		}
		count++
		entries = append(entries, protocol.InventoryEntry{Name: name, Hash: zs.Hash})
	}
	parts := (len(entries) + protocol.MaxInventoryNames - 1) / protocol.MaxInventoryNames
	if parts == 0 {
		parts = 1
	}
	id := inventoryID(e.st.ScanStartedAt)
	needed := 0
	for part := 1; part <= parts; part++ {
		lo := (part - 1) * protocol.MaxInventoryNames
		hi := min(lo+protocol.MaxInventoryNames, len(entries))
		req := &protocol.InventoryRequest{
			InventoryID: id, Part: part, Parts: parts,
			ScanStartedAt: e.st.ScanStartedAt, ScanCompletedAt: e.st.ScanCompletedAt,
			Zones: entries[lo:hi],
		}
		if req.Zones == nil {
			req.Zones = []protocol.InventoryEntry{}
		}
		resp, err := e.api.Inventory(ctx, req)
		if err != nil {
			return err
		}
		for _, n := range resp.Need {
			if zs, ok := e.st.Zones[filter.Normalize(n)]; ok && zs.Excluded == "" {
				zs.Acked, zs.RefusedHash = "", ""
				needed++
			}
		}
	}
	e.inventoryDue = false
	e.fullScanDone = false
	e.st.LastInventoryAt = e.Now().Unix()
	e.st.LastInventoryCount = count
	// An inventory implies every deletion (spec 8.3).
	e.st.Deletions = map[string]bool{}
	e.log.Info("inventory sent", "zones", count, "excluded", len(entries)-count, "server_needs", needed)
	return nil
}

func inventoryID(scan int64) string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%d-%s", scan, hex.EncodeToString(b))
}

func (e *Engine) ownerPtr(name string) (*string, string) {
	if e.owners == nil {
		return nil, ""
	}
	if o, ok := e.owners.Owner(name); ok {
		return &o, o
	}
	return nil, ""
}

func (e *Engine) pending() []string {
	var out []string
	for _, name := range sortedZones(e.st.Zones) {
		zs := e.st.Zones[name]
		if zs.Excluded == "" && zs.Error == "" && zs.Hash != "" && zs.Hash != zs.Acked && zs.Hash != zs.RefusedHash {
			out = append(out, name)
		}
	}
	return out
}

func (e *Engine) pushZones(ctx context.Context) error {
	names := e.pending()
	var batch []protocol.ZonePush
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := e.sendBatch(ctx, batch)
		batch, size = nil, 0
		return err
	}
	for _, name := range names {
		zs := e.st.Zones[name]
		p := e.cache[name]
		if p == nil || p.hash != zs.Hash {
			ref, ok := e.refs[name]
			if !ok {
				continue
			}
			var err error
			p, err = e.prepare(ctx, ref)
			if err != nil {
				zs.Error = err.Error()
				e.log.Warn("zone not read for push", "zone", name, "err", err)
				continue
			}
			zs.Hash, zs.Serial, zs.Signed = p.hash, p.serial, p.signed
			if zs.Hash == zs.Acked || zs.Hash == zs.RefusedHash {
				continue
			}
		}
		owner, _ := e.ownerPtr(name)
		zp := protocol.ZonePush{
			Name: name, Owner: owner, Hash: p.hash, Serial: p.serial,
			SignedAtSource: p.signed, Format: "rfc1035", Text: p.text,
		}
		b, _ := json.Marshal(zp)
		if len(batch) > 0 && (len(batch) >= protocol.MaxZonesPerBatch || size+len(b) > protocol.MaxBatchBytes-4096) {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, zp)
		size += len(b) + 1
	}
	return flush()
}

func (e *Engine) sendBatch(ctx context.Context, batch []protocol.ZonePush) error {
	resp, err := e.api.Zones(ctx, &protocol.ZonesRequest{ScanStartedAt: e.st.ScanStartedAt, Zones: batch})
	if err != nil {
		var ae *protocol.APIError
		if errors.As(err, &ae) && !ae.Retryable() && ae.Status >= 400 && ae.Status < 500 &&
			ae.Status != http.StatusUnauthorized && ae.Status != http.StatusForbidden &&
			ae.Status != http.StatusUpgradeRequired && !isEpochStale(err) {
			// Spec 7.5: not retried for the same payload.
			for _, z := range batch {
				zs := e.st.Zones[z.Name]
				zs.RefusedHash, zs.Status = z.Hash, protocol.StatusRefused
				zs.Reason = fmt.Sprintf("http_%d: %s", ae.Status, ae.Message)
				e.dropCache(z.Name)
			}
			e.log.Error("PanelDNS refused a batch of zones; they are sent again when they change", "zones", len(batch), "err", ae.Error())
			return nil
		}
		return err
	}
	results := map[string]protocol.ZoneResult{}
	for _, r := range resp.Results {
		results[filter.Normalize(r.Name)] = r
	}
	for _, z := range batch {
		zs := e.st.Zones[z.Name]
		r, ok := results[z.Name]
		if !ok {
			e.log.Warn("no answer for zone; it is sent again", "zone", z.Name)
			continue
		}
		zs.Status, zs.Reason = r.Status, joinReason(r.Reason, r.Message)
		switch {
		case protocol.Acknowledged(r.Status):
			zs.Acked, zs.RefusedHash = z.Hash, ""
			if z.Owner != nil {
				zs.Owner = *z.Owner
			} else {
				zs.Owner = ""
			}
			e.dropCache(z.Name)
		case r.Status == protocol.StatusRefused:
			zs.RefusedHash = z.Hash
			e.dropCache(z.Name)
			e.log.Warn("zone refused by PanelDNS", "zone", z.Name, "reason", zs.Reason)
		default:
			e.log.Warn("unknown zone status; the zone is sent again", "zone", z.Name, "status", r.Status)
		}
	}
	return nil
}

func joinReason(code, msg string) string {
	switch {
	case code != "" && msg != "":
		return code + ": " + msg
	case code != "":
		return code
	}
	return msg
}

func (e *Engine) sendDeletions(ctx context.Context) error {
	var names []string
	for n := range e.st.Deletions {
		names = append(names, n)
	}
	sort.Strings(names)
	for len(names) > 0 {
		k := min(len(names), protocol.MaxDeletionsPerReq)
		chunk := names[:k]
		names = names[k:]
		req := &protocol.DeletionsRequest{ScanStartedAt: e.st.ScanStartedAt}
		for _, n := range chunk {
			req.Deletions = append(req.Deletions, protocol.Deletion{Name: n})
		}
		if _, err := e.api.Deletions(ctx, req); err != nil {
			var ae *protocol.APIError
			if errors.As(err, &ae) && !ae.Retryable() && ae.Status >= 400 && ae.Status < 500 &&
				ae.Status != http.StatusUnauthorized && ae.Status != http.StatusForbidden &&
				ae.Status != http.StatusUpgradeRequired && !isEpochStale(err) {
				e.log.Error("PanelDNS refused deletions; the next inventory implies them", "names", len(chunk), "err", ae.Error())
			} else {
				return err
			}
		} else {
			e.log.Info("deletions sent", "names", len(chunk))
		}
		for _, n := range chunk {
			delete(e.st.Deletions, n)
		}
	}
	return nil
}

// HeartbeatRequest builds the heartbeat body from the current state.
func (e *Engine) HeartbeatRequest(check bool) *protocol.HeartbeatRequest {
	r := &protocol.HeartbeatRequest{
		AgentVersion: version.Version, Hostname: e.cfg.Host.Hostname, OS: e.cfg.Host.OS,
		Panel: e.cfg.Host.Panel, Backend: e.src.Kind(),
		ScanStartedAt: e.st.ScanStartedAt, ScanCompletedAt: e.st.ScanCompletedAt,
		Errors: []protocol.ZoneError{}, Check: check, PublicIPs: []string{},
	}
	if e.cfg.Host.PublicIPs != nil {
		r.PublicIPs = e.cfg.Host.PublicIPs()
	}
	if e.listing != nil {
		r.View = e.listing.View
	}
	add := func(z protocol.ZoneError) {
		if len(r.Errors) < protocol.MaxHeartbeatErrors {
			r.Errors = append(r.Errors, z)
		}
	}
	if e.scanErr != nil {
		add(protocol.ZoneError{Code: "scan_failed", Message: e.scanErr.Error()})
	}
	if e.listing != nil {
		for _, w := range e.listing.Warnings {
			add(protocol.ZoneError{Code: "config_warning", Message: w})
		}
	}
	for _, name := range sortedZones(e.st.Zones) {
		zs := e.st.Zones[name]
		switch {
		case zs.Excluded != "":
			r.ExcludedCount++
			continue
		case zs.Error != "":
			add(protocol.ZoneError{Zone: name, Code: "read_failed", Message: zs.Error})
		}
		r.ZoneCount++
		if zs.Signed {
			r.SignedCount++
		}
	}
	return r
}

func (e *Engine) heartbeat(ctx context.Context, check bool) error {
	resp, err := e.api.Heartbeat(ctx, e.HeartbeatRequest(check))
	if err != nil {
		return err
	}
	e.lastHB = resp
	if resp.Config != nil {
		e.overlay = *resp.Config
	}
	if resp.Resync {
		e.inventoryDue, e.fullScanDone = true, false
	}
	for _, n := range resp.ResyncNames {
		if zs, ok := e.st.Zones[filter.Normalize(n)]; ok {
			zs.Acked, zs.RefusedHash = "", ""
			zs.Fingerprint = "" // re-read on the next scan
		}
	}
	if resp.RotateKey {
		e.rotate = true
	}
	if resp.MinimumVersion != "" && version.Less(version.Version, resp.MinimumVersion) {
		e.log.Warn("this agent is below PanelDNS's minimum supported version; update the package",
			"version", version.Version, "minimum", resp.MinimumVersion, "grace_until", time.Unix(resp.MinimumGraceUntil, 0).UTC().Format(time.RFC3339))
	} else if resp.LatestVersion != "" && version.Less(version.Version, resp.LatestVersion) {
		e.log.Info("a newer agent version is available", "version", version.Version, "latest", resp.LatestVersion)
	}
	return nil
}

// Run scans every interval and runs a cycle after each scan, or sooner
// when a backoff delay ends. It returns when ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	nextScan := e.Now()
	for {
		now := e.Now()
		if !now.Before(nextScan) {
			if e.listingOK && e.Now().Sub(time.Unix(e.st.LastInventoryAt, 0)) >= e.resync() {
				e.inventoryDue = true
			}
			e.Scan(ctx, e.NeedsFullScan())
			nextScan = e.Now().Add(e.interval())
		}
		e.Cycle(ctx)
		wake := nextScan
		if !e.nextAttempt.IsZero() && e.nextAttempt.Before(wake) {
			wake = e.nextAttempt
		}
		t := time.NewTimer(time.Until(wake))
		select {
		case <-ctx.Done():
			t.Stop()
			e.save()
			return ctx.Err()
		case <-t.C:
		}
	}
}
