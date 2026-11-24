package engine

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/source"
	"github.com/hostingsimple/paneldns-agent/internal/state"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// fakeSource serves zones from memory. Changing text without touching fp
// models an edit the fingerprint misses.
type fakeSource struct {
	zones      map[string]*fakeZone
	unreadable []string
	running    source.Running
	listErr    error
	reads      int
}

type fakeZone struct {
	text, fp, declared string
	readErr            error
}

func (f *fakeSource) Kind() string { return "bind" }

func (f *fakeSource) List(ctx context.Context) (*source.Listing, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	l := &source.Listing{Backend: "bind", Unreadable: f.unreadable}
	var names []string
	for n := range f.zones {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		z := f.zones[n]
		l.Zones = append(l.Zones, source.ZoneRef{Name: n, Fingerprint: z.fp, DeclaredIn: z.declared})
	}
	return l, nil
}

func (f *fakeSource) Read(ctx context.Context, ref source.ZoneRef) ([]zonefile.RR, error) {
	f.reads++
	z, ok := f.zones[ref.Name]
	if !ok {
		return nil, fmt.Errorf("gone")
	}
	if z.readErr != nil {
		return nil, z.readErr
	}
	return zonefile.Parse([]byte(z.text), zonefile.Options{Origin: ref.Name})
}

func (f *fakeSource) Running(ctx context.Context) (source.Running, string) {
	return f.running, "test"
}

func zoneText(serial int, extra string) string {
	return fmt.Sprintf("$TTL 300\n@ IN SOA ns1.example.net. h.example.net. %d 1 2 3 4\n@ IN A 192.0.2.1\n%s", serial, extra)
}

// fakeAPI records requests and answers like a well-behaved server.
type fakeAPI struct {
	inventories []*protocol.InventoryRequest
	zones       []*protocol.ZonesRequest
	deletions   []*protocol.DeletionsRequest
	heartbeats  []*protocol.HeartbeatRequest
	epochs      int

	known      map[string]string // name -> hash the server holds
	fail       error             // returned by every call while set
	zonesErr   error
	status     map[string]string // forced per-zone status
	hbResp     *protocol.HeartbeatResponse
	staleOnce  bool
	needAlways []string
}

func newAPI() *fakeAPI { return &fakeAPI{known: map[string]string{}, status: map[string]string{}} }

func (a *fakeAPI) Epoch(ctx context.Context) (*protocol.EpochResponse, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	a.epochs++
	return &protocol.EpochResponse{Epoch: uint64(10 + a.epochs)}, nil
}

func (a *fakeAPI) Heartbeat(ctx context.Context, r *protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	a.heartbeats = append(a.heartbeats, r)
	if a.hbResp != nil {
		resp := a.hbResp
		a.hbResp = nil
		return resp, nil
	}
	return &protocol.HeartbeatResponse{}, nil
}

func (a *fakeAPI) Inventory(ctx context.Context, r *protocol.InventoryRequest) (*protocol.InventoryResponse, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	if a.staleOnce {
		a.staleOnce = false
		return nil, &protocol.APIError{Status: 409, Code: protocol.ErrEpochStale, Path: protocol.PathInventory}
	}
	a.inventories = append(a.inventories, r)
	resp := &protocol.InventoryResponse{Need: []string{}}
	for _, z := range r.Zones {
		if !z.Excluded && a.known[z.Name] != z.Hash {
			resp.Need = append(resp.Need, z.Name)
		}
	}
	resp.Need = append(resp.Need, a.needAlways...)
	return resp, nil
}

func (a *fakeAPI) Zones(ctx context.Context, r *protocol.ZonesRequest) (*protocol.ZonesResponse, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	if a.zonesErr != nil {
		return nil, a.zonesErr
	}
	a.zones = append(a.zones, r)
	resp := &protocol.ZonesResponse{}
	for _, z := range r.Zones {
		st := protocol.StatusAccepted
		if a.known[z.Name] == z.Hash {
			st = protocol.StatusUnchanged
		}
		if s, ok := a.status[z.Name]; ok {
			st = s
		}
		if protocol.Acknowledged(st) {
			a.known[z.Name] = z.Hash
		}
		resp.Results = append(resp.Results, protocol.ZoneResult{Name: z.Name, Status: st, Reason: "test"})
	}
	return resp, nil
}

func (a *fakeAPI) Deletions(ctx context.Context, r *protocol.DeletionsRequest) (*protocol.DeletionsResponse, error) {
	if a.fail != nil {
		return nil, a.fail
	}
	a.deletions = append(a.deletions, r)
	for _, d := range r.Deletions {
		delete(a.known, d.Name)
	}
	return &protocol.DeletionsResponse{}, nil
}

func (a *fakeAPI) pushedNames() []string {
	var out []string
	for _, r := range a.zones {
		for _, z := range r.Zones {
			out = append(out, z.Name)
		}
	}
	return out
}

func (a *fakeAPI) reset() {
	a.inventories, a.zones, a.deletions, a.heartbeats = nil, nil, nil, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock               { return &clock{t: time.Unix(1795000000, 0)} }
func cfg(statePath string) Config {
	return Config{Interval: time.Minute, Resync: 6 * time.Hour, StatePath: statePath}
}
func (f *fakeSource) set(n, text, fp string) {
	f.zones[n] = &fakeZone{text: text, fp: fp, declared: "/etc/named.conf"}
}

func newFixture(t *testing.T) (*Engine, *fakeSource, *fakeAPI, *clock) {
	t.Helper()
	src := &fakeSource{zones: map[string]*fakeZone{}, running: source.RunningYes}
	src.set("example.com", zoneText(1, ""), "a1")
	src.set("example.net", zoneText(1, "www IN A 192.0.2.2\n"), "b1")
	src.set("localhost", zoneText(1, ""), "l1") // system zone
	api := newAPI()
	c := newClock()
	e := New(cfg(filepath.Join(t.TempDir(), "state.json")), src, api, nil, nil, nil)
	e.Now = c.now
	return e, src, api, c
}

// step is one interval: scan then cycle, as Run does.
func step(t *testing.T, e *Engine, c *clock) error {
	t.Helper()
	ctx := context.Background()
	if err := e.Scan(ctx, e.NeedsFullScan()); err != nil {
		return err
	}
	err := e.Cycle(ctx)
	c.add(time.Minute)
	return err
}

func TestFirstRunInventoryThenPush(t *testing.T) {
	e, _, api, c := newFixture(t)
	if err := step(t, e, c); err != nil {
		t.Fatal(err)
	}
	if len(api.inventories) != 1 {
		t.Fatalf("inventories %d", len(api.inventories))
	}
	inv := api.inventories[0]
	if inv.Part != 1 || inv.Parts != 1 || len(inv.Zones) != 2 {
		t.Fatalf("inventory %+v", inv)
	}
	for _, z := range inv.Zones {
		if z.Name == "localhost" || !strings.HasPrefix(z.Hash, "sha256:") {
			t.Fatalf("bad entry %+v", z)
		}
	}
	if got := api.pushedNames(); strings.Join(got, ",") != "example.com,example.net" {
		t.Fatalf("pushed %v", got)
	}
	z := api.zones[0].Zones[0]
	if z.Format != "rfc1035" || z.Serial != 1 || z.Owner != nil || !strings.HasPrefix(z.Text, "$ORIGIN example.com.\n") {
		t.Fatalf("zone push %+v", z)
	}
	if len(api.heartbeats) != 1 || api.heartbeats[0].ZoneCount != 2 || api.heartbeats[0].ScanStartedAt == 0 {
		t.Fatalf("heartbeat %+v", api.heartbeats)
	}

	// Nothing changed: one heartbeat, nothing else.
	api.reset()
	if err := step(t, e, c); err != nil {
		t.Fatal(err)
	}
	if len(api.zones)+len(api.inventories)+len(api.deletions) != 0 || len(api.heartbeats) != 1 {
		t.Fatalf("idle cycle sent %d zones %d inventories %d deletions", len(api.zones), len(api.inventories), len(api.deletions))
	}
}

func TestChangeDetection(t *testing.T) {
	e, src, api, c := newFixture(t)
	step(t, e, c)
	api.reset()
	reads := src.reads

	// Serial bump only: re-read (fingerprint changed) but not pushed.
	src.set("example.com", zoneText(2, ""), "a2")
	step(t, e, c)
	if src.reads != reads+1 || len(api.zones) != 0 {
		t.Fatalf("serial-only change: reads %d pushes %d", src.reads-reads, len(api.zones))
	}
	// A real change is pushed, alone.
	src.set("example.com", zoneText(3, "new IN A 192.0.2.9\n"), "a3")
	step(t, e, c)
	if got := api.pushedNames(); strings.Join(got, ",") != "example.com" || api.zones[0].Zones[0].Serial != 3 {
		t.Fatalf("pushed %v", got)
	}
	// An edit the fingerprint misses waits for the full resync.
	api.reset()
	src.zones["example.net"].text = zoneText(1, "sneaky IN A 192.0.2.7\n")
	step(t, e, c)
	if len(api.zones) != 0 {
		t.Fatal("pushed without a fingerprint change")
	}
	c.add(6 * time.Hour)
	step(t, e, c) // the resync is noticed in this cycle and scheduled
	step(t, e, c) // full scan, inventory, push
	if len(api.inventories) != 1 || strings.Join(api.pushedNames(), ",") != "example.net" {
		t.Fatalf("resync: inventories %d pushed %v", len(api.inventories), api.pushedNames())
	}
}

func TestDeletionAndReappearance(t *testing.T) {
	e, src, api, c := newFixture(t)
	step(t, e, c)
	api.reset()
	delete(src.zones, "example.net")
	step(t, e, c)
	if len(api.deletions) != 1 || api.deletions[0].Deletions[0].Name != "example.net" {
		t.Fatalf("deletions %+v", api.deletions)
	}
	if len(e.State().Deletions) != 0 {
		t.Fatal("acknowledged deletion still pending")
	}
	// Gone while offline, back before reconnecting: no deletion at all.
	api.reset()
	api.fail = &protocol.APIError{Path: "/x", Err: errors.New("connection refused")}
	delete(src.zones, "example.com")
	step(t, e, c)
	if !e.State().Deletions["example.com"] {
		t.Fatal("deletion not queued while offline")
	}
	src.set("example.com", zoneText(1, ""), "a9")
	step(t, e, c)
	api.fail = nil
	c.add(time.Hour)
	step(t, e, c)
	if len(api.deletions) != 0 {
		t.Fatal("deletion sent for a zone that came back")
	}
	if strings.Join(api.pushedNames(), ",") != "example.com" || api.zones[0].Zones[0].Hash != api.known["example.com"] {
		t.Fatalf("reappeared zone pushed %v", api.pushedNames())
	}
}

func TestOfflineSendsLatestOnly(t *testing.T) {
	e, src, api, c := newFixture(t)
	step(t, e, c)
	api.reset()
	api.fail = &protocol.APIError{Path: "/x", Err: errors.New("timeout")}
	for i := 2; i < 6; i++ {
		src.set("example.com", zoneText(i, fmt.Sprintf("v%d IN A 192.0.2.%d\n", i, i)), fmt.Sprintf("a%d", i))
		step(t, e, c)
	}
	if e.NextAttempt().IsZero() {
		t.Fatal("no backoff after failures")
	}
	api.fail = nil
	c.add(time.Hour)
	step(t, e, c)
	if len(api.zones) != 1 || len(api.zones[0].Zones) != 1 || api.zones[0].Zones[0].Serial != 5 {
		t.Fatalf("expected one push of the latest version, got %+v", api.zones)
	}
}

func TestBackoffAndRetryAfter(t *testing.T) {
	e, _, api, c := newFixture(t)
	api.fail = &protocol.APIError{Status: 503, Path: "/x", RetryAfter: 2 * time.Minute}
	e.Scan(context.Background(), true)
	if err := e.Cycle(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if d := e.NextAttempt().Sub(c.now()); d < 2*time.Minute {
		t.Fatalf("Retry-After not honoured: %v", d)
	}
	api.fail = nil
	c.add(time.Minute)
	e.Cycle(context.Background())
	if len(api.heartbeats) != 0 {
		t.Fatal("cycle ran during backoff")
	}
	c.add(2 * time.Minute)
	if err := e.Cycle(context.Background()); err != nil || len(api.heartbeats) != 1 {
		t.Fatalf("cycle after backoff: %v", err)
	}
	if !e.NextAttempt().IsZero() {
		t.Fatal("backoff not reset after success")
	}
	// 401 parks the agent for the maximum delay.
	api.fail = &protocol.APIError{Status: 401, Path: "/x"}
	e.Cycle(context.Background())
	if d := e.NextAttempt().Sub(c.now()); d != 10*time.Minute {
		t.Fatalf("401 delay %v", d)
	}
}

func TestRefusedAndNonRetryable(t *testing.T) {
	e, src, api, c := newFixture(t)
	api.status["example.net"] = protocol.StatusRefused
	step(t, e, c)
	zs := e.State().Zones["example.net"]
	if zs.RefusedHash == "" || zs.Acked != "" || zs.Status != "refused" {
		t.Fatalf("refused state %+v", zs)
	}
	api.reset()
	step(t, e, c)
	if len(api.zones) != 0 {
		t.Fatal("refused zone resent unchanged")
	}
	delete(api.status, "example.net")
	src.set("example.net", zoneText(2, "fixed IN A 192.0.2.3\n"), "b2")
	step(t, e, c)
	if strings.Join(api.pushedNames(), ",") != "example.net" {
		t.Fatalf("changed refused zone not sent: %v", api.pushedNames())
	}
	// A 400 for a batch marks its zones refused instead of retrying.
	api.reset()
	src.set("example.com", zoneText(9, "x IN A 192.0.2.4\n"), "a9")
	api.zonesErr = &protocol.APIError{Status: 400, Code: "invalid", Message: "bad", Path: protocol.PathZones}
	if err := step(t, e, c); err != nil {
		t.Fatalf("400 should not fail the cycle: %v", err)
	}
	if zs := e.State().Zones["example.com"]; zs.RefusedHash != zs.Hash || !strings.HasPrefix(zs.Reason, "http_400") {
		t.Fatalf("state %+v", zs)
	}
}

func TestExclusionsAndSystemZones(t *testing.T) {
	src := &fakeSource{zones: map[string]*fakeZone{}, running: source.RunningYes}
	src.set("example.com", zoneText(1, ""), "a")
	src.set("printer.local", zoneText(1, ""), "p")
	src.set("0.0.127.in-addr.arpa", zoneText(1, ""), "r")
	api := newAPI()
	c := newClock()
	conf := cfg("")
	conf.Exclude = []string{"*.local"}
	e := New(conf, src, api, nil, nil, nil)
	e.Now = c.now
	step(t, e, c)
	inv := api.inventories[0].Zones
	if len(inv) != 2 || inv[1].Name != "printer.local" || !inv[1].Excluded || inv[1].Hash != "" {
		t.Fatalf("inventory %+v", inv)
	}
	if strings.Join(api.pushedNames(), ",") != "example.com" {
		t.Fatalf("pushed %v", api.pushedNames())
	}
	// A server overlay exclude makes a pushed zone excluded: no deletion,
	// a new inventory instead.
	api.reset()
	api.hbResp = &protocol.HeartbeatResponse{Config: &protocol.Overlay{Exclude: []string{"example.com"}}}
	step(t, e, c)
	step(t, e, c)
	step(t, e, c)
	if len(api.deletions) != 0 || len(api.inventories) != 1 {
		t.Fatalf("deletions %d inventories %d", len(api.deletions), len(api.inventories))
	}
	for _, z := range api.inventories[0].Zones {
		if z.Name == "example.com" && !z.Excluded {
			t.Fatal("excluded zone not reported as excluded")
		}
	}
}

func TestGuards(t *testing.T) {
	e, src, api, c := newFixture(t)
	step(t, e, c)
	api.reset()

	// All zones vanish while named is down: error, nothing deleted.
	saved := src.zones
	src.zones = map[string]*fakeZone{}
	src.running = source.RunningNo
	if err := step(t, e, c); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("guard: %v", err)
	}
	e.Cycle(context.Background())
	if len(api.deletions) != 0 || len(e.State().Deletions) != 0 {
		t.Fatal("deletions after guard tripped")
	}
	if hb := api.heartbeats; len(hb) == 0 || hb[len(hb)-1].Errors[0].Code != "scan_failed" {
		t.Fatalf("heartbeat should report the scan error: %+v", hb)
	}
	// named running and really empty: deletions go out.
	src.running = source.RunningYes
	api.reset()
	c.add(time.Hour)
	step(t, e, c)
	if len(api.deletions) != 1 || len(api.deletions[0].Deletions) != 2 {
		t.Fatalf("deletions %+v", api.deletions)
	}

	// A zone-bearing include becoming unreadable stops the scan.
	src.zones = saved
	src.running = source.RunningYes
	step(t, e, c)
	src.unreadable = []string{"/etc/named.conf"}
	if err := step(t, e, c); err == nil || !strings.Contains(err.Error(), "can't be read now") {
		t.Fatalf("include guard: %v", err)
	}
}

func TestEpochStaleRecovery(t *testing.T) {
	e, _, api, c := newFixture(t)
	api.staleOnce = true
	if err := step(t, e, c); err != nil {
		t.Fatal(err)
	}
	if api.epochs != 1 {
		t.Fatalf("epochs %d", api.epochs)
	}
	// The inventory is sent after the next full scan.
	if !e.NeedsFullScan() {
		t.Fatal("full scan not scheduled after epoch reset")
	}
	step(t, e, c)
	if len(api.inventories) != 1 {
		t.Fatalf("inventories %d", len(api.inventories))
	}
	// State lost at start: /epoch first.
	e2 := New(Config{Interval: time.Minute, Resync: time.Hour, NeedEpoch: true}, &fakeSource{zones: map[string]*fakeZone{}, running: source.RunningYes}, api, nil, nil, nil)
	e2.Now = c.now
	step(t, e2, c)
	if api.epochs != 2 {
		t.Fatalf("NeedEpoch: epochs %d", api.epochs)
	}
}

func TestBatching(t *testing.T) {
	src := &fakeSource{zones: map[string]*fakeZone{}, running: source.RunningYes}
	for i := 0; i < 250; i++ {
		src.set(fmt.Sprintf("z%03d.example.com", i), zoneText(1, ""), "f")
	}
	var sb strings.Builder
	for i := 0; i < 7000; i++ { // about 1.7 MB of canonical text
		fmt.Fprintf(&sb, "h%d IN TXT \"%s\"\n", i, strings.Repeat("y", 200))
	}
	src.set("big1.example.net", zoneText(1, sb.String()), "b")
	src.set("big2.example.net", zoneText(1, sb.String()), "b")
	src.set("big3.example.net", zoneText(1, sb.String()), "b")
	src.set("big4.example.net", zoneText(1, sb.String()), "b")
	src.set("big5.example.net", zoneText(1, sb.String()), "b")
	src.set("big6.example.net", zoneText(1, sb.String()), "b")
	src.set("toolarge.example.net", zoneText(1, sb.String()+strings.ReplaceAll(sb.String(), "h", "k")), "t")
	api := newAPI()
	c := newClock()
	e := New(cfg(""), src, api, nil, nil, nil)
	e.Now = c.now
	step(t, e, c)
	total := 0
	for _, r := range api.zones {
		size := 0
		for _, z := range r.Zones {
			size += len(z.Text)
		}
		if len(r.Zones) > protocol.MaxZonesPerBatch || size > protocol.MaxBatchBytes {
			t.Fatalf("batch of %d zones, %d bytes", len(r.Zones), size)
		}
		total += len(r.Zones)
	}
	if total != 256 {
		t.Fatalf("pushed %d zones, want 256", total)
	}
	if zs := e.State().Zones["toolarge.example.net"]; !strings.Contains(zs.Error, "limit") {
		t.Fatalf("oversized zone: %+v", zs)
	}
	if len(api.zones) < 4 {
		t.Fatalf("only %d batches", len(api.zones))
	}
}

func TestRestartSafety(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	src := &fakeSource{zones: map[string]*fakeZone{}, running: source.RunningYes}
	src.set("example.com", zoneText(1, ""), "a")
	src.set("example.net", zoneText(1, ""), "b")
	api := newAPI()
	api.status["example.net"] = "mystery" // not acknowledged
	c := newClock()
	e := New(cfg(statePath), src, api, nil, nil, nil)
	e.Now = c.now
	step(t, e, c)

	st, existed, err := state.Load(statePath)
	if err != nil || !existed {
		t.Fatalf("load %v %v", existed, err)
	}
	if st.Zones["example.com"].Acked == "" || st.Zones["example.net"].Acked != "" {
		t.Fatalf("acked hashes after restart: %+v %+v", st.Zones["example.com"], st.Zones["example.net"])
	}
	delete(api.status, "example.net")
	api.reset()
	e2 := New(cfg(statePath), src, api, nil, st, nil)
	e2.Now = c.now
	step(t, e2, c)
	// On start a full inventory runs; the unacknowledged zone is sent again.
	if strings.Join(api.pushedNames(), ",") != "example.net" {
		t.Fatalf("after restart pushed %v", api.pushedNames())
	}
}

func TestHeartbeatAnswers(t *testing.T) {
	e, _, api, c := newFixture(t)
	step(t, e, c)
	api.reset()
	rotated := 0
	e.Rotate = func(ctx context.Context) error { rotated++; return nil }
	api.hbResp = &protocol.HeartbeatResponse{
		ResyncNames: []string{"example.net."}, RotateKey: true,
		Config: &protocol.Overlay{Interval: 120}, MinimumVersion: "9.0.0",
	}
	step(t, e, c)
	if rotated != 1 {
		t.Fatalf("rotations %d", rotated)
	}
	if e.interval() != 2*time.Minute {
		t.Fatalf("overlay interval %v", e.interval())
	}
	step(t, e, c)
	if strings.Join(api.pushedNames(), ",") != "example.net" {
		t.Fatalf("resync name not pushed: %v", api.pushedNames())
	}
	if api.zones[0].Zones[0].Name != "example.net" {
		t.Fatal("wrong zone")
	}
	api.reset()
	api.hbResp = &protocol.HeartbeatResponse{Resync: true}
	step(t, e, c)
	step(t, e, c)
	if len(api.inventories) != 1 {
		t.Fatalf("resync request: inventories %d", len(api.inventories))
	}
}

func TestReadErrorsKeepZone(t *testing.T) {
	e, src, api, c := newFixture(t)
	step(t, e, c)
	api.reset()
	src.zones["example.com"].readErr = errors.New("named-compilezone failed: bad owner name (check-names)")
	src.zones["example.com"].fp = "changed"
	step(t, e, c)
	if len(api.deletions) != 0 || len(api.zones) != 0 {
		t.Fatal("a zone that fails to compile must not be deleted or pushed")
	}
	hb := api.heartbeats[len(api.heartbeats)-1]
	if len(hb.Errors) != 1 || hb.Errors[0].Zone != "example.com" || hb.Errors[0].Code != "read_failed" {
		t.Fatalf("heartbeat errors %+v", hb.Errors)
	}
}

// A rotation whose answer was lost (review A-15) is settled at the start of
// the next cycles, before any other request, until Rotate stops reporting
// it pending; it never starts a fresh rotation by itself.
func TestPendingRotation(t *testing.T) {
	e, _, api, c := newFixture(t)
	var calls []int // heartbeats seen when Rotate ran
	results := []error{ErrRotationPending, ErrRotationPending, nil}
	e.Rotate = func(ctx context.Context) error {
		calls = append(calls, len(api.heartbeats))
		err := results[0]
		results = results[1:]
		return err
	}
	api.hbResp = &protocol.HeartbeatResponse{RotateKey: true}
	step(t, e, c) // asked: Rotate after the heartbeat says pending
	step(t, e, c) // pending: Rotate first thing, still pending
	step(t, e, c) // pending: settled
	step(t, e, c) // nothing more
	if !reflect.DeepEqual(calls, []int{1, 1, 2}) {
		t.Fatalf("Rotate ran with heartbeats seen %v; want after the first, then before the 2nd and 3rd", calls)
	}

	e2, _, _, c2 := newFixture(t)
	e2.cfg.KeyPending, e2.keyPending = true, true
	n := 0
	e2.Rotate = func(context.Context) error { n++; return errors.New("dropped") }
	step(t, e2, c2)
	step(t, e2, c2)
	if n != 1 {
		t.Fatalf("Rotate ran %d times after a settled (failed) resolution", n)
	}
}
