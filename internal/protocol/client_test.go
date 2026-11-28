package protocol

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type memSeq struct {
	mu         sync.Mutex
	epoch, seq uint64
}

func (m *memSeq) Next() (uint64, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	return m.epoch, m.seq, nil
}

func (m *memSeq) SetEpoch(e uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epoch, m.seq = e, 0
	return nil
}

// server verifies requests the way PanelDNS must, then calls handle.
type server struct {
	t      *testing.T
	pub    ed25519.PublicKey
	nonces map[string]bool
	last   map[string]uint64
	handle func(w http.ResponseWriter, path string, body []byte, seq uint64)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if r.Method != http.MethodPost || r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Content-Type") != "application/json" {
		s.t.Errorf("bad request framing: %s %v", r.Method, r.Header)
	}
	if !strings.HasPrefix(r.Header.Get("User-Agent"), "paneldns-agent/") || r.Header.Get(HeaderAgentVersion) == "" {
		s.t.Errorf("version headers missing")
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		s.t.Fatalf("body not gzip: %v", err)
	}
	body, _ := io.ReadAll(zr)
	var seq uint64
	if r.URL.Path != PathEnrol {
		ts, _ := strconv.ParseInt(r.Header.Get(HeaderTimestamp), 10, 64)
		epoch, _ := strconv.ParseUint(r.Header.Get(HeaderEpoch), 10, 64)
		seq, _ = strconv.ParseUint(r.Header.Get(HeaderSeq), 10, 64)
		nonce := r.Header.Get(HeaderNonce)
		if len(nonce) != 32 || s.nonces[nonce] {
			s.t.Errorf("nonce %q bad or reused", nonce)
		}
		s.nonces[nonce] = true
		if !Verify(s.pub, r.Header.Get(HeaderSignature), r.Method, r.URL.Path, ts, nonce, epoch, seq, raw) {
			s.t.Errorf("signature does not verify for %s", r.URL.Path)
		}
		key := r.Header.Get(HeaderKey)
		within := key + "/" + r.Header.Get(HeaderEpoch) // seq restarts per epoch
		if seq <= s.last[within] {
			s.t.Errorf("seq %d not above %d", seq, s.last[within])
		}
		s.last[within] = seq
		if key != "17.4" {
			s.t.Errorf("key header %q", key)
		}
	} else if r.Header.Get(HeaderSignature) != "" {
		s.t.Errorf("enrol must not be signed")
	}
	s.handle(w, r.URL.Path, body, seq)
}

func newTestClient(t *testing.T, handle func(w http.ResponseWriter, path string, body []byte, seq uint64)) (*Client, *memSeq, *httptest.Server) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := &server{t: t, pub: pub, nonces: map[string]bool{}, last: map[string]uint64{}, handle: handle}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(srv.Close)
	seq := &memSeq{epoch: 3}
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client(), Seq: seq}
	c.SetKey(priv, "17", "4")
	return c, seq, srv
}

func TestSignedRequests(t *testing.T) {
	var gotZones ZonesRequest
	var gotDel DeletionsRequest
	var headerSeq uint64
	c, seq, _ := newTestClient(t, func(w http.ResponseWriter, path string, body []byte, s uint64) {
		w.Header().Set("Content-Type", "application/json")
		switch path {
		case PathHeartbeat:
			w.Write([]byte(`{"resync":true,"config":{"interval":30}}`))
		case PathZones:
			headerSeq = s
			json.Unmarshal(body, &gotZones)
			w.Write([]byte(`{"results":[{"name":"example.com","status":"accepted"}]}`))
		case PathDeletions:
			json.Unmarshal(body, &gotDel)
			w.Write([]byte(`{}`))
		case PathEpoch:
			w.Write([]byte(`{"epoch":9}`))
		case PathInventory:
			w.Write([]byte(`{"need":["example.com"]}`))
		case PathRotate:
			w.Write([]byte(`{"key_id":5}`))
		}
	})
	ctx := context.Background()
	hb, err := c.Heartbeat(ctx, &HeartbeatRequest{})
	if err != nil || !hb.Resync || hb.Config.Interval != 30 {
		t.Fatalf("heartbeat %+v %v", hb, err)
	}
	zr, err := c.Zones(ctx, &ZonesRequest{Zones: []ZonePush{{Name: "example.com"}, {Name: "example.net"}}})
	if err != nil || zr.Results[0].Status != "accepted" {
		t.Fatalf("zones %+v %v", zr, err)
	}
	if gotZones.Zones[0].Seq != headerSeq || gotZones.Zones[1].Seq != headerSeq || headerSeq == 0 {
		t.Fatalf("zone seq %d/%d, header %d", gotZones.Zones[0].Seq, gotZones.Zones[1].Seq, headerSeq)
	}
	if _, err := c.Deletions(ctx, &DeletionsRequest{Deletions: []Deletion{{Name: "example.org"}}}); err != nil || gotDel.Deletions[0].Seq == 0 {
		t.Fatalf("deletions %+v %v", gotDel, err)
	}
	if inv, err := c.Inventory(ctx, &InventoryRequest{}); err != nil || inv.Need[0] != "example.com" {
		t.Fatalf("inventory %v", err)
	}
	if ep, err := c.Epoch(ctx); err != nil || ep.Epoch != 9 || seq.epoch != 9 || seq.seq != 0 {
		t.Fatalf("epoch %+v %v seq %+v", ep, err, seq)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	if rr, err := c.Rotate(ctx, pub); err != nil || rr.KeyID != "5" {
		t.Fatalf("rotate %+v %v", rr, err)
	}
	if d, _ := c.ServerDate(); d.IsZero() {
		t.Fatal("server Date not recorded")
	}
}

func TestEnrolUnsigned(t *testing.T) {
	var got EnrolRequest
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, path string, body []byte, _ uint64) {
		json.Unmarshal(body, &got)
		w.Write([]byte(`{"source_id":17,"key_id":"4","epoch":1,"cluster_name":"Brand A"}`))
	})
	pub, _, _ := ed25519.GenerateKey(nil)
	resp, err := c.Enrol(context.Background(), &EnrolRequest{Code: "abc", PublicKey: EncodePublicKey(pub)})
	if err != nil || resp.SourceID != "17" || resp.KeyID != "4" || resp.Epoch != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(got.PublicKey); len(raw) != 32 || got.Code != "abc" {
		t.Fatalf("enrol body %+v", got)
	}
}

func TestErrors(t *testing.T) {
	status, body, retryAfter := 0, "", ""
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, path string, b []byte, _ uint64) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
	tests := []struct {
		status    int
		body, ra  string
		code      string
		retryable bool
		explain   string
		wait      time.Duration
	}{
		{403, `{"error":"ip_refused","message":"not allowed","ip":"192.0.2.7"}`, "", ErrIPRefused, false, "came from 192.0.2.7", 0},
		{409, `{"error":"epoch_stale"}`, "", ErrEpochStale, false, "epoch_stale", 0},
		{409, `{"error":"busy"}`, "", "busy", true, "", 0},
		{429, `{"error":"rate_limited"}`, "7", "rate_limited", true, "", 7 * time.Second},
		{503, `upstream down`, "", "", true, "", 0},
		{401, `{"error":"unauthorized"}`, "", ErrUnauthorized, false, "Re-enrol", 0},
		{401, `{"error":"timestamp_out_of_window"}`, "", ErrClockSkew, false, "clock", 0},
		{426, `{"error":"upgrade_required"}`, "", ErrUpgradeRequired, false, "minimum supported version", 0},
		{400, `{"error":"invalid","message":"bad json"}`, "", "invalid", false, "bad json", 0},
		{302, ``, "", "", false, "HTTP 302", 0},
	}
	for _, tt := range tests {
		status, body, retryAfter = tt.status, tt.body, tt.ra
		_, err := c.Heartbeat(context.Background(), &HeartbeatRequest{})
		var ae *APIError
		if !errors.As(err, &ae) {
			t.Fatalf("%d: not an APIError: %v", tt.status, err)
		}
		if ae.Status != tt.status || ae.Code != tt.code || ae.Retryable() != tt.retryable || ae.RetryAfter != tt.wait {
			t.Errorf("%d %s: got %+v retryable=%v", tt.status, tt.code, ae, ae.Retryable())
		}
		if tt.explain != "" && !strings.Contains(ae.Explain(), tt.explain) {
			t.Errorf("%d: explain %q", tt.status, ae.Explain())
		}
	}
}

func TestTransportErrorsAndHTTPS(t *testing.T) {
	c := &Client{BaseURL: "http://app.example.com", Seq: &memSeq{}}
	if _, err := c.Heartbeat(context.Background(), &HeartbeatRequest{}); err == nil || !strings.Contains(err.Error(), "only https") {
		t.Fatalf("http accepted: %v", err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	_, priv, _ := ed25519.GenerateKey(nil)
	c = &Client{BaseURL: url, Seq: &memSeq{}}
	c.SetKey(priv, "1", "1")
	_, err := c.Heartbeat(context.Background(), &HeartbeatRequest{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 0 || !ae.Retryable() {
		t.Fatalf("transport error: %v", err)
	}
	// Certificate verification is on: the test server's self-signed
	// certificate is refused by the default client.
	srv2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv2.Close()
	c = &Client{BaseURL: srv2.URL, Seq: &memSeq{}, HTTP: NewHTTPClient()}
	c.SetKey(priv, "1", "1")
	if _, err := c.Heartbeat(context.Background(), &HeartbeatRequest{}); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("self-signed certificate accepted: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		h    string
		want time.Duration
		ok   bool
	}{
		{"120", 2 * time.Minute, true},
		{"0", 0, true},
		{"-1", 0, false},
		{"", 0, false},
		{"soon", 0, false},
		{"Fri, 20 Nov 2026 12:01:00 GMT", time.Minute, true},
		{"Fri, 20 Nov 2026 11:00:00 GMT", 0, true},
	}
	for _, tt := range tests {
		d, ok := ParseRetryAfter(tt.h, now)
		if d != tt.want || ok != tt.ok {
			t.Errorf("%q: %v %v", tt.h, d, ok)
		}
	}
}

func TestReplayFields(t *testing.T) {
	// Two requests with identical bodies differ in nonce, seq and
	// signature; a signature does not survive a changed field.
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := Gzip([]byte(`{}`))
	sig := Sign(priv, "POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 3, 42, body)
	ok := func(method, path string, ts int64, nonce string, epoch, seq uint64, b []byte) bool {
		return Verify(pub, sig, method, path, ts, nonce, epoch, seq, b)
	}
	if !ok("POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 3, 42, body) {
		t.Fatal("valid signature rejected")
	}
	if !ok("post", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 3, 42, body) {
		t.Fatal("method is upper-cased before signing")
	}
	changes := map[string]bool{
		"path":  ok("POST", PathZones, 1795000000, "00112233445566778899aabbccddeeff", 3, 42, body),
		"time":  ok("POST", PathHeartbeat, 1795000001, "00112233445566778899aabbccddeeff", 3, 42, body),
		"nonce": ok("POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeef0", 3, 42, body),
		"epoch": ok("POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 4, 42, body),
		"seq":   ok("POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 3, 43, body),
		"body":  ok("POST", PathHeartbeat, 1795000000, "00112233445566778899aabbccddeeff", 3, 42, Gzip([]byte(`{"a":1}`))),
	}
	for f, v := range changes {
		if v {
			t.Errorf("signature still valid after changing %s", f)
		}
	}
	if Verify(pub, "not base64!", "POST", "/", 0, "", 0, 0, nil) {
		t.Fatal("garbage signature accepted")
	}
}

// TestCheckReport: the report goes signed to /check-report with its trigger
// and the report as sent (D-35).
func TestCheckReport(t *testing.T) {
	var got CheckReportRequest
	c, _, _ := newTestClient(t, func(w http.ResponseWriter, path string, body []byte, _ uint64) {
		if path != PathCheckReport {
			t.Errorf("path %s", path)
		}
		json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"report_id":12}`))
	})
	resp, err := c.CheckReport(context.Background(), &CheckReportRequest{Trigger: CheckTriggerManual, Report: json.RawMessage(`{"version":"0.1.8","checks":[]}`)})
	if err != nil || resp.ReportID != 12 {
		t.Fatalf("resp %+v %v", resp, err)
	}
	if got.Trigger != "manual" || string(got.Report) != `{"version":"0.1.8","checks":[]}` {
		t.Fatalf("sent %+v %s", got, got.Report)
	}
}
