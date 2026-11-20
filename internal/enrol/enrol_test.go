package enrol

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

func enrolServer(t *testing.T, status int, body string, got *protocol.EnrolRequest) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protocol.PathEnrol {
			t.Errorf("path %s", r.URL.Path)
		}
		zr, _ := gzip.NewReader(r.Body)
		b, _ := io.ReadAll(zr)
		json.Unmarshal(b, got)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnrolWritesFiles(t *testing.T) {
	var got protocol.EnrolRequest
	srv := enrolServer(t, 200, `{"source_id":"17","key_id":"4","epoch":2,"cluster_name":"Brand A","source_name":"web1","allowed_ips":["192.0.2.10"]}`, &got)
	dir := t.TempDir()
	confPath := filepath.Join(dir, "paneldns-agent.conf")
	sample, _ := os.ReadFile(filepath.Join("..", "..", "packaging", "paneldns-agent.conf"))
	os.WriteFile(confPath, sample, 0o640)
	stateDir := filepath.Join(dir, "state")
	// A stale key from an earlier install is replaced.
	os.MkdirAll(stateDir, 0o700)
	os.WriteFile(filepath.Join(stateDir, state.NextKeyFile), []byte("old"), 0o600)
	var out bytes.Buffer
	afterCalled := false
	res, err := Run(context.Background(), Options{
		URL: srv.URL + "/", Code: " abcd efgh ", ConfigPath: confPath, StateDir: stateDir, Out: &out,
		HTTP: srv.Client(), SkipRootTest: true, Preflight: func(config.Config) error { return nil },
		Detect: func() (Detected, error) {
			return Detected{ZoneSource: "bind", ZonesFile: "/etc/bind/named.conf", OwnersFile: "/etc/virtual/domainowners"}, nil
		},
		After: func(ctx context.Context, cfg config.Config, d Detected) error {
			afterCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != "abcdefgh" || got.Backend != "bind" || got.AgentVersion == "" {
		t.Fatalf("request %+v", got)
	}
	pub, _ := base64.StdEncoding.DecodeString(got.PublicKey)
	key, err := state.LoadKey(filepath.Join(stateDir, state.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key[32:], pub) {
		t.Fatal("sent public key does not match the stored private key")
	}
	id, err := state.LoadIdentity(filepath.Join(stateDir, state.IdentityFile))
	if err != nil || id.SourceID != "17" || id.KeyID != "4" || id.ClusterName != "Brand A" {
		t.Fatalf("identity %+v %v", id, err)
	}
	seq := &state.Sequence{Path: filepath.Join(stateDir, state.SequenceFile)}
	if e, n, err := seq.Current(); e != 2 || n != 0 || err != nil {
		t.Fatalf("sequence %d %d %v", e, n, err)
	}
	if _, existed, _ := state.Load(filepath.Join(stateDir, state.StateFile)); !existed {
		t.Fatal("state.json not written")
	}
	if _, err := os.Stat(filepath.Join(stateDir, state.NextKeyFile)); err == nil {
		t.Fatal("stale next key left behind")
	}
	cfg, err := config.Load(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != srv.URL || cfg.ZonesFile != "/etc/bind/named.conf" || cfg.OwnersFile != "/etc/virtual/domainowners" || cfg.Interval != 60 {
		t.Fatalf("config %+v", cfg)
	}
	if !afterCalled || res.Epoch != 2 {
		t.Fatal("after hook not run")
	}
	if !strings.Contains(out.String(), "IP allowlist: 192.0.2.10") || !strings.Contains(out.String(), `setup "Brand A"`) {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestEnrolErrors(t *testing.T) {
	detect := func() (Detected, error) { return Detected{ZoneSource: "bind", ZonesFile: "/etc/named.conf"}, nil }
	tests := []struct {
		name, url, code string
		status          int
		body, want      string
	}{
		{"http url", "http://app.example.com", "x", 0, "", "https"},
		{"no code", "", "  ", 0, "", "--code"},
		{"bad code", "", "x", 401, `{"error":"invalid_code"}`, "did not accept the enrolment code"},
		{"ip refused", "", "x", 403, `{"error":"ip_refused","ip":"192.0.2.99"}`, "came from 192.0.2.99"},
		{"rate limited", "", "x", 429, `{"error":"rate_limited"}`, "too many"},
		{"server error", "", "x", 500, `oops`, "enrolment failed"},
		{"bad ids", "", "x", 200, `{"source_id":"1.2","key_id":"3","epoch":1}`, "unusable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got protocol.EnrolRequest
			srv := enrolServer(t, tt.status, tt.body, &got)
			url := tt.url
			if url == "" {
				url = srv.URL
			}
			dir := t.TempDir()
			_, err := Run(context.Background(), Options{
				URL: url, Code: tt.code, ConfigPath: filepath.Join(dir, "c.conf"), StateDir: filepath.Join(dir, "s"),
				HTTP: srv.Client(), SkipRootTest: true, Detect: detect, Preflight: func(config.Config) error { return nil },
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want %q, got %v", tt.want, err)
			}
			// Nothing is written when enrolment fails.
			if _, err := os.Stat(filepath.Join(dir, "s", state.KeyFile)); err == nil {
				t.Fatal("key written although enrolment failed")
			}
		})
	}
}
