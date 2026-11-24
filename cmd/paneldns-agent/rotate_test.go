package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// fakePanel answers like PanelDNS 3.119 (VerifyAgentRequest and
// AgentIngestController::rotate): the signature is checked against the
// current key for the current key id, or the previous key for its id while
// it is valid; the previous key stops working once the current one is used;
// /rotate needs a requested rotation, refuses the current key, and gives the
// new key the next key id.
type fakePanel struct {
	mu        sync.Mutex
	cur       ed25519.PublicKey
	curID     int
	prev      ed25519.PublicKey
	prevID    int
	requested bool
	// lose: what happens to the answer of a /rotate PanelDNS commits:
	// "" answers, "drop" closes the connection, "502" answers 502 (a proxy).
	lose string
	// failBefore answers /rotate with 502 without committing.
	failBefore bool
	srv        *httptest.Server
	got        []string // "path key-id status"
}

type fakeSeq struct{ seq uint64 }

func (s *fakeSeq) Next() (uint64, uint64, error) { s.seq++; return 1, s.seq, nil }
func (s *fakeSeq) SetEpoch(uint64) error         { return nil }

func newFakePanel(t *testing.T, pub ed25519.PublicKey) *fakePanel {
	f := &fakePanel{cur: pub, curID: 3}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePanel) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	_, kid, _ := strings.Cut(r.Header.Get(protocol.HeaderKey), ".")
	id, _ := strconv.Atoi(kid)
	ts, _ := strconv.ParseInt(r.Header.Get(protocol.HeaderTimestamp), 10, 64)
	epoch, _ := strconv.ParseUint(r.Header.Get(protocol.HeaderEpoch), 10, 64)
	seq, _ := strconv.ParseUint(r.Header.Get(protocol.HeaderSeq), 10, 64)
	verify := func(pub ed25519.PublicKey) bool {
		return pub != nil && protocol.Verify(pub, r.Header.Get(protocol.HeaderSignature), r.Method, r.URL.Path, ts, r.Header.Get(protocol.HeaderNonce), epoch, seq, body)
	}
	answer := func(status int, v string) {
		f.got = append(f.got, r.URL.Path+" "+kid+" "+strconv.Itoa(status))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, v)
	}
	switch {
	case id == f.curID && verify(f.cur):
		f.prev = nil // the old key stops working once the new one is used
	case id == f.prevID && verify(f.prev):
	default:
		answer(401, `{"error":"unauthorized","message":"The request signature is not valid."}`)
		return
	}
	if r.URL.Path != protocol.PathRotate {
		answer(200, `{}`)
		return
	}
	if f.failBefore {
		answer(502, `bad gateway`)
		return
	}
	if !f.requested {
		answer(409, `{"error":"rotation_not_requested"}`)
		return
	}
	zr, _ := gzip.NewReader(bytes.NewReader(body))
	raw, _ := io.ReadAll(zr)
	var req protocol.RotateRequest
	json.Unmarshal(raw, &req)
	pk, _ := base64.StdEncoding.DecodeString(req.PublicKey)
	if len(pk) != ed25519.PublicKeySize || bytes.Equal(pk, f.cur) {
		answer(400, `{"error":"bad_request"}`)
		return
	}
	f.prev, f.prevID = f.cur, f.curID
	f.cur, f.curID, f.requested = ed25519.PublicKey(pk), f.curID+1, false
	switch f.lose {
	case "drop":
		f.got = append(f.got, r.URL.Path+" "+kid+" dropped")
		hj, _ := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
	case "502":
		answer(502, `bad gateway`)
	default:
		answer(200, `{"key_id":"`+strconv.Itoa(f.curID)+`"}`)
	}
}

func newRotateAgent(t *testing.T) (*agent, *fakePanel) {
	t.Helper()
	dir := t.TempDir()
	key, _ := state.GenerateKey(nil)
	if err := state.WriteKey(filepath.Join(dir, state.KeyFile), key); err != nil {
		t.Fatal(err)
	}
	f := newFakePanel(t, key.Public().(ed25519.PublicKey))
	a := &agent{stateDir: dir, key: key, log: slog.New(slog.DiscardHandler),
		id: &state.Identity{SourceID: "7", KeyID: "3"}}
	a.id.Save(filepath.Join(dir, state.IdentityFile))
	a.client = &protocol.Client{BaseURL: f.srv.URL, HTTP: f.srv.Client(), Seq: &fakeSeq{}}
	a.client.SetKey(key, "7", "3")
	return a, f
}

func (a *agent) heartbeatOK(t *testing.T) {
	t.Helper()
	if _, err := a.client.Heartbeat(context.Background(), &protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("heartbeat with key %s: %v", a.id.KeyID, err)
	}
}

func onDisk(t *testing.T, a *agent) (key ed25519.PrivateKey, id *state.Identity, next bool) {
	t.Helper()
	key, err := state.LoadKey(a.path(state.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	id, err = state.LoadIdentity(a.path(state.IdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(a.path(state.NextKeyFile))
	return key, id, err == nil
}

func TestRotate(t *testing.T) {
	ctx := context.Background()
	t.Run("answered", func(t *testing.T) {
		a, f := newRotateAgent(t)
		f.requested = true
		if err := a.rotate(ctx); err != nil {
			t.Fatal(err)
		}
		key, id, next := onDisk(t, a)
		if id.KeyID != "4" || next || !key.Equal(a.key) || !bytes.Equal(f.cur, key.Public().(ed25519.PublicKey)) {
			t.Fatalf("id %+v next %v", id, next)
		}
		a.heartbeatOK(t)
	})

	// Review A-15: PanelDNS switched to the new key but its answer never
	// arrived. 0.1.4 dropped the new key and was locked out after 24 hours.
	for _, lose := range []string{"drop", "502"} {
		t.Run("answer lost: "+lose, func(t *testing.T) {
			a, f := newRotateAgent(t)
			f.requested, f.lose = true, lose
			old := a.key
			if err := a.rotate(ctx); !errors.Is(err, engine.ErrRotationPending) {
				t.Fatalf("want pending, got %v", err)
			}
			if _, _, next := onDisk(t, a); !next || !a.key.Equal(old) {
				t.Fatal("the new key was not kept, or the old one was replaced")
			}
			a.heartbeatOK(t) // the old key still works meanwhile (24 h)
			f.lose = ""
			if err := a.rotate(ctx); err != nil {
				t.Fatalf("resolving: %v (requests %v)", err, f.got)
			}
			key, id, next := onDisk(t, a)
			if id.KeyID != "4" || next || id.NextKeyID != "" || !bytes.Equal(f.cur, key.Public().(ed25519.PublicKey)) {
				t.Fatalf("id %+v next %v", id, next)
			}
			a.heartbeatOK(t)
			if f.prev != nil {
				t.Fatal("PanelDNS still accepts the old key")
			}
		})
	}

	t.Run("answer lost, old key expired meanwhile", func(t *testing.T) {
		a, f := newRotateAgent(t)
		f.requested, f.lose = true, "drop"
		a.rotate(ctx)
		f.prev, f.lose = nil, "" // 24 hours later
		if err := a.rotate(ctx); err != nil {
			t.Fatalf("resolving: %v (requests %v)", err, f.got)
		}
		if _, id, _ := onDisk(t, a); id.KeyID != "4" {
			t.Fatalf("id %+v", id)
		}
		a.heartbeatOK(t)
	})

	t.Run("request lost before PanelDNS, still requested", func(t *testing.T) {
		a, f := newRotateAgent(t)
		f.requested, f.failBefore = true, true
		if err := a.rotate(ctx); !errors.Is(err, engine.ErrRotationPending) {
			t.Fatalf("want pending, got %v", err)
		}
		pending, _ := state.LoadKey(a.path(state.NextKeyFile))
		f.failBefore = false
		if err := a.rotate(ctx); err != nil {
			t.Fatal(err)
		}
		key, id, _ := onDisk(t, a)
		if id.KeyID != "4" || !key.Equal(pending) {
			t.Fatalf("id %+v; the pending key was not the one registered", id)
		}
		a.heartbeatOK(t)
	})

	t.Run("request lost before PanelDNS, request withdrawn", func(t *testing.T) {
		a, f := newRotateAgent(t)
		f.requested, f.failBefore = true, true
		a.rotate(ctx)
		f.failBefore, f.requested = false, false
		old := a.key
		if err := a.rotate(ctx); err != nil {
			t.Fatal(err)
		}
		key, id, next := onDisk(t, a)
		if id.KeyID != "3" || next || !key.Equal(old) {
			t.Fatalf("id %+v next %v", id, next)
		}
		a.heartbeatOK(t)
	})

	t.Run("refused outright", func(t *testing.T) {
		a, f := newRotateAgent(t)
		err := a.rotate(ctx) // not requested: 409
		var ae *protocol.APIError
		if !errors.As(err, &ae) || ae.Status != 409 || errors.Is(err, engine.ErrRotationPending) {
			t.Fatalf("got %v", err)
		}
		if _, _, next := onDisk(t, a); next {
			t.Fatal("new key kept after a refusal")
		}
		_ = f
	})
}

// A crash part way through the commit is finished at start.
func TestRecoverRotation(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		a, _ := newRotateAgent(t)
		nk, _ := state.GenerateKey(nil)
		state.WriteKey(a.path(state.NextKeyFile), nk)
		a.id.NextKeyID = "4"
		a.id.Save(a.path(state.IdentityFile))
		if renamed {
			os.Rename(a.path(state.NextKeyFile), a.path(state.KeyFile))
		}
		pending, err := a.recoverRotation()
		if err != nil || pending {
			t.Fatalf("renamed %v: pending %v err %v", renamed, pending, err)
		}
		key, id, next := onDisk(t, a)
		if id.KeyID != "4" || id.NextKeyID != "" || next || !key.Equal(nk) || !a.key.Equal(nk) {
			t.Fatalf("renamed %v: id %+v next %v", renamed, id, next)
		}
	}
	a, _ := newRotateAgent(t)
	nk, _ := state.GenerateKey(nil)
	state.WriteKey(a.path(state.NextKeyFile), nk)
	if pending, err := a.recoverRotation(); err != nil || !pending {
		t.Fatalf("unknown outcome: pending %v err %v", pending, err)
	}
	if _, _, next := onDisk(t, a); !next {
		t.Fatal("the pending key was removed at start")
	}
}

func TestNextKeyID(t *testing.T) {
	if id, ok := nextKeyID("41"); !ok || id != "42" {
		t.Fatal(id)
	}
	if _, ok := nextKeyID("k-1"); ok {
		t.Fatal("non-numeric")
	}
}
