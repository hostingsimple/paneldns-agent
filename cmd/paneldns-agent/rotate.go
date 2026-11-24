package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// Key rotation (spec 8.1, docs/DECISIONS.md D-19, security review A-15).
//
// The new key is written to agent.key.next before /rotate is sent, and
// both keys are kept until PanelDNS has shown which one it holds. Before,
// a lost answer (a timeout, a proxy error, a crash) discarded the new key:
// PanelDNS had already switched to it, the old key stopped working after
// 24 hours, and the server had to be enrolled again.

func (a *agent) path(n string) string { return filepath.Join(a.stateDir, n) }

// rotate is the engine's Rotate hook: it finishes a pending rotation if
// there is one, else starts a new one.
func (a *agent) rotate(ctx context.Context) error {
	if _, err := os.Stat(a.path(state.NextKeyFile)); err == nil {
		return a.resolvePending(ctx)
	}
	key, err := state.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := state.WriteKey(a.path(state.NextKeyFile), key); err != nil {
		return err
	}
	resp, err := a.client.Rotate(ctx, key.Public().(ed25519.PublicKey))
	if err == nil {
		return a.commitRotation(key, string(resp.KeyID))
	}
	if refusedOutright(err) {
		// PanelDNS answered with a refusal: it registered nothing.
		os.Remove(a.path(state.NextKeyFile))
		return err
	}
	return fmt.Errorf("%w: %v", engine.ErrRotationPending, err)
}

// refusedOutright reports a /rotate error after which PanelDNS certainly
// holds the old key still: a 4xx refusal (409 rotation_not_requested, 401,
// 403 ip_refused, 429, ...). Transport errors, 5xx (a proxy may have timed
// out after PanelDNS committed) and a 2xx without a usable key id leave the
// outcome unknown.
func refusedOutright(err error) bool {
	var ae *protocol.APIError
	return errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500
}

// signatureAccepted classifies an answer to a request signed with a key
// PanelDNS may or may not hold. PanelDNS checks, in order (PanelDNS's
// docs/panel-sync-protocol-notes.md S-05): key header, enrolment, IP
// allowlist, rate limits, body size, time stamp, signature, then nonce,
// epoch, sequence, minimum version and the body. So 401 means the key was
// not accepted; any answer only given after the signature check (2xx, 400,
// 409, 426) means it was; anything else (403, 413, 429, 5xx, no answer)
// says nothing.
func signatureAccepted(err error) (accepted, known bool) {
	if err == nil {
		return true, true
	}
	var ae *protocol.APIError
	if !errors.As(err, &ae) {
		return false, false
	}
	switch {
	case ae.Status == http.StatusUnauthorized:
		return false, true
	case ae.Status >= 200 && ae.Status < 300, ae.Status == http.StatusBadRequest,
		ae.Status == http.StatusConflict, ae.Status == http.StatusUpgradeRequired:
		return true, true
	}
	return false, false
}

// resolvePending settles a rotation whose answer was lost: agent.key.next
// exists but identity.json has no key id for it.
//
//  1. Send /rotate again with the same new key, signed with the current
//     key. If PanelDNS still wants a rotation, it registers the key now and
//     answers with its id.
//  2. Otherwise (409 rotation_not_requested: the first request did get
//     through, or the request was cancelled; 400: the key is the current
//     one already; 401: the current key no longer works) sign a request
//     with the new key under the key id PanelDNS gives a rotated key, one
//     above the current one, and see whether PanelDNS accepts the
//     signature. If it does, the new key is PanelDNS's key: keep it. If it
//     answers 401, PanelDNS never registered it: drop it.
//
// Until one of these gives an answer, both keys stay and the current one
// is used (it keeps working for 24 hours after a rotation).
func (a *agent) resolvePending(ctx context.Context) error {
	next := a.path(state.NextKeyFile)
	key, err := state.LoadKey(next)
	if err != nil {
		os.Remove(next)
		return fmt.Errorf("unreadable %s removed: %w", next, err)
	}
	pub := key.Public().(ed25519.PublicKey)
	resp, err := a.client.Rotate(ctx, pub)
	if err == nil {
		a.log.Info("key rotation: PanelDNS registered the new key on the second try")
		return a.commitRotation(key, string(resp.KeyID))
	}
	var ae *protocol.APIError
	if !errors.As(err, &ae) || (ae.Status != http.StatusConflict && ae.Status != http.StatusBadRequest && ae.Status != http.StatusUnauthorized) {
		return fmt.Errorf("%w: %v", engine.ErrRotationPending, err)
	}
	oldRefused := ae.Status == http.StatusUnauthorized
	cand, ok := nextKeyID(a.id.KeyID)
	if !ok {
		os.Remove(next)
		return fmt.Errorf("key rotation: can't tell whether PanelDNS holds the new key (key id %q is not a number); it was dropped, and if the current key stops working the server must be enrolled again", a.id.KeyID)
	}
	probe := &protocol.Client{BaseURL: a.client.BaseURL, HTTP: a.client.HTTP, Seq: a.client.Seq, Now: a.client.Now, Rand: a.client.Rand}
	probe.SetKey(key, a.id.SourceID, cand)
	presp, perr := probe.Rotate(ctx, pub)
	accepted, known := signatureAccepted(perr)
	switch {
	case !known:
		return fmt.Errorf("%w: %v", engine.ErrRotationPending, perr)
	case accepted:
		id := cand
		if perr == nil {
			id = string(presp.KeyID)
		}
		a.log.Info("key rotation: the answer to /rotate was lost, but PanelDNS holds the new key; using it", "key_id", id)
		return a.commitRotation(key, id)
	}
	os.Remove(next)
	if oldRefused {
		return errors.New("key rotation: PanelDNS refuses both the current and the new key; enrol this server again with a new code from the dashboard")
	}
	a.log.Info("key rotation: PanelDNS never registered the new key; it was dropped and the current key stays")
	return nil
}

// nextKeyID is the key id PanelDNS gives a rotated key: the current one
// plus one (PanelDNS AgentIngestController::rotate). The protocol keeps key
// ids opaque, so this is only used to check a key PanelDNS may already
// hold, never to send traffic it hasn't confirmed.
func nextKeyID(cur string) (string, bool) {
	n, err := strconv.ParseUint(cur, 10, 63)
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(n+1, 10), true
}

// commitRotation switches to the new key PanelDNS holds under keyID. The
// key id goes into identity.json first (NextKeyID), then the key file is
// renamed, then the key id becomes the current one, so a crash at any
// point leaves enough on disk for recoverRotation.
func (a *agent) commitRotation(key ed25519.PrivateKey, keyID string) error {
	a.id.NextKeyID = keyID
	if err := a.id.Save(a.path(state.IdentityFile)); err != nil {
		a.id.NextKeyID = ""
		return fmt.Errorf("%w: saving the new key id: %v", engine.ErrRotationPending, err)
	}
	if err := os.Rename(a.path(state.NextKeyFile), a.path(state.KeyFile)); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrRotationPending, err)
	}
	a.id.KeyID, a.id.NextKeyID = keyID, ""
	a.key = key
	a.client.SetKey(key, a.id.SourceID, a.id.KeyID)
	if err := a.id.Save(a.path(state.IdentityFile)); err != nil {
		return err
	}
	a.log.Info("key rotated", "key_id", a.id.KeyID)
	return nil
}

// recoverRotation runs at start. A commit interrupted by a crash is
// finished from what is on disk; a new key whose fate is unknown makes the
// engine resolve it (keyPending) before anything else.
func (a *agent) recoverRotation() (keyPending bool, err error) {
	next := a.path(state.NextKeyFile)
	_, statErr := os.Stat(next)
	nextExists := statErr == nil
	if a.id.NextKeyID != "" {
		if nextExists {
			if err := os.Rename(next, a.path(state.KeyFile)); err != nil {
				return false, err
			}
		}
		key, err := state.LoadKey(a.path(state.KeyFile))
		if err != nil {
			return false, err
		}
		a.id.KeyID, a.id.NextKeyID = a.id.NextKeyID, ""
		if err := a.id.Save(a.path(state.IdentityFile)); err != nil {
			return false, err
		}
		a.key = key
		a.client.SetKey(key, a.id.SourceID, a.id.KeyID)
		a.log.Info("key rotation: finished an interrupted switch to the new key", "key_id", a.id.KeyID)
		return false, nil
	}
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return false, statErr
	}
	if nextExists {
		a.log.Info("key rotation: a new key from an earlier rotation is waiting; checking which key PanelDNS holds")
	}
	return nextExists, nil
}
