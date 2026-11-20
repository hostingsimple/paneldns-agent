package protocol

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/version"
)

// Sequencer hands out (epoch, seq) pairs; seq only increases within an
// epoch (internal/state.Sequence).
type Sequencer interface {
	Next() (epoch, seq uint64, err error)
	SetEpoch(epoch uint64) error
}

// MaxResponseBytes caps a response body.
const MaxResponseBytes = 4 << 20

// Client speaks the ingest API. Requests are sent one at a time.
type Client struct {
	BaseURL string // PANELDNS_URL, https only
	HTTP    *http.Client
	Seq     Sequencer
	Now     func() time.Time
	Rand    io.Reader

	mu       sync.Mutex
	key      ed25519.PrivateKey
	keyID    string // "<source id>.<key id>"
	lastDate time.Time
	lastSent time.Time
}

// NewHTTPClient returns the HTTP client the agent uses: system roots, TLS
// 1.2 or later, certificate verification always on, no redirects.
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.Proxy = http.ProxyFromEnvironment
	return &http.Client{
		Transport: tr,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// SetKey sets the signing key and the X-PanelDNS-Key value.
func (c *Client) SetKey(key ed25519.PrivateKey, sourceID, keyID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.key = key
	c.keyID = sourceID + "." + keyID
}

// ServerDate is the Date header of the last answer (for the clock-skew
// check) and the local time it was received.
func (c *Client) ServerDate() (server, local time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastDate, c.lastSent
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) nonce() (string, error) {
	r := c.Rand
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Gzip compresses a body. The gzip header carries no name and no time.
func Gzip(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// do sends one request. build returns the body for the (epoch, seq) the
// request is signed with, so payload sequence numbers match the header.
func (c *Client) do(ctx context.Context, path string, signed bool, build func(epoch, seq uint64) any, out any) error {
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + path)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing to send to %s: only https is used", u.Redacted())
	}
	var epoch, seq uint64
	if signed {
		if c.Seq == nil {
			return errors.New("no sequence store")
		}
		epoch, seq, err = c.Seq.Next()
		if err != nil {
			return fmt.Errorf("sequence: %w", err)
		}
	}
	raw, err := json.Marshal(build(epoch, seq))
	if err != nil {
		return err
	}
	body := Gzip(raw)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set(HeaderAgentVersion, version.Version)
	if signed {
		c.mu.Lock()
		key, keyID := c.key, c.keyID
		c.mu.Unlock()
		if key == nil {
			return errors.New("no signing key loaded")
		}
		nonce, err := c.nonce()
		if err != nil {
			return err
		}
		ts := c.now().Unix()
		req.Header.Set(HeaderKey, keyID)
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(HeaderNonce, nonce)
		req.Header.Set(HeaderEpoch, strconv.FormatUint(epoch, 10))
		req.Header.Set(HeaderSeq, strconv.FormatUint(seq, 10))
		req.Header.Set(HeaderSignature, Sign(key, http.MethodPost, u.EscapedPath(), ts, nonce, epoch, seq, body))
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = NewHTTPClient()
	}
	sent := c.now()
	resp, err := httpc.Do(req)
	if err != nil {
		return &APIError{Path: path, Err: err}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return &APIError{Path: path, Err: err}
	}
	if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		c.mu.Lock()
		c.lastDate, c.lastSent = d, sent
		c.mu.Unlock()
	}
	if len(data) > MaxResponseBytes {
		return &APIError{Path: path, Status: resp.StatusCode, Message: "response too large"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Path: path, Status: resp.StatusCode}
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil {
			ae.Code, ae.Message, ae.IP = eb.Error, eb.Message, eb.IP
		} else {
			ae.Message = strings.TrimSpace(string(data))
			if len(ae.Message) > 300 {
				ae.Message = ae.Message[:300]
			}
		}
		if d, ok := ParseRetryAfter(resp.Header.Get("Retry-After"), c.now()); ok {
			ae.RetryAfter = d
		}
		return ae
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s: bad response: %w", path, err)
		}
	}
	return nil
}

func fixed(v any) func(uint64, uint64) any { return func(uint64, uint64) any { return v } }

// Enrol exchanges a one-time code for a source id, key id and epoch. It is
// the only unsigned request.
func (c *Client) Enrol(ctx context.Context, r *EnrolRequest) (*EnrolResponse, error) {
	out := &EnrolResponse{}
	if err := c.do(ctx, PathEnrol, false, fixed(r), out); err != nil {
		return nil, err
	}
	if out.SourceID == "" || out.KeyID == "" || strings.Contains(string(out.SourceID), ".") || strings.Contains(string(out.KeyID), ".") {
		return nil, fmt.Errorf("enrol: the server sent an unusable source or key id")
	}
	return out, nil
}

// Epoch asks for a new epoch after state loss or epoch_stale and stores
// it in the sequence store (seq restarts at 1).
func (c *Client) Epoch(ctx context.Context) (*EpochResponse, error) {
	out := &EpochResponse{}
	if err := c.do(ctx, PathEpoch, true, fixed(struct{}{}), out); err != nil {
		return nil, err
	}
	if out.Epoch == 0 {
		return nil, fmt.Errorf("epoch: the server sent epoch 0")
	}
	if err := c.Seq.SetEpoch(out.Epoch); err != nil {
		return nil, err
	}
	return out, nil
}

// Rotate registers a new public key, signed with the current key.
func (c *Client) Rotate(ctx context.Context, newPub ed25519.PublicKey) (*RotateResponse, error) {
	out := &RotateResponse{}
	if err := c.do(ctx, PathRotate, true, fixed(&RotateRequest{PublicKey: EncodePublicKey(newPub)}), out); err != nil {
		return nil, err
	}
	if out.KeyID == "" || strings.Contains(string(out.KeyID), ".") {
		return nil, fmt.Errorf("rotate: the server sent an unusable key id")
	}
	return out, nil
}

// Heartbeat implements engine.API.
func (c *Client) Heartbeat(ctx context.Context, r *HeartbeatRequest) (*HeartbeatResponse, error) {
	out := &HeartbeatResponse{}
	return out, c.do(ctx, PathHeartbeat, true, fixed(r), out)
}

// Inventory implements engine.API.
func (c *Client) Inventory(ctx context.Context, r *InventoryRequest) (*InventoryResponse, error) {
	out := &InventoryResponse{}
	return out, c.do(ctx, PathInventory, true, fixed(r), out)
}

// Zones implements engine.API. Every zone carries the request's seq.
func (c *Client) Zones(ctx context.Context, r *ZonesRequest) (*ZonesResponse, error) {
	out := &ZonesResponse{}
	return out, c.do(ctx, PathZones, true, func(_, seq uint64) any {
		for i := range r.Zones {
			r.Zones[i].Seq = seq
		}
		return r
	}, out)
}

// Deletions implements engine.API. Every name carries the request's seq.
func (c *Client) Deletions(ctx context.Context, r *DeletionsRequest) (*DeletionsResponse, error) {
	out := &DeletionsResponse{}
	return out, c.do(ctx, PathDeletions, true, func(_, seq uint64) any {
		for i := range r.Deletions {
			r.Deletions[i].Seq = seq
		}
		return r
	}, out)
}
