package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// PowerDNS reads zones through the PowerDNS Authoritative HTTP API on the
// loopback address (spec 7.3): the zone list and each zone's export.
// API: https://doc.powerdns.com/authoritative/http-api/zone.html
type PowerDNS struct {
	BaseURL string // PDNS_API_URL, e.g. http://127.0.0.1:8081
	KeyFile string // PDNS_API_KEY_FILE
	// ServerID is the API server id; spec 7.3 fixes it to "localhost".
	ServerID string
	Client   *http.Client
	// CheckListener refuses an API address whose listening socket is not
	// PowerDNS's (listener.go); nil checks /proc/net/tcp. Tests replace it.
	CheckListener func(base string) error

	mu  sync.Mutex
	key string
}

// MaxExportSize caps one zone export.
const MaxExportSize = 32 << 20

// Kind implements Source.
func (p *PowerDNS) Kind() string { return "powerdns-api" }

func (p *PowerDNS) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		// Never follow a redirect: Go would send X-API-Key (a read-write
		// key) along to wherever it points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (p *PowerDNS) apiKey(reload bool) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key != "" && !reload {
		return p.key, nil
	}
	b, err := os.ReadFile(p.KeyFile)
	if err != nil {
		return "", fmt.Errorf("PowerDNS API key: %w", err)
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", fmt.Errorf("PowerDNS API key file %s is empty", p.KeyFile)
	}
	p.key = k
	return k, nil
}

func (p *PowerDNS) serverID() string {
	if p.ServerID != "" {
		return p.ServerID
	}
	return "localhost"
}

func (p *PowerDNS) get(ctx context.Context, rel string, limit int64) (*http.Response, []byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		key, err := p.apiKey(attempt > 0)
		if err != nil {
			return nil, nil, err
		}
		check := p.CheckListener
		if check == nil {
			check = func(base string) error { return checkListener(base, osReadFile) }
		}
		if err := check(p.BaseURL); err != nil {
			return nil, nil, fmt.Errorf("PowerDNS API: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.BaseURL, "/")+rel, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("X-API-Key", key)
		req.Header.Set("Accept", "application/json, text/plain")
		resp, err := p.client().Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("PowerDNS API: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("PowerDNS API: %w", err)
		}
		if int64(len(body)) > limit {
			return nil, nil, fmt.Errorf("PowerDNS API: response larger than %d bytes", limit)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue // the key may have been replaced on disk
		}
		if resp.StatusCode != http.StatusOK {
			msg := strings.TrimSpace(string(body))
			var e struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(body, &e) == nil && e.Error != "" {
				msg = e.Error
			}
			if len(msg) > 500 {
				msg = msg[:500]
			}
			if resp.StatusCode == http.StatusUnauthorized {
				msg = "unauthorized (check PDNS_API_KEY_FILE)"
			}
			return resp, nil, fmt.Errorf("PowerDNS API %s: HTTP %d: %s", rel, resp.StatusCode, msg)
		}
		return resp, body, nil
	}
	return nil, nil, errors.New("PowerDNS API: no attempt made")
}

type pdnsZone struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Serial       uint32 `json:"serial"`
	EditedSerial uint32 `json:"edited_serial"`
}

// isPrimaryKind keeps Native and Master (Primary in newer releases) zones;
// Slave/Secondary, Producer and Consumer (catalog) zones are skipped.
func isPrimaryKind(k string) bool {
	switch strings.ToLower(k) {
	case "native", "master", "primary":
		return true
	}
	return false
}

// List implements Source.
func (p *PowerDNS) List(ctx context.Context) (*Listing, error) {
	_, body, err := p.get(ctx, "/api/v1/servers/"+url.PathEscape(p.serverID())+"/zones?dnssec=false", 64<<20)
	if err != nil {
		return nil, err
	}
	var zs []pdnsZone
	if err := json.Unmarshal(body, &zs); err != nil {
		return nil, fmt.Errorf("PowerDNS zone list: %w", err)
	}
	out := &Listing{Backend: "powerdns-api"}
	for _, z := range zs {
		if !isPrimaryKind(z.Kind) {
			out.Skipped++
			continue
		}
		if z.ID == "" || z.Name == "" {
			out.Warnings = append(out.Warnings, "PowerDNS listed a zone without id or name")
			continue
		}
		out.Zones = append(out.Zones, ZoneRef{
			Name:        normalize(z.Name),
			Fingerprint: "s=" + strconv.FormatUint(uint64(z.Serial), 10) + ";e=" + strconv.FormatUint(uint64(z.EditedSerial), 10),
			key:         z.ID,
		})
	}
	return out, nil
}

func normalize(n string) string {
	n = strings.ToLower(n)
	if n == "." {
		return n
	}
	return strings.TrimSuffix(n, ".")
}

// Read implements Source: GET .../zones/{id}/export returns the zone in
// AXFR format, as text/plain (older releases wrap it as {"zone": "..."}).
func (p *PowerDNS) Read(ctx context.Context, ref ZoneRef) ([]zonefile.RR, error) {
	resp, body, err := p.get(ctx, "/api/v1/servers/"+url.PathEscape(p.serverID())+"/zones/"+url.PathEscape(ref.key)+"/export", MaxExportSize)
	if err != nil {
		return nil, err
	}
	text := body
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt == "application/json" {
		var wrapped struct {
			Zone string `json:"zone"`
		}
		if err := json.Unmarshal(body, &wrapped); err != nil {
			return nil, fmt.Errorf("PowerDNS export of %s: %w", ref.Name, err)
		}
		text = []byte(wrapped.Zone)
	}
	return zonefile.Parse(text, zonefile.Options{Origin: ref.Name, File: ref.Name + " (PowerDNS export)"})
}

// Running implements Source: the API answering means PowerDNS runs.
func (p *PowerDNS) Running(ctx context.Context) (Running, string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, _, err := p.get(ctx, "/api/v1/servers/"+url.PathEscape(p.serverID()), 1<<20)
	if err != nil && resp == nil {
		return RunningNo, err.Error()
	}
	if err != nil {
		return RunningYes, "API answered with an error: " + err.Error()
	}
	return RunningYes, "API answered"
}
