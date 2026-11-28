// Package protocol implements the PanelDNS ingest API (spec section 8) as
// the agent speaks it: wire types, request signing and the HTTP client.
// docs/PROTOCOL.md is the normative description; keep the two in step.
package protocol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BasePath is the ingest API's path prefix under PANELDNS_URL.
const BasePath = "/api/agent/v1"

// Endpoint paths (spec 8.3).
const (
	PathEnrol     = BasePath + "/enrol"
	PathRotate    = BasePath + "/rotate"
	PathEpoch     = BasePath + "/epoch"
	PathHeartbeat = BasePath + "/heartbeat"
	PathInventory = BasePath + "/inventory"
	PathZones     = BasePath + "/zones"
	PathDeletions = BasePath + "/deletions"
	// PathCheckReport takes a --check report (D-35).
	PathCheckReport = BasePath + "/check-report"
)

// Limits the agent applies before sending (spec 7.5, 8.5).
const (
	MaxZonesPerBatch   = 100
	MaxBatchBytes      = 8 << 20 // uncompressed JSON body
	MaxZoneTextBytes   = 2 << 20
	MaxInventoryNames  = 20000
	MaxDeletionsPerReq = 1000
	MaxHeartbeatErrors = 100
)

// Per-zone statuses in /zones and /deletions answers (spec 8.4).
const (
	StatusAccepted       = "accepted"
	StatusUnchanged      = "unchanged"
	StatusStored         = "stored"
	StatusSkippedRecords = "skipped_records"
	StatusRefused        = "refused"
	StatusHeld           = "held"
	StatusExcluded       = "excluded"
	StatusDeleted        = "deleted" // /deletions only (docs/PROTOCOL.md)
)

// Acknowledged reports whether a status means "the server has this
// content"; the agent then records the hash and stops sending it.
func Acknowledged(status string) bool {
	switch status {
	case StatusAccepted, StatusUnchanged, StatusStored, StatusSkippedRecords, StatusHeld, StatusExcluded:
		return true
	}
	return false
}

// ID is a server-issued identifier. The server should send strings;
// JSON numbers are accepted too.
type ID string

// UnmarshalJSON accepts a string or a number.
func (id *ID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*id = ID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("id must be a string or a number")
	}
	*id = ID(n.String())
	return nil
}

// EnrolRequest is POST /enrol (spec 8.1).
type EnrolRequest struct {
	Code         string   `json:"code"`
	PublicKey    string   `json:"public_key"` // base64 of the 32-byte Ed25519 key
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	Backend      string   `json:"backend"`
	Panel        string   `json:"panel"`
	PublicIPs    []string `json:"public_ips"`
	AgentVersion string   `json:"agent_version"`
}

// EnrolResponse answers /enrol.
type EnrolResponse struct {
	SourceID    ID       `json:"source_id"`
	KeyID       ID       `json:"key_id"`
	Epoch       uint64   `json:"epoch"`
	ClusterName string   `json:"cluster_name,omitempty"`
	SourceName  string   `json:"source_name,omitempty"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
}

// RotateRequest is POST /rotate, signed with the old key.
type RotateRequest struct {
	PublicKey string `json:"public_key"`
}

// RotateResponse answers /rotate.
type RotateResponse struct {
	KeyID ID `json:"key_id"`
}

// EpochResponse answers POST /epoch (empty JSON object body).
type EpochResponse struct {
	Epoch uint64 `json:"epoch"`
}

// ZoneError is one problem reported in a heartbeat.
type ZoneError struct {
	Zone    string `json:"zone,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// HeartbeatRequest is POST /heartbeat.
type HeartbeatRequest struct {
	AgentVersion    string      `json:"agent_version"`
	Hostname        string      `json:"hostname"`
	OS              string      `json:"os"`
	Backend         string      `json:"backend"`
	Panel           string      `json:"panel"`
	View            string      `json:"view,omitempty"`
	PublicIPs       []string    `json:"public_ips"`
	ZoneCount       int         `json:"zone_count"`
	ExcludedCount   int         `json:"excluded_count"`
	SignedCount     int         `json:"signed_count"`
	ScanStartedAt   int64       `json:"scan_started_at"`
	ScanCompletedAt int64       `json:"scan_completed_at"`
	Errors          []ZoneError `json:"errors"`
	Check           bool        `json:"check,omitempty"` // sent by --check
}

// Overlay is the server's config overlay (spec 7.2).
type Overlay struct {
	Interval int      `json:"interval,omitempty"`
	Resync   int      `json:"resync,omitempty"`
	Exclude  []string `json:"exclude,omitempty"`
}

// HeartbeatResponse answers /heartbeat.
type HeartbeatResponse struct {
	Config            *Overlay `json:"config,omitempty"`
	LatestVersion     string   `json:"latest_version,omitempty"`
	MinimumVersion    string   `json:"minimum_version,omitempty"`
	MinimumGraceUntil int64    `json:"minimum_grace_until,omitempty"`
	Resync            bool     `json:"resync,omitempty"`
	ResyncNames       []string `json:"resync_names,omitempty"`
	RotateKey         bool     `json:"rotate_key,omitempty"`
	ClusterName       string   `json:"cluster_name,omitempty"`
	SourceName        string   `json:"source_name,omitempty"`
	// CheckRequested asks the service to run --check and upload the
	// report (D-35).
	CheckRequested bool `json:"check_requested,omitempty"`
}

// Check report triggers (D-35).
const (
	CheckTriggerManual    = "manual"    // paneldns-agent --check --upload
	CheckTriggerRequested = "requested" // the service, after check_requested
)

// MaxCheckReportBytes bounds an uploaded report (uncompressed JSON).
const MaxCheckReportBytes = 256 << 10

// CheckReportRequest is POST /check-report: the --check --json report.
type CheckReportRequest struct {
	Trigger string          `json:"trigger"`
	Report  json.RawMessage `json:"report"`
}

// CheckReportResponse answers /check-report.
type CheckReportResponse struct {
	ReportID int64 `json:"report_id"`
}

// InventoryEntry is one name in an inventory. Hash is empty for an
// excluded name and for a zone the agent could not read yet.
type InventoryEntry struct {
	Name     string `json:"name"`
	Hash     string `json:"hash,omitempty"`
	Excluded bool   `json:"excluded"`
}

// InventoryRequest is POST /inventory, one part of a full inventory.
type InventoryRequest struct {
	InventoryID     string           `json:"inventory_id"`
	Part            int              `json:"part"`  // 1-based
	Parts           int              `json:"parts"` // total parts
	ScanStartedAt   int64            `json:"scan_started_at"`
	ScanCompletedAt int64            `json:"scan_completed_at"`
	Zones           []InventoryEntry `json:"zones"`
}

// InventoryResponse answers /inventory with the names to send in full.
type InventoryResponse struct {
	Need []string `json:"need"`
}

// ZonePush is one zone in POST /zones (spec 8.4).
type ZonePush struct {
	Name           string  `json:"name"`
	Seq            uint64  `json:"seq"`
	Owner          *string `json:"owner"`
	Hash           string  `json:"hash"`
	Serial         uint32  `json:"serial"`
	SignedAtSource bool    `json:"signed_at_source"`
	Format         string  `json:"format"`
	Text           string  `json:"text"`
}

// ZonesRequest is POST /zones.
type ZonesRequest struct {
	ScanStartedAt int64      `json:"scan_started_at"`
	Zones         []ZonePush `json:"zones"`
}

// ZoneResult is the server's answer for one zone or deletion.
type ZoneResult struct {
	Name           string            `json:"name"`
	Status         string            `json:"status"`
	Reason         string            `json:"reason,omitempty"`
	Message        string            `json:"message,omitempty"`
	SkippedRecords []json.RawMessage `json:"skipped_records,omitempty"`
}

// ZonesResponse answers /zones.
type ZonesResponse struct {
	Results []ZoneResult `json:"results"`
}

// Deletion is one name in POST /deletions.
type Deletion struct {
	Name string `json:"name"`
	Seq  uint64 `json:"seq"`
}

// DeletionsRequest is POST /deletions.
type DeletionsRequest struct {
	ScanStartedAt int64      `json:"scan_started_at"`
	Deletions     []Deletion `json:"deletions"`
}

// DeletionsResponse answers /deletions.
type DeletionsResponse struct {
	Results []ZoneResult `json:"results"`
}

// Error codes in error bodies (docs/PROTOCOL.md section 7).
const (
	ErrEpochStale      = "epoch_stale"
	ErrIPRefused       = "ip_refused"
	ErrUnauthorized    = "unauthorized"
	ErrUpgradeRequired = "upgrade_required"
	ErrClockSkew       = "timestamp_out_of_window"
)

// ErrorBody is the JSON body of a non-2xx answer.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
}

// APIError is a non-2xx answer, or a transport failure (Status 0).
type APIError struct {
	Status     int
	Code       string
	Message    string
	IP         string
	RetryAfter time.Duration
	Path       string
	Err        error // transport error
}

func (e *APIError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s: %v", e.Path, e.Err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: HTTP %d", e.Path, e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	return b.String()
}

func (e *APIError) Unwrap() error { return e.Err }

// Retryable reports whether the same request may be retried later
// (spec 7.5): transport errors, 408, 409 (other than epoch_stale, which
// has its own recovery), 429 and 5xx.
func (e *APIError) Retryable() bool {
	switch {
	case e.Status == 0:
		return true
	case e.Status == http.StatusRequestTimeout, e.Status == http.StatusTooManyRequests:
		return true
	case e.Status == http.StatusConflict:
		return e.Code != ErrEpochStale
	case e.Status >= 500:
		return true
	}
	return false
}

// Explain returns a message for logs and --check that tells a person
// what to do.
func (e *APIError) Explain() string {
	switch {
	case e.Status == http.StatusForbidden && e.Code == ErrIPRefused:
		ip := e.IP
		if ip == "" {
			ip = "this server's address"
		}
		return fmt.Sprintf("PanelDNS refused the request because it came from %s, which is not on this server's IP allowlist. Allow the address in the PanelDNS dashboard (Panel Sync, the setup, Servers, this server); the agent keeps retrying", ip)
	case e.Status == http.StatusUnauthorized && e.Code == ErrClockSkew:
		return "PanelDNS refused the request time stamp: this server's clock is more than 5 minutes off. Fix time sync (chrony or systemd-timesyncd)"
	case e.Status == http.StatusUnauthorized:
		return "PanelDNS did not accept this agent's key (revoked, or the source was re-enrolled elsewhere). Re-enrol: paneldns-agent enrol --url ... --code ..."
	case e.Status == http.StatusUpgradeRequired:
		return "This agent version is below PanelDNS's minimum supported version. Update the paneldns-agent package; zones keep serving their last synced content meanwhile"
	case e.Status == http.StatusConflict && e.Code == ErrEpochStale:
		return "PanelDNS says this agent's state is out of date (epoch_stale); the agent asks for a new epoch and sends a full inventory"
	}
	return e.Error()
}

// ParseRetryAfter reads a Retry-After header: seconds or an HTTP date.
func ParseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(h, 10, 64); err == nil {
		if n < 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
