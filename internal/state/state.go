// Package state keeps the agent's files in /var/lib/paneldns-agent:
// state.json (per-zone fingerprints, hashes and what the server
// acknowledged), plus the identity, sequence and key files (key.go,
// sequence.go). Every write is atomic: a temporary file in the same
// directory, fsync, rename.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// FormatVersion is bumped when state.json changes incompatibly; an
// unknown version is discarded and rebuilt by a full resync.
const FormatVersion = 1

// Zone is what the agent remembers about one zone.
type Zone struct {
	Fingerprint string `json:"fp,omitempty"`
	Hash        string `json:"hash,omitempty"`   // last computed content hash
	Serial      uint32 `json:"serial,omitempty"` // SOA serial of Hash
	Signed      bool   `json:"signed,omitempty"` // signed_at_source of Hash
	Owner       string `json:"owner,omitempty"`  // owner sent with Acked
	Acked       string `json:"acked,omitempty"`  // hash the server acknowledged
	Status      string `json:"status,omitempty"` // last per-zone status from the server
	Reason      string `json:"reason,omitempty"` // and its reason code or text
	RefusedHash string `json:"refused,omitempty"`
	Error       string `json:"error,omitempty"` // last local read error
	Excluded    string `json:"excluded,omitempty"`
}

// State is state.json.
type State struct {
	Version int              `json:"version"`
	Zones   map[string]*Zone `json:"zones"`
	// Deletions are names gone from the server's view of this source but
	// not yet acknowledged.
	Deletions map[string]bool `json:"deletions,omitempty"`
	// ConfigFiles are the config files that declared zones in the last
	// good listing (docs/DECISIONS.md D-02, D-14).
	ConfigFiles []string `json:"config_files,omitempty"`
	// LastInventory is when the last full inventory was acknowledged and
	// how many names it held (for the empty-inventory guard).
	LastInventoryAt    int64 `json:"last_inventory_at,omitempty"`
	LastInventoryCount int   `json:"last_inventory_count,omitempty"`
	ScanStartedAt      int64 `json:"scan_started_at,omitempty"`
	ScanCompletedAt    int64 `json:"scan_completed_at,omitempty"`
}

// New returns an empty state.
func New() *State {
	return &State{Version: FormatVersion, Zones: map[string]*Zone{}, Deletions: map[string]bool{}}
}

// Load reads state.json; a missing or unreadable-as-JSON file gives an
// empty state and reports whether one existed.
func Load(path string) (*State, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return New(), false, nil
	}
	if err != nil {
		return nil, false, err
	}
	s := New()
	if err := json.Unmarshal(b, s); err != nil || s.Version != FormatVersion {
		return New(), false, nil
	}
	if s.Zones == nil {
		s.Zones = map[string]*Zone{}
	}
	if s.Deletions == nil {
		s.Deletions = map[string]bool{}
	}
	return s, true, nil
}

// Save writes state.json atomically with mode 0600.
func (s *State) Save(path string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return WriteAtomic(path, b, 0o600)
}

// WriteAtomic replaces path with data.
func WriteAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
