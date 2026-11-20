package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Sequence is sequence.json: the server-issued epoch and the last
// sequence number used in it. Every allocation is locked, written and
// synced before the number is used, so the service and --check never
// reuse a number and a crash never repeats one.
type Sequence struct {
	Path string
	Lock string // lock file; "" uses .lock next to Path
}

type seqFile struct {
	Epoch uint64 `json:"epoch"`
	Seq   uint64 `json:"seq"`
}

// ErrNoEpoch means sequence.json is missing: the agent must call /epoch.
var ErrNoEpoch = errors.New("no epoch: sequence.json is missing")

func (s *Sequence) lockPath() string {
	if s.Lock != "" {
		return s.Lock
	}
	return filepath.Join(filepath.Dir(s.Path), LockFile)
}

func (s *Sequence) read() (seqFile, bool, error) {
	var f seqFile
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, false, nil
	}
	if err != nil {
		return f, false, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, false, fmt.Errorf("%s: %w", s.Path, err)
	}
	return f, true, nil
}

func (s *Sequence) write(f seqFile) error {
	b, _ := json.Marshal(f)
	return WriteAtomic(s.Path, b, 0o600)
}

// Exists reports whether sequence.json is present and readable.
func (s *Sequence) Exists() bool {
	_, ok, err := s.read()
	return ok && err == nil
}

// Current returns the epoch and last sequence without allocating.
func (s *Sequence) Current() (epoch, seq uint64, err error) {
	f, ok, err := s.read()
	if err != nil {
		return 0, 0, err
	}
	if !ok {
		return 0, 0, ErrNoEpoch
	}
	return f.Epoch, f.Seq, nil
}

// Next allocates the next sequence number. Without sequence.json it uses
// epoch 0, which only /epoch accepts.
func (s *Sequence) Next() (uint64, uint64, error) {
	unlock, err := lockFile(s.lockPath())
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	f, _, err := s.read()
	if err != nil {
		return 0, 0, err
	}
	f.Seq++
	if err := s.write(f); err != nil {
		return 0, 0, err
	}
	return f.Epoch, f.Seq, nil
}

// SetEpoch starts a new epoch; the next sequence number is 1.
func (s *Sequence) SetEpoch(epoch uint64) error {
	unlock, err := lockFile(s.lockPath())
	if err != nil {
		return err
	}
	defer unlock()
	return s.write(seqFile{Epoch: epoch})
}
