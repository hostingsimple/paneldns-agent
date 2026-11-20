package state

import (
	"encoding/json"
	"fmt"
	"os"
)

// Identity is identity.json, written at enrolment. It holds no secret.
type Identity struct {
	URL         string `json:"url"`
	SourceID    string `json:"source_id"`
	KeyID       string `json:"key_id"`
	ClusterName string `json:"cluster_name,omitempty"`
	SourceName  string `json:"source_name,omitempty"`
	EnrolledAt  int64  `json:"enrolled_at"`
}

// LoadIdentity reads identity.json.
func LoadIdentity(path string) (*Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	id := &Identity{}
	if err := json.Unmarshal(b, id); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if id.SourceID == "" || id.KeyID == "" {
		return nil, fmt.Errorf("%s: source or key id missing", path)
	}
	return id, nil
}

// Save writes identity.json (0600).
func (id *Identity) Save(path string) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, append(b, '\n'), 0o600)
}
