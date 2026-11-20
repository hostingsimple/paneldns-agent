package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	s, existed, err := Load(p)
	if err != nil || existed || len(s.Zones) != 0 {
		t.Fatalf("missing file: %v %v %+v", existed, err, s)
	}
	s.Zones["example.com"] = &Zone{Hash: "sha256:aa", Acked: "sha256:aa", Serial: 7}
	s.Deletions["example.net"] = true
	s.LastInventoryCount = 1
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	got, existed, err := Load(p)
	if err != nil || !existed {
		t.Fatalf("load: %v %v", existed, err)
	}
	if got.Zones["example.com"].Serial != 7 || !got.Deletions["example.net"] || got.LastInventoryCount != 1 {
		t.Fatalf("round trip %+v", got)
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries", len(entries))
	}
}

func TestLoadDiscardsBadState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	for _, content := range []string{"{not json", `{"version": 99, "zones": {"a": {}}}`} {
		os.WriteFile(p, []byte(content), 0o600)
		s, existed, err := Load(p)
		if err != nil || existed || len(s.Zones) != 0 {
			t.Fatalf("%q: %v %v %+v", content, existed, err, s)
		}
	}
}
