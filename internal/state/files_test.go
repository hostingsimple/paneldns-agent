package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestKeyRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, KeyFile)
	k, err := GenerateKey(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(p, k); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k) {
		t.Fatal("key changed in round trip")
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasPrefix(b, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("not PKCS#8 PEM: %s", b)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", fi.Mode().Perm())
		}
		os.Chmod(p, 0o640)
		if _, err := LoadKey(p); !errors.Is(err, ErrKeyMode) {
			t.Fatalf("0640 key accepted: %v", err)
		}
	}
	if _, err := DecodeKey([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), IdentityFile)
	id := &Identity{URL: "https://app.example.com", SourceID: "17", KeyID: "4", EnrolledAt: 1}
	if err := id.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadIdentity(p)
	if err != nil || *got != *id {
		t.Fatalf("%+v %v", got, err)
	}
	os.WriteFile(p, []byte(`{"url":"x"}`), 0o600)
	if _, err := LoadIdentity(p); err == nil {
		t.Fatal("incomplete identity accepted")
	}
}

func TestSequence(t *testing.T) {
	dir := t.TempDir()
	s := &Sequence{Path: filepath.Join(dir, SequenceFile)}
	if s.Exists() {
		t.Fatal("exists before creation")
	}
	if _, _, err := s.Current(); !errors.Is(err, ErrNoEpoch) {
		t.Fatalf("current: %v", err)
	}
	e, n, err := s.Next()
	if err != nil || e != 0 || n != 1 {
		t.Fatalf("next without epoch: %d %d %v", e, n, err)
	}
	if err := s.SetEpoch(5); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	seen := make(chan uint64, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, n, err := s.Next()
			if err != nil {
				t.Error(err)
			}
			seen <- n
		}()
	}
	wg.Wait()
	close(seen)
	uniq := map[uint64]bool{}
	for n := range seen {
		if uniq[n] {
			t.Fatalf("sequence %d handed out twice", n)
		}
		uniq[n] = true
	}
	e, n, _ = s.Current()
	if e != 5 || n != 100 {
		t.Fatalf("after 100: epoch %d seq %d", e, n)
	}
	// A second store on the same file continues the count.
	s2 := &Sequence{Path: s.Path}
	if _, n, _ := s2.Next(); n != 101 {
		t.Fatalf("second store got %d", n)
	}
}
