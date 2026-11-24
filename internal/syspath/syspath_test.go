package syspath

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFind(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	a, b, c := dir+"/a", dir+"/b", dir+"/c"
	for _, d := range []string{a, b, c} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(b+"/prog", []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(c+"/prog", []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(a+"/data", []byte(""), 0o644)
	os.Mkdir(a+"/adir", 0o755)
	oldD, oldO := Dirs, ownerOK
	defer func() { Dirs, ownerOK = oldD, oldO }()
	Dirs = []string{a, b, c}
	ownerOK = func(fs.FileInfo) bool { return true }

	// PATH plays no part.
	t.Setenv("PATH", a)
	if p, err := Find("prog"); err != nil || p != b+"/prog" {
		t.Fatalf("Find: %q %v", p, err)
	}
	// Not executable, a directory, missing: not found.
	for _, n := range []string{"data", "adir", "missing"} {
		if n == "data" && runtime.GOOS == "windows" {
			continue // no execute bit
		}
		if _, err := Find(n); !errors.Is(err, exec.ErrNotFound) || !IsNotFound(err) {
			t.Errorf("%s: %v", n, err)
		}
	}
	for _, n := range []string{"", "../prog", "/bin/sh", "a/prog"} {
		if _, err := Find(n); err == nil || IsNotFound(err) {
			t.Errorf("%q: %v", n, err)
		}
	}
	// A copy someone other than root could change is skipped, and named.
	ownerOK = func(fi fs.FileInfo) bool { return fi.Name() != "b" }
	if p, err := Find("prog"); err != nil || p != c+"/prog" {
		t.Fatalf("skipping an untrusted directory: %q %v", p, err)
	}
	ownerOK = func(fs.FileInfo) bool { return false }
	if _, err := Find("prog"); !IsNotFound(err) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("all refused: %v", err)
	}
}

func TestOwnerOKOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owners")
	}
	f := filepath.Join(t.TempDir(), "x")
	os.WriteFile(f, nil, 0o755)
	fi, _ := os.Stat(f)
	if want := os.Getuid() == 0; ownerOKOS(fi) != want {
		t.Errorf("own file: got %v, want %v", ownerOKOS(fi), want)
	}
	os.Chmod(f, 0o775)
	fi, _ = os.Stat(f)
	if ownerOKOS(fi) {
		t.Error("group-writable file accepted")
	}
	// A real system program is found where systems keep it.
	if p, err := Find("sh"); err != nil || !strings.HasPrefix(p, "/") {
		t.Errorf("sh: %q %v", p, err)
	}
}
