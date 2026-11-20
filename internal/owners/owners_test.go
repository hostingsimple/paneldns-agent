package owners

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		file    string
		want    map[string]string
		skipped int
	}{
		{"userdomains", map[string]string{
			"example.com": "exampleuser", "www.example.com": "exampleuser",
			"shop.example.net": "shopuser", "parked.example.net": "shopuser",
		}, 4},
		// CRLF and a later line for the same domain.
		{"domainowners", map[string]string{"example.com": "client1", "reseller.example.net": "resell1"}, 0},
		{"userdatadomains", map[string]string{"example.com": "exampleuser", "addon.example.net": "exampleuser"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, st := Parse(b)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v\nwant %v", got, tt.want)
			}
			if st.Skipped != tt.skipped {
				t.Fatalf("skipped %d, want %d", st.Skipped, tt.skipped)
			}
		})
	}
}

func TestFileReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "domainowners")
	f := &File{Path: p}
	if err := f.Reload(); err == nil {
		t.Fatal("missing file should be reported")
	}
	if _, ok := f.Owner("example.com"); ok {
		t.Fatal("owner from a missing file")
	}
	os.WriteFile(p, []byte("example.com: one\n"), 0o644)
	if err := f.Reload(); err != nil {
		t.Fatal(err)
	}
	if u, ok := f.Owner("Example.COM."); !ok || u != "one" {
		t.Fatalf("owner %q %v", u, ok)
	}
	os.WriteFile(p, []byte("example.com: two\n"), 0o644)
	os.Chtimes(p, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	f.Reload()
	if u, _ := f.Owner("example.com"); u != "two" {
		t.Fatalf("not re-read: %q", u)
	}
	if st, err := f.Stats(); err != nil || st.Entries != 1 {
		t.Fatalf("stats %+v %v", st, err)
	}
	var nilFile *File
	if nilFile.Reload() != nil {
		t.Fatal("nil file")
	}
	if _, ok := nilFile.Owner("x"); ok {
		t.Fatal("nil file owner")
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	if Detect("cpanel", dir) != "" {
		t.Fatal("detected a missing file")
	}
	os.MkdirAll(filepath.Join(dir, "etc", "virtual"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "virtual", "domainowners"), nil, 0o644)
	if Detect("directadmin", filepath.ToSlash(dir)) != DirectAdmin {
		t.Fatal("DirectAdmin owner file not found")
	}
	if Detect("plesk", dir) != "" {
		t.Fatal("no owner file for Plesk in v1")
	}
}
