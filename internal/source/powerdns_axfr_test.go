package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
)

// D-33: a zone the API refuses (CyberPanel's unquoted TXT, HTTP 500) is read by AXFR.
func TestPowerDNSAXFRFallback(t *testing.T) {
	dir := t.TempDir()
	keyFile := path.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/servers/localhost/zones":
			w.Write([]byte(`[{"id":"cp.example.","name":"cp.example.","kind":"Native","serial":1,"edited_serial":1}]`))
		case "/api/v1/servers/localhost/zones/cp.example./export":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Parsing record content (try 'pdnsutil check-zone'): Data field in DNS should start with quote (\") at position 0 of 'v=spf1 a mx ~all'"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	var argv []string
	axfr := "cp.example.\t3600\tIN\tSOA\tns1.cp.example. hostmaster.cp.example. 1 10800 3600 1209600 3600\n" +
		"cp.example.\t3600\tIN\tA\t192.0.2.30\n" +
		"cp.example.\t3600\tIN\tTXT\t\"v=spf1 a mx ~all\"\n" +
		"www.cp.example.\t3600\tIN\tCNAME\tcp.example.\n" +
		"cp.example.\t3600\tIN\tSOA\tns1.cp.example. hostmaster.cp.example. 1 10800 3600 1209600 3600\n"
	p := &PowerDNS{BaseURL: srv.URL, KeyFile: keyFile, CheckListener: noListenerCheck, Dig: "/usr/bin/dig",
		Run: func(ctx context.Context, a []string) ([]byte, []byte, error) {
			argv = a
			return []byte(axfr), nil, nil
		}}
	ctx := context.Background()
	l, err := p.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := p.Read(ctx, l.Zones[0])
	if err != nil {
		t.Fatal(err)
	}
	// The closing SOA is dropped; TXT keeps its text.
	if len(rrs) != 4 || rrs[0].Type != "SOA" || rrs[3].Type != "CNAME" || rrs[2].Data[0].Text != "v=spf1 a mx ~all" {
		t.Fatalf("axfr read %+v", rrs)
	}
	want := []string{"/usr/bin/dig", "+nocmd", "+nocomments", "+nostats", "+noquestion", "+time=10", "+tries=1", "@127.0.0.1", "cp.example.", "AXFR"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv %q\nwant %q", argv, want)
	}

	// A refused transfer fails the zone with both errors.
	p.Run = func(ctx context.Context, a []string) ([]byte, []byte, error) {
		return []byte("; Transfer failed.\n"), nil, nil
	}
	if _, err := p.Read(ctx, l.Zones[0]); err == nil || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "refused or failed") {
		t.Fatalf("refused transfer: %v", err)
	}

	// With the fallback off, the API error stands alone.
	p.NoAXFR = true
	if _, err := p.Read(ctx, l.Zones[0]); err == nil || strings.Contains(err.Error(), "AXFR") {
		t.Fatalf("NoAXFR: %v", err)
	}
	p.NoAXFR = false

	// A name dig would read as an option or a server is never passed to it.
	called := false
	p.Run = func(ctx context.Context, a []string) ([]byte, []byte, error) { called = true; return nil, nil, nil }
	for _, name := range []string{"-p.example", "+short.example", "@evil.example"} {
		if _, err := p.readAXFR(ctx, ZoneRef{Name: name, key: name + "."}); err == nil || called {
			t.Fatalf("name %q passed to dig (err %v)", name, err)
		}
	}

	// Errors other than 500 and 404 (here 401) don't fall back.
	if _, err := p.Read(ctx, ZoneRef{Name: "other.example", key: "other.example."}); err == nil || strings.Contains(err.Error(), "AXFR") {
		t.Fatalf("401 fell back: %v", err)
	}
}
