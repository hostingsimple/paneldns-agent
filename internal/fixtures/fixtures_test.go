package fixtures

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/protocol"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

var update = flag.Bool("update", false, "rewrite the expected outputs in testdata/")

const root = "../../testdata"

// ---- Ed25519 signing vector -------------------------------------------

// The seed is the 32 bytes 0x00..0x1f: a public test key, never used for
// anything real.
func vectorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

type vectorCase struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	KeyHeader     string `json:"x_paneldns_key"`
	Timestamp     int64  `json:"x_paneldns_timestamp"`
	Nonce         string `json:"x_paneldns_nonce"`
	Epoch         uint64 `json:"x_paneldns_epoch"`
	Seq           uint64 `json:"x_paneldns_seq"`
	BodyJSON      string `json:"body_json"`
	BodyGzipB64   string `json:"body_wire_base64"`
	BodySHA256Hex string `json:"body_wire_sha256_hex"`
	SigningString string `json:"signing_string"`
	Signature     string `json:"x_paneldns_signature"`
}

type vectorFile struct {
	Comment       []string     `json:"comment"`
	Algorithm     string       `json:"algorithm"`
	SeedHex       string       `json:"private_key_seed_hex"`
	PublicKeyB64  string       `json:"public_key_base64"`
	PublicKeyHex  string       `json:"public_key_hex"`
	Cases         []vectorCase `json:"cases"`
	NegativeCases []negative   `json:"negative_cases"`
}

type negative struct {
	Name     string `json:"name"`
	Base     string `json:"base_case"`
	Change   string `json:"change"`
	Expected string `json:"expected"`
}

func vectorInputs() []vectorCase {
	return []vectorCase{
		{Name: "heartbeat", Method: "POST", Path: "/api/agent/v1/heartbeat", KeyHeader: "17.4",
			Timestamp: 1795000000, Nonce: "00112233445566778899aabbccddeeff", Epoch: 3, Seq: 42,
			BodyJSON: `{"agent_version":"1.0.0","hostname":"web1.example.com","os":"Debian GNU/Linux 13 (trixie)","backend":"bind","panel":"directadmin","public_ips":["192.0.2.10","2001:db8::10"],"zone_count":2,"excluded_count":0,"signed_count":0,"scan_started_at":1794999990,"scan_completed_at":1794999995,"errors":[]}`},
		{Name: "zones", Method: "POST", Path: "/api/agent/v1/zones", KeyHeader: "17.4",
			Timestamp: 1795000060, Nonce: "ffeeddccbbaa99887766554433221100", Epoch: 3, Seq: 43,
			BodyJSON: `{"scan_started_at":1795000050,"zones":[{"name":"example.com","seq":43,"owner":"exampleuser","hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","serial":2026112001,"signed_at_source":false,"format":"rfc1035","text":"$ORIGIN example.com.\nexample.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. 2026112001 3600 900 604800 300\nexample.com. 3600 IN TXT \"v=spf1 -all\"\n"}]}`},
		{Name: "epoch request after state loss (epoch 0)", Method: "POST", Path: "/api/agent/v1/epoch", KeyHeader: "17.4",
			Timestamp: 1795000120, Nonce: "0123456789abcdef0123456789abcdef", Epoch: 0, Seq: 1,
			BodyJSON: `{}`},
		{Name: "base URL with a path prefix", Method: "POST", Path: "/paneldns/api/agent/v1/inventory", KeyHeader: "17.4",
			Timestamp: 1795000180, Nonce: "fedcba9876543210fedcba9876543210", Epoch: 4, Seq: 1,
			BodyJSON: `{"inventory_id":"1795000170-0a0b0c0d","part":1,"parts":1,"scan_started_at":1795000170,"scan_completed_at":1795000175,"zones":[{"name":"example.com","hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","excluded":false},{"name":"printer.example.net","excluded":true}]}`},
	}
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func TestSigningVector(t *testing.T) {
	path := filepath.Join(root, "signing", "ed25519-request-signing.json")
	key := vectorKey()
	pub := key.Public().(ed25519.PublicKey)
	if *update {
		vf := vectorFile{
			Comment: []string{
				"Shared Ed25519 request-signing vector for the PanelDNS agent ingest API.",
				"See testdata/README.md and docs/PROTOCOL.md section 3. TEST KEY ONLY: the seed is the bytes 00..1f.",
				"body_wire_base64 is the exact request body (gzip); the signature covers SHA-256 of those bytes, never the inflated JSON.",
			},
			Algorithm:    "Ed25519 (RFC 8032), signature standard base64 with padding",
			SeedHex:      hex.EncodeToString(key.Seed()),
			PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
			PublicKeyHex: hex.EncodeToString(pub),
			NegativeCases: []negative{
				{"body inflated before hashing", "zones", "hash SHA-256 of body_json instead of the gzip bytes", "signature invalid"},
				{"other seq", "heartbeat", "x_paneldns_seq 43", "signature invalid"},
				{"path with query", "heartbeat", "path /api/agent/v1/heartbeat?x=1", "signature invalid"},
				{"lower-case method", "heartbeat", "method post (upper-case before signing)", "signature valid"},
			},
		}
		for _, c := range vectorInputs() {
			wire := protocol.Gzip([]byte(c.BodyJSON))
			c.BodyGzipB64 = base64.StdEncoding.EncodeToString(wire)
			c.BodySHA256Hex = protocol.BodyHash(wire)
			c.SigningString = protocol.SigningString(c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire)
			c.Signature = protocol.Sign(key, c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire)
			vf.Cases = append(vf.Cases, c)
		}
		writeJSON(t, path, vf)
	}
	var vf vectorFile
	readJSON(t, path, &vf)
	if vf.SeedHex != hex.EncodeToString(key.Seed()) || vf.PublicKeyB64 != base64.StdEncoding.EncodeToString(pub) {
		t.Fatal("vector key differs from the fixed test key")
	}
	if len(vf.Cases) != len(vectorInputs()) {
		t.Fatalf("vector has %d cases, inputs %d", len(vf.Cases), len(vectorInputs()))
	}
	for i, c := range vf.Cases {
		in := vectorInputs()[i]
		if c.Name != in.Name || c.Path != in.Path || c.Seq != in.Seq || c.BodyJSON != in.BodyJSON {
			t.Fatalf("case %q inputs changed; regenerate with -update", c.Name)
		}
		wire, err := base64.StdEncoding.DecodeString(c.BodyGzipB64)
		if err != nil {
			t.Fatal(err)
		}
		inflated, err := gunzip(wire)
		if err != nil || string(inflated) != c.BodyJSON {
			t.Fatalf("%s: wire body does not inflate to body_json", c.Name)
		}
		if protocol.BodyHash(wire) != c.BodySHA256Hex {
			t.Fatalf("%s: body hash", c.Name)
		}
		if got := protocol.SigningString(c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire); got != c.SigningString {
			t.Fatalf("%s: signing string\n%q\n%q", c.Name, got, c.SigningString)
		}
		if got := protocol.Sign(key, c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire); got != c.Signature {
			t.Fatalf("%s: signature %s, want %s", c.Name, got, c.Signature)
		}
		if !protocol.Verify(pub, c.Signature, c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire) {
			t.Fatalf("%s: does not verify", c.Name)
		}
		// Negative cases.
		if protocol.Verify(pub, c.Signature, c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, []byte(c.BodyJSON)) {
			t.Fatalf("%s: verifies over the inflated body", c.Name)
		}
		if protocol.Verify(pub, c.Signature, c.Method, c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq+1, wire) {
			t.Fatalf("%s: verifies with another seq", c.Name)
		}
		if protocol.Verify(pub, c.Signature, c.Method, c.Path+"?x=1", c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire) {
			t.Fatalf("%s: verifies with a query string", c.Name)
		}
		if !protocol.Verify(pub, c.Signature, strings.ToLower(c.Method), c.Path, c.Timestamp, c.Nonce, c.Epoch, c.Seq, wire) {
			t.Fatalf("%s: method must be upper-cased before signing", c.Name)
		}
	}
}

// ---- canonical-hash fixture -------------------------------------------

type canonCase struct {
	File           string `json:"file"`
	Origin         string `json:"origin"`
	Serial         uint32 `json:"serial"`
	SignedAtSource bool   `json:"signed_at_source"`
	Stripped       int    `json:"stripped_records"`
	Hash           string `json:"hash"`
	HashInput      string `json:"hash_input"`
	Text           string `json:"text"`
}

type canonFile struct {
	Comment []string    `json:"comment"`
	Cases   []canonCase `json:"cases"`
	// SameHash lists files that are the same zone and must hash equal.
	SameHash [][]string `json:"same_hash"`
}

var canonInputs = []canonCase{
	{File: "handwritten.example.com.db", Origin: "example.com"},
	{File: "compiled.example.com.db", Origin: "example.com"},
	{File: "directadmin.example.com.db", Origin: "example.com"},
	{File: "signed-export.example.com.db", Origin: "example.com"},
	{File: "rules.example.net.db", Origin: "example.net"},
}

var sameHash = [][]string{{"handwritten.example.com.db", "compiled.example.com.db", "directadmin.example.com.db", "signed-export.example.com.db"}}

func canonicalOf(t *testing.T, c canonCase) canonCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "canonical", c.File))
	if err != nil {
		t.Fatal(err)
	}
	rrs, err := zonefile.Parse(b, zonefile.Options{Origin: c.Origin, File: c.File})
	if err != nil {
		t.Fatal(err)
	}
	rrs, sr := zonefile.Strip(rrs)
	z, err := zonefile.MakeCanonical(rrs, c.Origin)
	if err != nil {
		t.Fatal(err)
	}
	c.Serial, c.SignedAtSource, c.Stripped = z.Serial, sr.SignedAtSource, sr.Removed
	c.Hash, c.HashInput, c.Text = z.Hash, z.HashInput(), z.Text
	// The pushed text canonicalises to itself (the server re-hashes it).
	rrs2, err := zonefile.Parse([]byte(z.Text), zonefile.Options{Origin: c.Origin})
	if err != nil {
		t.Fatal(err)
	}
	z2, err := zonefile.MakeCanonical(rrs2, c.Origin)
	if err != nil || z2.Hash != z.Hash || z2.Text != z.Text {
		t.Fatalf("%s: pushed text is not a fixed point", c.File)
	}
	return c
}

func TestCanonicalFixture(t *testing.T) {
	path := filepath.Join(root, "canonical", "canonical-hash.json")
	if *update {
		cf := canonFile{
			Comment: []string{
				"Shared canonical-hash fixture for Panel Sync (docs/PROTOCOL.md section 5).",
				"For each input file: parse with the given origin, strip DNSSEC/private types, canonicalise.",
				"hash = \"sha256:\" + hex(SHA-256(hash_input)); hash_input is the sorted canonical lines with the SOA serial removed, each ending in \\n.",
				"text is what the agent pushes; re-canonicalising text gives the same text and hash.",
			},
			SameHash: sameHash,
		}
		for _, c := range canonInputs {
			cf.Cases = append(cf.Cases, canonicalOf(t, c))
		}
		writeJSON(t, path, cf)
	}
	var cf canonFile
	readJSON(t, path, &cf)
	if len(cf.Cases) != len(canonInputs) {
		t.Fatalf("fixture has %d cases", len(cf.Cases))
	}
	byFile := map[string]canonCase{}
	for i, want := range cf.Cases {
		got := canonicalOf(t, canonInputs[i])
		if got != want {
			t.Fatalf("%s differs from the fixture; if the canonical rules changed on purpose, run with -update\ngot  %+v\nwant %+v", want.File, got, want)
		}
		byFile[want.File] = want
	}
	for _, group := range cf.SameHash {
		for _, f := range group[1:] {
			if byFile[f].Hash != byFile[group[0]].Hash {
				t.Fatalf("%s and %s should hash the same", f, group[0])
			}
		}
	}
	if !byFile["signed-export.example.com.db"].SignedAtSource || byFile["handwritten.example.com.db"].SignedAtSource {
		t.Fatal("signed_at_source wrong")
	}
}

// ---- SHA256SUMS -------------------------------------------------------

func TestChecksums(t *testing.T) {
	path := filepath.Join(root, "SHA256SUMS")
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "SHA256SUMS" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		lines = append(lines, fmt.Sprintf("%s  %s", hex.EncodeToString(sum[:]), rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	want := strings.Join(lines, "\n") + "\n"
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("testdata/SHA256SUMS is out of date; run go test ./internal/fixtures -update\nwant:\n%s", want)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate with: go test ./internal/fixtures -update)", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}
