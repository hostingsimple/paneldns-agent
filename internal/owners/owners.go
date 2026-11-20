// Package owners reads the panel's owner file, which maps a domain to the
// hosting account that owns it (spec 7.3): cPanel's /etc/userdomains and
// DirectAdmin's /etc/virtual/domainowners, both "domain: user" per line.
// cPanel's /etc/userdatadomains ("domain: user==owner==type==...") is
// accepted too. Nothing is ever read from a panel API.
package owners

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Well-known owner files.
const (
	CPanel      = "/etc/userdomains"
	DirectAdmin = "/etc/virtual/domainowners"
)

// MaxSize caps the owner file.
const MaxSize = 64 << 20

// validUser is what the agent passes on as an owner: up to 64 characters
// (the server's column size), letters, digits, '.', '_' and '-'.
var validUser = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Stats describes the last parse.
type Stats struct {
	Entries int // domain -> user pairs kept
	Skipped int // lines that were not a usable pair
}

// Parse reads owner-file text into domain -> user. Domains are lower-cased
// without a trailing dot; the cPanel catch-all "*" and lines with an
// unusable user are skipped. A later line for the same domain wins.
func Parse(data []byte) (map[string]string, Stats) {
	m := map[string]string{}
	var st Stats
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		dom, user, ok := strings.Cut(line, ":")
		if !ok {
			st.Skipped++
			continue
		}
		dom = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(dom)), ".")
		user = strings.TrimSpace(user)
		if i := strings.Index(user, "=="); i >= 0 { // userdatadomains
			user = user[:i]
		}
		if dom == "" || dom == "*" || strings.ContainsAny(dom, " \t") || !validUser.MatchString(user) {
			st.Skipped++
			continue
		}
		m[dom] = user
		st.Entries++
	}
	return m, st
}

// File is an owner file re-read only when its size or mtime changes.
type File struct {
	Path string

	mu    sync.Mutex
	stamp string
	m     map[string]string
	stats Stats
	err   error
}

// Reload re-reads the file if it changed. A missing file means "no
// owners" and is reported as an error once per change.
func (f *File) Reload() error {
	if f == nil || f.Path == "" {
		return nil
	}
	fi, err := os.Stat(f.Path)
	stamp := "missing"
	if err == nil {
		stamp = strconv.FormatInt(fi.Size(), 10) + "@" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if stamp == f.stamp && f.m != nil {
		return nil
	}
	f.stamp = stamp
	f.m = map[string]string{}
	f.stats = Stats{}
	if err != nil {
		f.err = fmt.Errorf("owner file %s: %w", f.Path, err)
		return f.err
	}
	if fi.Size() > MaxSize {
		f.err = fmt.Errorf("owner file %s is larger than %d bytes", f.Path, MaxSize)
		return f.err
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			err = fmt.Errorf("%w (grant the agent read access: setfacl -m u:paneldns-agent:r %s)", err, f.Path)
		}
		f.err = fmt.Errorf("owner file %s: %w", f.Path, err)
		return f.err
	}
	f.m, f.stats = Parse(b)
	f.err = nil
	return nil
}

// Owner returns the account owning zone.
func (f *File) Owner(zone string) (string, bool) {
	if f == nil {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.m[strings.TrimSuffix(strings.ToLower(zone), ".")]
	return u, ok
}

// Stats returns the last parse's counts and error.
func (f *File) Stats() (Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats, f.err
}

// Detect returns the owner file for a panel, if it exists.
func Detect(panel string, root string) string {
	var p string
	switch panel {
	case "cpanel":
		p = CPanel
	case "directadmin":
		p = DirectAdmin
	default:
		return ""
	}
	if _, err := os.Stat(root + p); err == nil {
		return p
	}
	return ""
}
