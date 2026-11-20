// Package filter decides which zone names the agent never sends (system
// zones) and which it reports as excluded (EXCLUDE patterns and the
// server's overlay), per spec 7.3, 7.4 and 10.11.
package filter

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// systemZones is the default list of spec 7.3. Names match exactly; the
// PanelDNS server applies the same list again at ingest.
var systemZones = func() map[string]bool {
	m := map[string]bool{
		".":                     true, // the root hint zone
		"localhost":             true,
		"localdomain":           true,
		"localhost.localdomain": true,
		"0.in-addr.arpa":        true,
		"127.in-addr.arpa":      true,
		"0.0.127.in-addr.arpa":  true,
		"255.in-addr.arpa":      true,
		// ::1 reverse zone.
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa": true,
		// RFC 1918 reverse zones, as in named's built-in empty zones.
		"10.in-addr.arpa":      true,
		"168.192.in-addr.arpa": true,
	}
	for i := 16; i <= 31; i++ {
		m[strconv.Itoa(i)+".172.in-addr.arpa"] = true
	}
	return m
}()

// Normalize lower-cases a zone name and removes the trailing dot.
func Normalize(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "." || name == "" {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

// IsSystem reports whether name is a system zone, never sent.
func IsSystem(name string) bool { return systemZones[Normalize(name)] }

// SystemZones returns the list, sorted, for --check and the docs.
func SystemZones() []string {
	var out []string
	for k := range systemZones {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Excluder matches zone names against glob patterns (path.Match syntax:
// '*' matches any run of characters, dots included).
type Excluder struct {
	patterns []string
}

// NewExcluder lower-cases and de-duplicates the patterns. Bad patterns
// were refused when the config was read; here they simply never match.
func NewExcluder(patterns ...[]string) *Excluder {
	seen := map[string]bool{}
	e := &Excluder{}
	for _, list := range patterns {
		for _, p := range list {
			p = Normalize(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			e.patterns = append(e.patterns, p)
		}
	}
	return e
}

// Match returns the first pattern matching name, or "".
func (e *Excluder) Match(name string) string {
	if e == nil {
		return ""
	}
	n := Normalize(name)
	for _, p := range e.patterns {
		if ok, _ := path.Match(p, n); ok {
			return p
		}
	}
	return ""
}

// Patterns returns the active patterns.
func (e *Excluder) Patterns() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.patterns...)
}
