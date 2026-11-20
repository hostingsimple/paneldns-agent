// Package config reads and writes /etc/paneldns-agent.conf (spec 7.2).
//
// The file is flat KEY=VALUE text. A '#' at the start of a line, or a '#'
// preceded by whitespace, starts a comment. Values may be wrapped in double
// quotes. The file holds no secret.
package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// DefaultPath is where the package installs the config file.
const DefaultPath = "/etc/paneldns-agent.conf"

// StateDir is the agent's only writable directory.
const StateDir = "/var/lib/paneldns-agent"

// Zone sources (ZONE_SOURCE).
const (
	SourceBIND        = "bind"
	SourcePowerDNSAPI = "powerdns-api"
	SourcePdnsutil    = "pdnsutil"
)

// MinInterval is the smallest scan interval accepted, in seconds.
const MinInterval = 15

// Config is the parsed configuration.
type Config struct {
	URL            string   // PANELDNS_URL
	Interval       int      // INTERVAL, seconds
	Resync         int      // RESYNC, seconds
	LogLevel       string   // LOG_LEVEL
	ZoneSource     string   // ZONE_SOURCE
	ZonesFile      string   // ZONES_FILE
	Chroot         string   // CHROOT
	View           string   // VIEW
	PDNSAPIURL     string   // PDNS_API_URL
	PDNSAPIKeyFile string   // PDNS_API_KEY_FILE
	OwnersFile     string   // OWNERS_FILE
	Exclude        []string // EXCLUDE, glob patterns

	// Warnings lists non-fatal problems found while parsing, such as
	// unknown keys. They are logged and shown by --check.
	Warnings []string
}

// Keys in the order the sample file lists them.
var Keys = []string{
	"PANELDNS_URL", "INTERVAL", "RESYNC", "LOG_LEVEL", "ZONE_SOURCE",
	"ZONES_FILE", "CHROOT", "VIEW", "PDNS_API_URL", "PDNS_API_KEY_FILE",
	"OWNERS_FILE", "EXCLUDE",
}

// Defaults returns the configuration used for keys the file leaves out.
func Defaults() Config {
	return Config{
		Interval:       60,
		Resync:         21600,
		LogLevel:       "info",
		ZoneSource:     SourceBIND,
		ZonesFile:      "/etc/named.conf",
		PDNSAPIURL:     "http://127.0.0.1:8081",
		PDNSAPIKeyFile: StateDir + "/pdns-api-key",
	}
}

// Load reads and validates the file at p.
func Load(p string) (Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return Config{}, err
	}
	c, err := Parse(string(b))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", p, err)
	}
	return c, nil
}

// ParseValues splits the file into KEY -> raw value. Later lines win.
func ParseValues(text string) (map[string]string, error) {
	vals := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(strings.TrimSuffix(sc.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		key := strings.TrimSpace(line[:eq])
		val, err := parseValue(line[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		vals[key] = val
	}
	return vals, sc.Err()
}

func parseValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, `"`) {
		end := strings.IndexByte(raw[1:], '"')
		if end < 0 {
			return "", fmt.Errorf("unterminated quote")
		}
		rest := strings.TrimSpace(raw[end+2:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return "", fmt.Errorf("unexpected text after quoted value")
		}
		return raw[1 : end+1], nil
	}
	// An unquoted value ends at a '#' that follows whitespace.
	for i := 0; i < len(raw); i++ {
		if raw[i] == '#' && (i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t') {
			raw = raw[:i]
			break
		}
	}
	return strings.TrimSpace(raw), nil
}

// Parse parses and validates config text.
func Parse(text string) (Config, error) {
	vals, err := ParseValues(text)
	if err != nil {
		return Config{}, err
	}
	c := Defaults()
	known := map[string]bool{}
	for _, k := range Keys {
		known[k] = true
	}
	var unknown []string
	for k := range vals {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}
	sort.Strings(unknown)
	for _, k := range unknown {
		c.Warnings = append(c.Warnings, fmt.Sprintf("unknown key %s ignored", k))
	}
	str := func(k string, dst *string) {
		if v, ok := vals[k]; ok {
			*dst = v
		}
	}
	str("PANELDNS_URL", &c.URL)
	str("LOG_LEVEL", &c.LogLevel)
	str("ZONE_SOURCE", &c.ZoneSource)
	str("ZONES_FILE", &c.ZonesFile)
	str("CHROOT", &c.Chroot)
	str("VIEW", &c.View)
	str("PDNS_API_URL", &c.PDNSAPIURL)
	str("PDNS_API_KEY_FILE", &c.PDNSAPIKeyFile)
	str("OWNERS_FILE", &c.OwnersFile)
	for _, k := range []struct {
		key string
		dst *int
	}{{"INTERVAL", &c.Interval}, {"RESYNC", &c.Resync}} {
		if v, ok := vals[k.key]; ok && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: not a whole number of seconds: %q", k.key, v)
			}
			*k.dst = n
		}
	}
	if v, ok := vals["EXCLUDE"]; ok {
		c.Exclude = strings.Fields(v)
	}
	return c, c.Validate()
}

// Validate checks every value.
func (c *Config) Validate() error {
	if err := ValidateURL(c.URL); err != nil {
		return fmt.Errorf("PANELDNS_URL: %w", err)
	}
	if c.Interval < MinInterval {
		return fmt.Errorf("INTERVAL: must be at least %d seconds", MinInterval)
	}
	if c.Resync < c.Interval {
		return fmt.Errorf("RESYNC: must be at least INTERVAL (%d)", c.Interval)
	}
	switch c.LogLevel {
	case "error", "warn", "info", "debug":
	default:
		return fmt.Errorf("LOG_LEVEL: must be error, warn, info or debug")
	}
	switch c.ZoneSource {
	case SourceBIND:
		if !path.IsAbs(c.ZonesFile) {
			return fmt.Errorf("ZONES_FILE: must be an absolute path")
		}
		if c.Chroot != "" && !path.IsAbs(c.Chroot) {
			return fmt.Errorf("CHROOT: must be an absolute path")
		}
	case SourcePowerDNSAPI:
		if err := ValidatePDNSURL(c.PDNSAPIURL); err != nil {
			return fmt.Errorf("PDNS_API_URL: %w", err)
		}
		if !path.IsAbs(c.PDNSAPIKeyFile) {
			return fmt.Errorf("PDNS_API_KEY_FILE: must be an absolute path")
		}
	case SourcePdnsutil:
		return fmt.Errorf("ZONE_SOURCE: pdnsutil is planned for a later version; use bind or powerdns-api")
	default:
		return fmt.Errorf("ZONE_SOURCE: must be bind or powerdns-api")
	}
	if c.OwnersFile != "" && !path.IsAbs(c.OwnersFile) {
		return fmt.Errorf("OWNERS_FILE: must be an absolute path or empty")
	}
	for _, p := range c.Exclude {
		if _, err := path.Match(p, "x"); err != nil {
			return fmt.Errorf("EXCLUDE: bad pattern %q", p)
		}
	}
	return nil
}

// ValidateURL accepts only https URLs with a host and no user info, query or
// fragment (spec 11.5: HTTPS only, no insecure option).
func ValidateURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("must start with https:// (plain HTTP is never used)")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("has no host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain user info, a query or a fragment")
	}
	return nil
}

// ValidatePDNSURL accepts http or https URLs whose host is a loopback
// address (spec 7.2: loopback only).
func ValidatePDNSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must be http:// or https://")
	}
	h := u.Hostname()
	if h == "localhost" {
		return nil
	}
	ip := net.ParseIP(h)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("must point at a loopback address (127.0.0.1 or ::1)")
	}
	return nil
}

// SetValues returns text with each key in vals set to its value. Existing
// KEY= lines are rewritten in place (keeping a trailing comment); keys not
// present are appended. Used by enrol, so hand edits and comments survive.
func SetValues(text string, vals map[string]string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	done := map[string]bool{}
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		eq := strings.IndexByte(t, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:eq])
		v, ok := vals[key]
		if !ok {
			continue
		}
		comment := ""
		rest := t[eq+1:]
		for j := 0; j < len(rest); j++ {
			if rest[j] == '#' && j > 0 && (rest[j-1] == ' ' || rest[j-1] == '\t') {
				comment = "   " + rest[j:]
				break
			}
		}
		lines[i] = key + "=" + quoteIfNeeded(v) + comment
		done[key] = true
	}
	text = strings.Join(lines, "\n")
	var add []string
	for _, k := range Keys {
		if v, ok := vals[k]; ok && !done[k] {
			add = append(add, k+"="+quoteIfNeeded(v))
		}
	}
	if len(add) > 0 {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += strings.Join(add, "\n") + "\n"
	}
	return text
}

func quoteIfNeeded(v string) string {
	if strings.Contains(v, "#") {
		return `"` + v + `"`
	}
	return v
}
