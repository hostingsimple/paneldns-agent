// Package enrol implements `paneldns-agent enrol` (spec 7.1, 8.1): detect
// the zone source, generate the key pair on this server, exchange the
// one-time code and the public key for a source id, and write the config
// and state files.
package enrol

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/syspath"
)

// Root is prefixed to every path detection looks at (tests).
var Root = ""

func rooted(p string) string { return Root + p }

func fileExists(p string) bool {
	fi, err := os.Stat(rooted(p))
	return err == nil && !fi.IsDir()
}

// Detected is what enrol found on this server.
type Detected struct {
	ZoneSource string
	ZonesFile  string
	Chroot     string
	PDNSAPIURL string
	PDNSAPIKey string // plain key, copied into PDNS_API_KEY_FILE
	OwnersFile string
	Notes      []string
}

// namedConfs are the usual named.conf locations.
var namedConfs = []string{"/etc/named.conf", "/etc/bind/named.conf", "/etc/namedb/named.conf", "/usr/local/etc/namedb/named.conf"}

var pdnsConfs = []string{"/etc/powerdns/pdns.conf", "/etc/pdns/pdns.conf"}

// DetectSource finds the zone source. BIND wins when a named.conf exists,
// which also covers PowerDNS with the bind backend reading the same files
// (cPanel); otherwise a PowerDNS with its API on a loopback address.
func DetectSource() (Detected, error) {
	var d Detected
	pdns, pdnsFile := readPDNSConf()
	if bc := pdns["bind-config"]; bc != "" && fileExists(bc) {
		d.ZoneSource, d.ZonesFile = config.SourceBIND, bc
		d.Notes = append(d.Notes, fmt.Sprintf("PowerDNS bind backend in %s reads %s", pdnsFile, bc))
		return d, nil
	}
	if chroot, conf := detectChroot(); chroot != "" {
		d.ZoneSource, d.ZonesFile, d.Chroot = config.SourceBIND, conf, chroot
		d.Notes = append(d.Notes, "chrooted named in "+chroot)
		return d, nil
	}
	// P1 on fusion (DirectAdmin on Ubuntu 24.04): /etc/named.conf was a stale panel template
	// pointing at a /var/named that did not exist, while the running named read
	// /etc/bind/named.conf. The config the running named uses wins over the first file found.
	if c, how := runningNamedConf(); c != "" && fileExists(c) {
		d.ZoneSource, d.ZonesFile = config.SourceBIND, c
		if others := otherNamedConfs(c); len(others) > 0 {
			d.Notes = append(d.Notes, fmt.Sprintf("named reads %s (%s); also found, not used: %s", c, how, strings.Join(others, ", ")))
		}
		return d, nil
	}
	for _, c := range namedConfs {
		if fileExists(c) {
			d.ZoneSource, d.ZonesFile = config.SourceBIND, c
			if others := otherNamedConfs(c); len(others) > 0 {
				d.Notes = append(d.Notes, fmt.Sprintf("named is not running; chose %s, also found %s: check ZONES_FILE", c, strings.Join(others, ", ")))
			}
			return d, nil
		}
	}
	if pdnsFile != "" {
		v, set := pdns["api"]
		switch {
		case !set:
			return d, fmt.Errorf("found %s but it doesn't set api, so the PowerDNS HTTP API is off (its default, and CyberPanel's); %s", pdnsFile, apiHowTo)
		case pdnsBool(v) == pdnsOff:
			return d, fmt.Errorf("found %s but its HTTP API is off (api=%s); %s", pdnsFile, v, apiHowTo)
		case pdnsBool(v) == pdnsUnclear:
			return d, fmt.Errorf("found %s with api=%s, which PowerDNS reads as on (only no and off turn it off) but looks meant as off; write api=yes to use the API with the agent, or api=no", pdnsFile, v)
		}
		key := pdns["api-key"]
		if key == "" {
			return d, fmt.Errorf("%s has no api-key", pdnsFile)
		}
		if strings.HasPrefix(key, "$") {
			return d, fmt.Errorf("%s stores a hashed api-key, which can't be copied; write the plain key to %s/pdns-api-key (mode 0600) and set ZONE_SOURCE=powerdns-api by hand", pdnsFile, config.StateDir)
		}
		addr := pdns["webserver-address"]
		switch addr {
		case "", "0.0.0.0", "::", "127.0.0.1":
			addr = "127.0.0.1"
		case "::1":
			addr = "[::1]"
		default:
			return d, fmt.Errorf("the PowerDNS API listens on %s only; the agent needs it on a loopback address", addr)
		}
		port := pdns["webserver-port"]
		if port == "" {
			port = "8081"
		}
		d.ZoneSource = config.SourcePowerDNSAPI
		d.PDNSAPIURL = "http://" + addr + ":" + port
		d.PDNSAPIKey = key
		return d, nil
	}
	return d, fmt.Errorf("no named.conf (%s) and no pdns.conf found; set ZONE_SOURCE and ZONES_FILE in %s by hand", strings.Join(namedConfs, ", "), config.DefaultPath)
}

// apiHowTo is what enrol tells an admin whose PowerDNS has no HTTP API (D-33).
// The agent only reads through it, from loopback.
const apiHowTo = "add these lines to pdns.conf and restart PowerDNS, then run enrol again: " +
	"api=yes, api-key=<a long random key>, webserver-address=127.0.0.1, webserver-port=8081, " +
	"webserver-allow-from=127.0.0.1,::1"

// A pdns.conf boolean as enrol reads it.
const (
	pdnsOnValue = iota
	pdnsOff
	pdnsUnclear
)

// pdnsBool reads a pdns.conf boolean that is present in the file.
// PowerDNS's ArgvMap::mustDo is on for every value but exactly "no" and
// "off"; a bare key ("api") is set to "" and so is on. Enrol follows it for
// those, and for the usual spellings of on (yes, true, 1, on, any case).
// Anything else PowerDNS also reads as on, but "false", "0", "No", "OFF" and
// the like look meant as off, and enrol copies a read-write API key on this
// answer, so it refuses those instead of guessing either way.
func pdnsBool(v string) int {
	switch v {
	case "no", "off":
		return pdnsOff
	}
	switch strings.ToLower(v) {
	case "", "yes", "true", "1", "on":
		return pdnsOnValue
	}
	return pdnsUnclear
}

// readPDNSConf reads key=value pairs and bare keys from pdns.conf and its include-dir.
func readPDNSConf() (map[string]string, string) {
	vals := map[string]string{}
	for _, p := range pdnsConfs {
		if !fileExists(p) {
			continue
		}
		readPDNSFile(rooted(p), vals)
		if dir := vals["include-dir"]; dir != "" {
			matches, _ := filepath.Glob(rooted(path.Join(dir, "*.conf")))
			for _, m := range matches {
				readPDNSFile(m, vals)
			}
		}
		return vals, p
	}
	return vals, ""
}

// readPDNSFile reads a pdns.conf as PowerDNS's ArgvMap::parseFile does: a
// line ending in a backslash continues on the next; a "#" at the start of
// the line or after white space starts a comment (so "api=yes  # on" is
// "yes", but "#" inside a value, as in a key, stays); a line without "="
// is a bare key with an empty value (on, for a boolean); the key is
// trimmed, and so is the value.
func readPDNSFile(p string, vals map[string]string) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	line := ""
	for sc.Scan() {
		part := strings.TrimRightFunc(sc.Text(), unicode.IsSpace)
		if strings.HasSuffix(part, "\\") {
			line += strings.TrimSuffix(part, "\\")
			continue
		}
		line += part
		for i := 0; i < len(line); i++ {
			if line[i] == '#' && (i == 0 || unicode.IsSpace(rune(line[i-1]))) {
				line = line[:i]
				break
			}
		}
		l := strings.TrimSpace(line)
		line = ""
		if l == "" {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
}

// readKV reads shell-style KEY=value lines (/etc/sysconfig/named).
func readKV(p string, vals map[string]string) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A line without "=" is a bare key, which PowerDNS reads as the key
		// with an empty value (on, for a boolean); keep it, set to "".
		k, v, _ := strings.Cut(line, "=")
		vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
}

// detectChroot finds a chrooted named: ROOTDIR in /etc/sysconfig/named
// (the RHEL convention, also used by Plesk's run-root), an enabled
// named-chroot.service, or /etc/named.conf being a link into a chroot.
func detectChroot() (chroot, conf string) {
	check := func(dir string) bool {
		return dir != "" && dir != "/" && fileExists(path.Join(dir, "etc/named.conf"))
	}
	vals := map[string]string{}
	readKV(rooted("/etc/sysconfig/named"), vals)
	if d := strings.Trim(vals["ROOTDIR"], `"'`); check(d) {
		return d, path.Join(d, "etc/named.conf")
	}
	if fileExists("/etc/systemd/system/multi-user.target.wants/named-chroot.service") && check("/var/named/chroot") {
		return "/var/named/chroot", "/var/named/chroot/etc/named.conf"
	}
	if real, err := filepath.EvalSymlinks(rooted("/etc/named.conf")); err == nil {
		real = filepath.ToSlash(strings.TrimPrefix(real, filepath.Clean(Root)))
		for _, d := range []string{"/var/named/run-root", "/var/named/chroot"} {
			if strings.HasPrefix(real, d+"/") && check(d) {
				return d, real
			}
		}
	}
	return "", ""
}

// namedVersionOutput runs `named -V`, whose "named configuration:" line is the compiled-in
// default config path (tests replace it).
var namedVersionOutput = func() ([]byte, error) {
	cmd, err := syspath.Command("named", "-V")
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

// runningNamedConf returns the named.conf the running named reads: its -c argument, or else
// the compiled-in default from `named -V`. Empty when no named process is found.
func runningNamedConf() (conf, how string) {
	entries, err := os.ReadDir(rooted("/proc"))
	if err != nil {
		return "", ""
	}
	found := false
	var trusted map[string]bool
	for _, e := range entries {
		if !e.IsDir() || strings.Trim(e.Name(), "0123456789") != "" {
			continue
		}
		comm, err := os.ReadFile(rooted("/proc/" + e.Name() + "/comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "named" {
			continue
		}
		// Any local user can start a process called "named" with a -c of
		// their choosing; only one running as root or as named's own user
		// is the real named.
		if trusted == nil {
			trusted = namedUIDs()
		}
		if !procRunsAs(e.Name(), trusted) {
			continue
		}
		found = true
		raw, err := os.ReadFile(rooted("/proc/" + e.Name() + "/cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				return args[i+1], "named -c"
			}
			if strings.HasPrefix(a, "-c") && len(a) > 2 {
				return a[2:], "named -c"
			}
		}
	}
	if !found {
		return "", ""
	}
	out, err := namedVersionOutput()
	if err != nil {
		return "", ""
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if k, v, ok := strings.Cut(string(line), ":"); ok && strings.TrimSpace(k) == "named configuration" {
			return strings.TrimSpace(v), "named -V default"
		}
	}
	return "", ""
}

// namedUIDs are the uids a real named runs as: root, which starts it, and
// the named or bind user it switches to with -u (from /etc/passwd; system
// users are always local).
func namedUIDs() map[string]bool {
	uids := map[string]bool{"0": true}
	b, err := os.ReadFile(rooted("/etc/passwd"))
	if err != nil {
		return uids
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) > 2 && (f[0] == "named" || f[0] == "bind") && f[2] != "" {
			uids[f[2]] = true
		}
	}
	return uids
}

// procRunsAs reports whether every uid of a process (real, effective,
// saved, file system; the Uid: line of /proc/PID/status) is in uids.
func procRunsAs(pid string, uids map[string]bool) bool {
	b, err := os.ReadFile(rooted("/proc/" + pid + "/status"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "Uid:" {
			continue
		}
		for _, u := range f[1:] {
			if !uids[u] {
				return false
			}
		}
		return true
	}
	return false
}

// otherNamedConfs lists the usual named.conf locations that exist besides chosen.
func otherNamedConfs(chosen string) []string {
	var others []string
	for _, c := range namedConfs {
		if c != chosen && fileExists(c) {
			others = append(others, c)
		}
	}
	return others
}
