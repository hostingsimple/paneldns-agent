// Package enrol implements `paneldns-agent enrol` (spec 7.1, 8.1): detect
// the zone source, generate the key pair on this server, exchange the
// one-time code and the public key for a source id, and write the config
// and state files.
package enrol

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/config"
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
	for _, c := range namedConfs {
		if fileExists(c) {
			d.ZoneSource, d.ZonesFile = config.SourceBIND, c
			return d, nil
		}
	}
	if pdnsFile != "" {
		if !yes(pdns["api"]) {
			return d, fmt.Errorf("found %s but its HTTP API is off (api=no); enable api=yes with an api-key, or use BIND", pdnsFile)
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

func yes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

// readPDNSConf reads key=value pairs from pdns.conf and its include-dir.
func readPDNSConf() (map[string]string, string) {
	vals := map[string]string{}
	for _, p := range pdnsConfs {
		if !fileExists(p) {
			continue
		}
		readKV(rooted(p), vals)
		if dir := vals["include-dir"]; dir != "" {
			matches, _ := filepath.Glob(rooted(path.Join(dir, "*.conf")))
			for _, m := range matches {
				readKV(m, vals)
			}
		}
		return vals, p
	}
	return vals, ""
}

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
		k, v, ok := strings.Cut(line, "=")
		if ok {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
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
