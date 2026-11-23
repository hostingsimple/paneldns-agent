package source

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// The PowerDNS API key is read-write and goes in clear text to a loopback
// port. Any local user may listen on a free port above 1023, so a user who
// takes the API port while PowerDNS restarts would receive the key. Before
// each request the agent therefore checks, in /proc/net/tcp and tcp6, that
// every socket listening on the API address belongs to root or the
// PowerDNS user.

// pdnsUsers are the user names PowerDNS runs as on the supported systems.
var pdnsUsers = []string{"pdns", "powerdns"}

// trustedListenerUIDs returns root's uid and the PowerDNS users' uids from
// passwd (system users are always local).
func trustedListenerUIDs(passwd []byte) map[uint32]bool {
	uids := map[uint32]bool{0: true}
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		for _, u := range pdnsUsers {
			if f[0] == u {
				if n, err := strconv.ParseUint(f[2], 10, 32); err == nil {
					uids[uint32(n)] = true
				}
			}
		}
	}
	return uids
}

// listenerUIDs returns the uids of the TCP sockets listening on ip:port
// (or on the wildcard address of its family) in a /proc/net/tcp or tcp6
// table. Addresses are in the kernel's host byte order: this reads
// little-endian machines (amd64, arm64) correctly.
func listenerUIDs(table []byte, ip net.IP, port int) []uint32 {
	var out []uint32
	sc := bufio.NewScanner(bytes.NewReader(table))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[3] != "0A" { // 0A: TCP_LISTEN
			continue
		}
		host, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		raw, err := hex.DecodeString(host)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		for i := 0; i+4 <= len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		local := net.IP(raw)
		if !local.Equal(ip) && !local.IsUnspecified() {
			continue
		}
		uid, err := strconv.ParseUint(f[7], 10, 32)
		if err != nil {
			continue
		}
		out = append(out, uint32(uid))
	}
	return out
}

// checkListener refuses to talk to the API at base unless every socket
// listening on its address belongs to root or the PowerDNS user. readFile
// reads /proc/net/tcp, /proc/net/tcp6 and /etc/passwd.
func checkListener(base string, readFile func(string) ([]byte, error)) error {
	u, err := url.Parse(base)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("PowerDNS API host %q is not an IP address", host)
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil {
			return fmt.Errorf("PowerDNS API port %q: %w", ps, err)
		}
	}
	var uids []uint32
	read := 0
	for _, t := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := readFile(t)
		if err != nil {
			continue
		}
		read++
		uids = append(uids, listenerUIDs(b, ip, port)...)
	}
	if read == 0 {
		if runtime.GOOS != "linux" {
			return nil // development builds
		}
		return errors.New("can't read /proc/net/tcp to check who listens on the PowerDNS API port")
	}
	if len(uids) == 0 {
		return fmt.Errorf("nothing listens on %s:%d (is PowerDNS running with its API on?)", ip, port)
	}
	passwd, _ := readFile("/etc/passwd")
	trusted := trustedListenerUIDs(passwd)
	for _, id := range uids {
		if !trusted[id] {
			return fmt.Errorf("the process listening on %s:%d runs as uid %d, not root or %s; the API key is not sent to it", ip, port, id, strings.Join(pdnsUsers, "/"))
		}
	}
	return nil
}

func osReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
