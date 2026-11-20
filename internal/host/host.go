// Package host describes the server the agent runs on: host name, OS,
// hosting panel and public addresses. It reads local files only.
package host

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
)

// Panel identifiers reported to PanelDNS.
const (
	PanelCPanel      = "cpanel"
	PanelDirectAdmin = "directadmin"
	PanelPlesk       = "plesk"
	PanelVirtualmin  = "virtualmin"
	PanelHestia      = "hestiacp"
	PanelISPConfig   = "ispconfig"
	PanelCyberPanel  = "cyberpanel"
	PanelNone        = "none"
)

// Root is prefixed to every path the package looks at (tests).
var Root = ""

func exists(p string) bool {
	_, err := os.Stat(Root + p)
	return err == nil
}

// panelMarkers are checked in order; the first present directory wins.
var panelMarkers = []struct{ panel, path string }{
	{PanelCPanel, "/usr/local/cpanel"},
	{PanelDirectAdmin, "/usr/local/directadmin"},
	{PanelPlesk, "/usr/local/psa"},
	{PanelHestia, "/usr/local/hestia"},
	{PanelCyberPanel, "/usr/local/CyberCP"},
	{PanelISPConfig, "/usr/local/ispconfig"},
	{PanelVirtualmin, "/etc/webmin/virtual-server"},
}

// Panel detects the hosting panel from its install directory.
func Panel() string {
	for _, m := range panelMarkers {
		if exists(m.path) {
			return m.panel
		}
	}
	return PanelNone
}

// Hostname returns the host name or "".
func Hostname() string {
	h, _ := os.Hostname()
	return h
}

// OS returns PRETTY_NAME from /etc/os-release, or GOOS.
func OS() string {
	f, err := os.Open(Root + "/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && k == "PRETTY_NAME" {
			return strings.Trim(v, `"'`)
		}
	}
	return runtime.GOOS
}

// PublicIPs lists this server's global unicast addresses that are not
// private (RFC 1918, ULA), loopback or link-local, sorted.
func PublicIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}
	}
	return filterPublic(addrs)
}

func filterPublic(addrs []net.Addr) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
			continue
		}
		if s := addr.String(); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
