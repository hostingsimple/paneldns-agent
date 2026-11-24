package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// The agent unit's per-server drop-ins (docs/DECISIONS.md D-21). The
// packaged unit denies loopback, link-local, multicast and the private
// ranges, and hides /home; enrol, `update-units` and `fix-acls` run by hand
// write what this server needs on top.
var (
	// agentNetDropIn allows the addresses in a denied range the agent must
	// reach: the PowerDNS API, the resolvers of /etc/resolv.conf, and
	// PanelDNS itself when its name resolves there (review A-11).
	agentNetDropIn = DropInPath
	// agentHomeDropIn makes home directories readable when zone data lives
	// there (HestiaCP), instead of hidden (review A-12).
	agentHomeDropIn = "/etc/systemd/system/paneldns-agent.service.d/20-paneldns-home.conf"
)

// deniedNets mirrors IPAddressDeny= in packaging/systemd/paneldns-agent.service
// (a test keeps them equal): systemd's localhost, link-local and multicast,
// RFC 1918, shared address space (RFC 6598) and IPv6 unique local addresses.
var deniedNets = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/64"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

func denied(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range deniedNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// lookupHost resolves the PanelDNS host name for the drop-in (root, outside
// the unit's sandbox); replaced in tests.
var lookupHost = func(host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// networkAllow lists the addresses in a denied range the unit must allow:
// the PowerDNS API host (always loopback, spec 7.2), every nameserver in
// /etc/resolv.conf in a denied range (systemd-resolved's 127.0.0.53, a local
// named, a cloud's link-local or VPC resolver, a LAN resolver), and the
// PanelDNS host's own addresses if they are in one (a PanelDNS on the LAN).
func networkAllow(cfg config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		if denied(a) && !seen[a.String()] {
			seen[a.String()] = true
			out = append(out, a.String())
		}
	}
	if cfg.ZoneSource == config.SourcePowerDNSAPI {
		if u, err := url.Parse(cfg.PDNSAPIURL); err == nil {
			h := u.Hostname()
			if h == "localhost" {
				h = "127.0.0.1"
			}
			if a, err := netip.ParseAddr(h); err == nil {
				add(a)
			}
		}
	}
	if f, err := os.Open(enrol.Root + "/etc/resolv.conf"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && fields[0] == "nameserver" {
				if a, err := netip.ParseAddr(fields[1]); err == nil {
					add(a)
				}
			}
		}
	}
	if u, err := url.Parse(cfg.URL); err == nil && u.Hostname() != "" {
		if a, err := netip.ParseAddr(u.Hostname()); err == nil {
			add(a)
		} else if addrs, err := lookupHost(u.Hostname()); err == nil {
			for _, a := range addrs {
				add(a)
			}
		}
	}
	return out
}

// agentDropIns renders the agent unit's drop-ins for this server; "" means
// the file should not exist.
func agentDropIns(allow []string, home bool) map[string]string {
	out := map[string]string{agentNetDropIn: "", agentHomeDropIn: ""}
	if len(allow) > 0 {
		out[agentNetDropIn] = "# Written by paneldns-agent (enrol, update-units, or fix-acls run by hand as root);\n" +
			"# it rewrites this file. Local changes go in another file in this directory.\n" +
			"# Addresses in a range the unit denies that the agent needs: the PowerDNS API,\n" +
			"# the resolvers in /etc/resolv.conf, PanelDNS itself.\n" +
			"[Service]\nIPAddressAllow=" + strings.Join(allow, " ") + "\n"
	}
	if home {
		out[agentHomeDropIn] = "# Written by paneldns-agent (enrol, update-units, or fix-acls run by hand as root);\n" +
			"# it rewrites this file. Local changes go in another file in this directory.\n" +
			"# Zone data under a home directory (HestiaCP): read-only, not hidden.\n" +
			"[Service]\nProtectHome=read-only\n"
	}
	return out
}

// planHome reports whether any path the agent reads is under a home
// directory (the plan's files, zone directories and traversed parents).
func planHome(p *enrol.ACLPlan) bool {
	if p == nil {
		return false
	}
	return enrol.UnderHome(append(append(append([]string{}, p.Read...), p.Dirs...), p.Traverse...))
}

// staleDropIns lists the drop-ins whose content differs from want.
func staleDropIns(want map[string]string) []string {
	var stale []string
	for p, text := range want {
		b, err := os.ReadFile(p)
		switch {
		case text == "" && errors.Is(err, fs.ErrNotExist):
		case err == nil && bytes.Equal(b, []byte(text)):
		default:
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	return stale
}

// syncAgentUnits writes or removes the agent's drop-ins where they differ.
// It does not reload systemd.
func syncAgentUnits(want map[string]string, out io.Writer) (changed bool, err error) {
	if !unitsSupported {
		return false, nil
	}
	for _, p := range staleDropIns(want) {
		text := want[p]
		if text == "" {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return changed, err
			}
			fmt.Fprintf(out, "Unit drop-in %s removed\n", p)
		} else {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return changed, err
			}
			if err := state.WriteAtomic(p, []byte(text), 0o644); err != nil {
				return changed, err
			}
			fmt.Fprintf(out, "Unit drop-in %s written\n", p)
		}
		changed = true
	}
	return changed, nil
}

// cmdUpdateUnits rewrites the per-server drop-ins of the agent and of the
// ACL watcher from the config and the ACL plan, then reloads systemd. The
// package runs it on upgrade, before restarting the agent, so a unit that
// denies more never meets a server whose drop-ins predate it.
func cmdUpdateUnits(args []string, stdout, stderr io.Writer) int {
	fset := newFlagSet("update-units", stderr)
	configPath := fset.String("config", config.DefaultPath, "config file")
	stateDir := fset.String("state-dir", config.StateDir, "state directory")
	quiet := fset.Bool("if-enrolled", false, "do nothing, successfully, on a server that is not enrolled (the package's upgrade step)")
	if fset.Parse(args) != nil {
		return 2
	}
	if geteuid() != 0 {
		fmt.Fprintln(stderr, "paneldns-agent update-units must run as root (it writes unit drop-ins in /etc/systemd/system)")
		return 1
	}
	if _, err := os.Stat(filepath.Join(*stateDir, state.IdentityFile)); err != nil && *quiet {
		return 0
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent update-units:", err)
		return 1
	}
	if err := updateUnits(cfg, nil, stdout, true); err != nil {
		fmt.Fprintln(stderr, "paneldns-agent update-units:", err)
		return 1
	}
	return 0
}

// updateUnits writes the agent's and the ACL watcher's drop-ins (plan nil:
// work it out) and, with reload, reloads systemd if any changed.
func updateUnits(cfg config.Config, plan *enrol.ACLPlan, out io.Writer, reload bool) error {
	if plan == nil {
		var err error
		if plan, err = enrol.PlanACLs(cfg); err != nil {
			return fmt.Errorf("working out read access: %w", err)
		}
	}
	changed, err := syncAgentUnits(agentDropIns(networkAllow(cfg), planHome(plan)), out)
	if err != nil {
		return err
	}
	w := enrol.PlanWatch(plan)
	wchanged, err := syncWatchUnits(w, out, false)
	if err != nil {
		return err
	}
	if !reload || !(changed || wchanged) || !unitsSupported {
		return nil
	}
	if b, err := runSystemctl("daemon-reload"); err != nil {
		fmt.Fprintf(out, "warning: systemctl daemon-reload: %v: %s\n", err, strings.TrimSpace(string(b)))
		return nil
	}
	if changed {
		fmt.Fprintln(out, "The agent picks the new drop-ins up when it restarts: systemctl try-restart paneldns-agent")
	}
	if wchanged {
		if b, err := runSystemctl("try-restart", enrol.ACLPathUnit); err != nil {
			fmt.Fprintf(out, "warning: systemctl try-restart %s: %v: %s\n", enrol.ACLPathUnit, err, strings.TrimSpace(string(b)))
		}
	}
	return nil
}
