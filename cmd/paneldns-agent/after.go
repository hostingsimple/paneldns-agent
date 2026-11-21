package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// DropInPath is the unit drop-in enrol writes when the agent needs a
// loopback address (spec 7.9: IPAddressAllow= only for the PowerDNS API,
// plus a loopback resolver; docs/DECISIONS.md D-21).
const DropInPath = "/etc/systemd/system/paneldns-agent.service.d/10-paneldns-network.conf"

type afterOptions struct {
	configPath string
	stateDir   string
	noACL      bool
	noStart    bool
	out        io.Writer
}

// afterEnrol runs spec 7.1 steps 3 and 4 after a successful enrolment:
// read ACLs for the agent user, the network drop-in, --check as the agent
// user, and enabling the unit.
func afterEnrol(o afterOptions) func(context.Context, config.Config, enrol.Detected) error {
	return func(ctx context.Context, cfg config.Config, d enrol.Detected) error {
		plan, err := enrol.PlanACLs(cfg)
		if err != nil {
			return fmt.Errorf("working out read access: %w", err)
		}
		for _, w := range plan.Warnings {
			fmt.Fprintln(o.out, "warning:", w)
		}
		for _, s := range plan.Skipped {
			fmt.Fprintf(o.out, "Not readable by the agent (key material): %s\n", s)
		}
		if o.noACL {
			fmt.Fprintln(o.out, "--no-acl: run these yourself:")
			for _, c := range plan.Commands() {
				fmt.Fprintln(o.out, "  "+strings.Join(c, " "))
			}
		} else if err := enrol.ApplyACLs(plan, nil); err != nil {
			return err
		} else {
			fmt.Fprintf(o.out, "Read ACLs set for %s: %d files, %d zone directories, %d parent directories\n",
				enrol.User, len(plan.Read), len(plan.Dirs), len(plan.Traverse))
			// The pass the watcher runs: masks that hide the agent's entry
			// (a 0600 file with an inherited ACL) are raised now too.
			if runtime.GOOS == "linux" {
				if uid, err := lookupAgentUID(); err != nil {
					fmt.Fprintln(o.out, "warning:", err)
				} else if code := runFixACLs(cfg, uid, fixOptions{noWatch: true, out: o.out,
					plan: func(config.Config) (*enrol.ACLPlan, error) { return plan, nil }}); code != 0 {
					return errors.New("fix-acls failed; see the errors above")
				}
			}
		}

		allow := networkAllow(cfg)
		if err := writeDropIn(allow); err != nil {
			return err
		}
		if len(allow) > 0 {
			fmt.Fprintf(o.out, "Unit drop-in %s allows %s\n", DropInPath, strings.Join(allow, " "))
		}
		// The root ACL watcher's drop-ins: written even with --no-acl or
		// --no-start, so enabling it later needs only systemctl.
		watch := enrol.PlanWatch(plan)
		for _, r := range watch.Rejected {
			fmt.Fprintf(o.out, "warning: %s is not watched for ACL resets (characters a unit file can't hold)\n", r)
		}
		if _, err := syncWatchUnits(watch, o.out, false); err != nil {
			return err
		}
		if runtime.GOOS != "linux" {
			return nil
		}
		systemctl(o.out, "daemon-reload")
		if o.noACL || o.noStart {
			fmt.Fprintf(o.out, "--no-acl/--no-start: the ACL watcher is not enabled; enable it with: systemctl enable --now %s\n", enrol.ACLPathUnit)
		} else if err := systemctl(o.out, "enable", enrol.ACLPathUnit); err != nil {
			fmt.Fprintln(o.out, "warning:", err)
		} else if err := systemctl(o.out, "restart", enrol.ACLPathUnit); err != nil {
			fmt.Fprintln(o.out, "warning:", err)
		} else {
			fmt.Fprintf(o.out, "ACL watcher %s enabled: it restores the agent's read access when the panel writes zone files\n", enrol.ACLPathUnit)
		}

		fmt.Fprintln(o.out, "\nRunning paneldns-agent --check as", enrol.User, "...")
		self, err := os.Executable()
		if err != nil {
			return err
		}
		out, err := runAsAgent(self, "--check", "--config", o.configPath, "--state-dir", o.stateDir)
		o.out.Write(out)
		if err != nil {
			return errors.New("the self-check failed; fix the problems above, then run: systemctl enable --now paneldns-agent")
		}
		if o.noStart {
			fmt.Fprintln(o.out, "--no-start: start the agent with: systemctl enable --now paneldns-agent")
			return nil
		}
		if err := systemctl(o.out, "enable", "paneldns-agent"); err != nil {
			return err
		}
		if err := systemctl(o.out, "restart", "paneldns-agent"); err != nil {
			return err
		}
		fmt.Fprintln(o.out, "paneldns-agent is enabled and running. Follow it with: journalctl -u paneldns-agent -f")
		return nil
	}
}

func systemctl(out io.Writer, args ...string) error {
	b, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		out.Write(b)
		return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// networkAllow lists the loopback addresses the unit must allow: the
// PowerDNS API host, and nameservers in /etc/resolv.conf on loopback
// (systemd-resolved's 127.0.0.53, or a local named), because
// IPAddressDeny=localhost would otherwise stop name resolution.
func networkAllow(cfg config.Config) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a netip.Addr) {
		if a.IsLoopback() && !seen[a.String()] {
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
	return out
}

func writeDropIn(allow []string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if len(allow) == 0 {
		err := os.Remove(DropInPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(DropInPath), 0o755); err != nil {
		return err
	}
	text := "# Written by paneldns-agent enrol; re-running enrol rewrites it.\n" +
		"# Loopback addresses the agent needs: the PowerDNS API and/or a local resolver.\n" +
		"[Service]\nIPAddressAllow=" + strings.Join(allow, " ") + "\n"
	return state.WriteAtomic(DropInPath, []byte(text), 0o644)
}
