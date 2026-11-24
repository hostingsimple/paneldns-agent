package enrol

import (
	"path"
	"path/filepath"
	"strings"
)

// The root ACL watcher (docs/DECISIONS.md D-30): a path unit that starts
// `paneldns-agent fix-acls` when a watched directory changes. The
// directories differ per server, so enrol and fix-acls write them into
// drop-ins next to the packaged units.
const (
	ACLPathUnit      = "paneldns-agent-acl.path"
	ACLServiceUnit   = "paneldns-agent-acl.service"
	ACLPathDropIn    = "/etc/systemd/system/paneldns-agent-acl.path.d/watch.conf"
	ACLServiceDropIn = "/etc/systemd/system/paneldns-agent-acl.service.d/watch.conf"
)

// WatchList is what the ACL watcher's drop-ins say.
type WatchList struct {
	// Watch are the directories the path unit watches (PathChanged=):
	// every zone directory and the directory of every other planned file
	// (named.conf, its includes, the owner file).
	Watch []string
	// Writable are the only paths the service may change (ReadWritePaths=):
	// the zone directories, and each planned file or traversed directory
	// outside them. Everything else stays read-only.
	Writable []string
	// ProtectHomeReadOnly is set when a path is under /home, /root or
	// /run/user (HestiaCP keeps zones in home directories): the unit's
	// ProtectHome=yes would hide them.
	ProtectHomeReadOnly bool
	// Rejected are paths left out because a unit file can't hold them
	// safely (whitespace, quotes, backslashes, "%", control characters).
	Rejected []string
}

// PlanWatch works out the watcher's drop-ins from an ACL plan.
func PlanWatch(p *ACLPlan) WatchList {
	var w WatchList
	watch := map[string]bool{}
	writable := map[string]bool{}
	rejected := map[string]bool{}
	ok := func(s string) bool {
		if unitSafe(s) {
			return true
		}
		rejected[s] = true
		return false
	}
	for _, d := range p.Dirs {
		if ok(d) {
			watch[d], writable[d] = true, true
		}
	}
	// A path under a writable directory is writable already.
	under := func(f string) bool {
		for _, d := range append(append([]string{}, p.Dirs...), p.Traverse...) {
			if strings.HasPrefix(f, strings.TrimSuffix(d, "/")+"/") {
				return true
			}
		}
		return false
	}
	for _, f := range p.Read {
		if IsKeyPath(f) || !ok(f) {
			continue
		}
		if d := path.Dir(f); ok(d) {
			watch[d] = true
		}
		if !under(f) {
			writable[f] = true
		}
	}
	for _, d := range p.Traverse {
		if ok(d) {
			writable[d] = true
		}
	}
	w.Watch = sortedKeys(watch)
	w.Writable = sortedKeys(writable)
	w.Rejected = sortedKeys(rejected)
	w.ProtectHomeReadOnly = UnderHome(append(append([]string{}, w.Watch...), w.Writable...))
	return w
}

// homeDirs are what systemd's ProtectHome= hides or makes read-only.
var homeDirs = []string{"/home", "/root", "/run/user"}

// UnderHome reports whether any of paths (host paths) is under a home
// directory, as named or once symbolic links are resolved: a unit with
// ProtectHome=yes can't reach it (HestiaCP keeps zones in home
// directories; a server may have /var/named linked into /home).
func UnderHome(paths []string) bool {
	under := func(s string) bool {
		for _, h := range homeDirs {
			if s == h || strings.HasPrefix(s, h+"/") {
				return true
			}
		}
		return false
	}
	for _, p := range paths {
		if under(p) {
			return true
		}
		if real, err := filepath.EvalSymlinks(rooted(p)); err == nil {
			real = filepath.ToSlash(real)
			if Root != "" {
				real = strings.TrimPrefix(real, filepath.ToSlash(filepath.Clean(Root)))
			}
			if under(real) {
				return true
			}
		}
	}
	return false
}

// unitSafe reports whether a path can go into a unit file as it is.
func unitSafe(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.Contains(s, "/../") || strings.HasSuffix(s, "/..") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r == '"' || r == '\'' || r == '\\' || r == '%' || r == ';' {
			return false
		}
	}
	return true
}

const dropInHeader = "# Written by paneldns-agent (enrol, or fix-acls run by hand as root), which\n" +
	"# rewrites it when the zone directories change. Don't edit: local changes go\n" +
	"# in another file in this directory.\n"

// PathDropIn renders the path unit's drop-in.
func (w WatchList) PathDropIn() string {
	var b strings.Builder
	b.WriteString(dropInHeader)
	b.WriteString("# Directories watched for new, changed or replaced files.\n[Path]\n")
	for _, d := range w.Watch {
		b.WriteString("PathChanged=" + d + "\n")
	}
	return b.String()
}

// ServiceDropIn renders the service's drop-in.
func (w WatchList) ServiceDropIn() string {
	var b strings.Builder
	b.WriteString(dropInHeader)
	b.WriteString("# The only paths fix-acls may change (it sets ACLs on them); everything\n" +
		"# else is read-only. \"-\": a path that doesn't exist (yet) is skipped.\n[Service]\n")
	for _, d := range w.Writable {
		b.WriteString("ReadWritePaths=-" + d + "\n")
	}
	if w.ProtectHomeReadOnly {
		b.WriteString("# Zone files under a home directory: read-only, not hidden.\nProtectHome=read-only\n")
	}
	return b.String()
}
