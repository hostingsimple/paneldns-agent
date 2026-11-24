package namedconf

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Zone is one primary zone of the selected view.
type Zone struct {
	Name       string // lower case, no trailing dot ("." for the root)
	File       string // host path of the zone file
	Journal    string // host path of the journal
	CheckNames string // fail | warn | ignore (named-compilezone -k)
	Integrity  string // local | local-sibling | none (named-compilezone -i)
	Format     string // text | raw | map (named-compilezone -f)
	DeclaredIn string // host path of the config file that declares it
}

// Conf is the part of named's configuration the agent uses.
type Conf struct {
	// Directory is named's working directory as a host path.
	Directory string
	// View is the view read; "" when the config has no views.
	View string
	// Views lists every view in file order.
	Views []string
	// Zones are the primary zones of the view, in file order.
	Zones []Zone
	// Skipped counts zones of the view that are not primary or have no file.
	Skipped int
	// OtherViews maps a zone name found only in other views to those views.
	OtherViews map[string][]string
	// Includes lists every include met, readable or not.
	Includes []Include
	// PidFile is named's pid file as a host path ("" = named's default).
	PidFile string
	// InlineKeys are key statements in files the agent reads.
	InlineKeys []KeyRef
	// KeyDirs are the DNSSEC key directories named.conf sets with
	// key-directory (options, any view, any zone), as host paths, sorted.
	// named's working directory, the default, is not listed.
	KeyDirs []string
}

// Read loads named.conf at hostPath and resolves the zones of view (""
// applies the default rule of spec 7.3).
func Read(l *Loader, hostPath, view string) (*Conf, error) {
	stmts, err := l.Load(hostPath)
	if err != nil {
		return nil, err
	}
	return Resolve(stmts, l, hostPath, view)
}

// Resolve works out directory, view and zones from parsed statements.
func Resolve(stmts []*Stmt, l *Loader, hostPath, wantView string) (*Conf, error) {
	c := &Conf{OtherViews: map[string][]string{}, Includes: l.Includes, InlineKeys: l.InlineKeys}
	opts := Find(stmts, "options")
	var optBlock []*Stmt
	if opts != nil {
		optBlock = opts.Block
	}
	// named's default directory is its working directory; the agent uses
	// the config file's directory (docs/DECISIONS.md D-04).
	c.Directory = path.Dir(hostPath)
	if d := Find(optBlock, "directory"); d != nil && d.Arg(1) != "" {
		c.Directory = l.HostPath(d.Arg(1), path.Dir(hostPath))
	}
	if p := Find(optBlock, "pid-file"); p != nil && p.Arg(1) != "" && !strings.EqualFold(p.Arg(1), "none") {
		c.PidFile = l.HostPath(p.Arg(1), c.Directory)
	}

	type viewInfo struct {
		name       string
		block      []*Stmt
		matchesAny bool
	}
	var views []viewInfo
	for _, s := range stmts {
		if s.Name() == "view" && s.HasBlock {
			v := viewInfo{name: s.Arg(1), block: s.Block}
			mc := Find(s.Block, "match-clients")
			v.matchesAny = mc == nil
			if mc != nil {
				for _, e := range mc.Block {
					if len(e.Args) == 1 && strings.EqualFold(e.Args[0], "any") {
						v.matchesAny = true
						break
					}
					// An earlier element that negates or matches a
					// subset doesn't stop "any" later from matching, but
					// a leading "!any" means nobody: keep it simple and
					// only accept a plain "any".
				}
			}
			views = append(views, v)
			c.Views = append(c.Views, v.name)
		}
	}

	var zoneBlock []*Stmt
	var viewBlock []*Stmt
	if len(views) == 0 {
		if wantView != "" && wantView != "_default" {
			return nil, fmt.Errorf("VIEW=%s is set but named.conf has no views", wantView)
		}
		zoneBlock = stmts
	} else {
		pick := -1
		if wantView != "" {
			for i, v := range views {
				if v.name == wantView {
					pick = i
					break
				}
			}
			if pick < 0 {
				return nil, fmt.Errorf("VIEW=%s not found; views are: %s", wantView, strings.Join(c.Views, ", "))
			}
		} else {
			for _, rule := range []func(viewInfo) bool{
				func(v viewInfo) bool { return v.name == "_default" },
				func(v viewInfo) bool { return v.name == "external" },
				func(v viewInfo) bool { return v.matchesAny },
			} {
				for i, v := range views {
					if rule(v) {
						pick = i
						break
					}
				}
				if pick >= 0 {
					break
				}
			}
			if pick < 0 {
				return nil, fmt.Errorf("no view named _default or external and none matches any client; set VIEW (views are: %s)", strings.Join(c.Views, ", "))
			}
		}
		c.View = views[pick].name
		zoneBlock = views[pick].block
		viewBlock = views[pick].block
	}

	inView := map[string]bool{}
	for _, s := range zoneBlock {
		if s.Name() != "zone" || !s.HasBlock {
			continue
		}
		name := NormalizeName(s.Arg(1))
		inView[name] = true
		typ := strings.ToLower(argOf(s.Block, "type"))
		file := argOf(s.Block, "file")
		if (typ != "primary" && typ != "master") || file == "" || Find(s.Block, "in-view") != nil {
			c.Skipped++
			continue
		}
		z := Zone{
			Name:       name,
			File:       l.HostPath(file, c.Directory),
			CheckNames: checkNames(s.Block, viewBlock, optBlock),
			Integrity:  integrity(s.Block, viewBlock, optBlock),
			Format:     strings.ToLower(firstNonEmpty(argOf(s.Block, "masterfile-format"), argOf(viewBlock, "masterfile-format"), argOf(optBlock, "masterfile-format"), "text")),
			DeclaredIn: s.File,
		}
		if j := argOf(s.Block, "journal"); j != "" {
			z.Journal = l.HostPath(j, c.Directory)
		} else {
			z.Journal = z.File + ".jnl"
		}
		c.Zones = append(c.Zones, z)
	}
	for _, v := range views {
		if v.name == c.View {
			continue
		}
		for _, s := range v.block {
			if s.Name() != "zone" || !s.HasBlock {
				continue
			}
			name := NormalizeName(s.Arg(1))
			if inView[name] {
				continue
			}
			typ := strings.ToLower(argOf(s.Block, "type"))
			if typ != "primary" && typ != "master" {
				continue
			}
			c.OtherViews[name] = append(c.OtherViews[name], v.name)
		}
	}
	for k := range c.OtherViews {
		sort.Strings(c.OtherViews[k])
	}
	c.KeyDirs = keyDirectories(stmts, optBlock, l, c.Directory)
	return c, nil
}

// keyDirectories collects every key-directory: in options, in each view,
// and in each zone at top level or in a view, whichever view is read (the
// ACL plan must keep all of them from the agent).
func keyDirectories(stmts, optBlock []*Stmt, l *Loader, dir string) []string {
	seen := map[string]bool{}
	add := func(block []*Stmt) {
		if d := argOf(block, "key-directory"); d != "" {
			seen[path.Clean(l.HostPath(d, dir))] = true
		}
	}
	add(optBlock)
	zones := func(block []*Stmt) {
		for _, s := range block {
			if s.Name() == "zone" && s.HasBlock {
				add(s.Block)
			}
		}
	}
	zones(stmts)
	for _, s := range stmts {
		if s.Name() == "view" && s.HasBlock {
			add(s.Block)
			zones(s.Block)
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// NormalizeName lower-cases a zone name and drops the trailing dot (the
// root zone stays ".").
func NormalizeName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if n == "." || n == "" {
		return n
	}
	return strings.TrimSuffix(n, ".")
}

func argOf(block []*Stmt, name string) string {
	if s := Find(block, name); s != nil {
		return s.Arg(1)
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// checkNames finds the effective check-names mode for a primary zone:
// the zone's own "check-names <mode>", then "check-names primary|master
// <mode>" in the view and in options, then named's default, fail.
func checkNames(zone, view, opts []*Stmt) string {
	if s := Find(zone, "check-names"); s != nil && validMode(s.Arg(1)) {
		return strings.ToLower(s.Arg(1))
	}
	for _, block := range [][]*Stmt{view, opts} {
		for _, s := range block {
			if s.Name() != "check-names" {
				continue
			}
			t := strings.ToLower(s.Arg(1))
			if (t == "primary" || t == "master") && validMode(s.Arg(2)) {
				return strings.ToLower(s.Arg(2))
			}
		}
	}
	return "fail"
}

func validMode(m string) bool {
	switch strings.ToLower(m) {
	case "fail", "warn", "ignore":
		return true
	}
	return false
}

// integrity maps check-integrity and check-sibling (zone, view, options;
// both default yes for a primary zone) to named-compilezone's -i mode.
// named's own check-integrity looks only at in-zone data, which is
// named-compilezone's "local" mode; "full" would look names up in the DNS.
func integrity(zone, view, opts []*Stmt) string {
	yes := func(name string) bool {
		v := strings.ToLower(firstNonEmpty(argOf(zone, name), argOf(view, name), argOf(opts, name), "yes"))
		return v == "yes" || v == "true" || v == "1"
	}
	if !yes("check-integrity") {
		return "none"
	}
	if !yes("check-sibling") {
		return "local-sibling"
	}
	return "local"
}

// ErrInlineKey means a key secret sits in a file the agent must read.
var ErrInlineKey = errors.New("named.conf holds a key secret in a file the agent reads")

// InlineKeyError explains which key statements to move, or returns nil.
func InlineKeyError(keys []KeyRef) error {
	if len(keys) == 0 {
		return nil
	}
	locs := make([]string, len(keys))
	for i, k := range keys {
		locs[i] = k.String()
	}
	return fmt.Errorf("%w: %s. Move each key statement into a separate file that holds only key statements (for example /etc/named.keys.conf, mode 0640 root:named), include that file from named.conf, and don't grant paneldns-agent read access to it", ErrInlineKey, strings.Join(locs, ", "))
}
