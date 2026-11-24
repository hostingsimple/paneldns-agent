package enrol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/namedconf"
)

// ACLPlan is the read access the agent needs (spec 7.9): POSIX ACL entries
// for the agent user only, never group membership in named, bind or pdns.
type ACLPlan struct {
	Read     []string // files: u:paneldns-agent:r
	Dirs     []string // zone directories: u:paneldns-agent:rx plus default u:paneldns-agent:r (not on NoDefault ones)
	Traverse []string // parent directories not searchable by others: u:paneldns-agent:x
	Skipped  []string // files deliberately left unreadable (key material)
	// NoDefault are the zone directories (of Dirs) that also hold, or are where
	// tools write, configuration or key files: they get rx but never a default
	// ACL, which a key file created there later would inherit (review A-7).
	// fix-acls removes an agent default entry an older version left on them.
	NoDefault []string
	// Strip are key files in planned directories and in the DNSSEC key
	// directories, and the Skipped files: fix-acls removes any entry the
	// agent has on them (an inherited one).
	Strip []string
	// KeyDirs are named.conf's key-directory folders. They never get rx or
	// a default ACL: one that is also a zone directory is in NoDefault, any
	// other is not in Dirs at all (only x, in Traverse, when the agent must
	// pass through it), and fix-acls removes the agent's default entry, and
	// its access entry unless it is in Traverse.
	KeyDirs  []string
	Warnings []string

	// ids is what each Read, Dirs and Traverse path reached when the plan
	// was made (Linux): setfacl is only run on that same object (fdwalk.go).
	ids map[string]fileID
}

// aclSet is one setfacl invocation for a list of paths of one kind.
type aclSet struct {
	prefix []string
	paths  []string
	dir    bool
}

func (p *ACLPlan) sets() []aclSet {
	u := "u:" + User
	return []aclSet{
		{[]string{"setfacl", "-m", u + ":x"}, p.Traverse, true},
		{[]string{"setfacl", "-m", u + ":rx"}, p.Dirs, true},
		{[]string{"setfacl", "-d", "-m", u + ":r"}, p.defaultDirs(), true},
		{[]string{"setfacl", "-m", u + ":r"}, p.Read, false},
	}
}

// Commands returns the setfacl command lines for the plan.
func (p *ACLPlan) Commands() [][]string {
	var out [][]string
	for _, s := range p.sets() {
		for paths := s.paths; len(paths) > 0; {
			n := min(len(paths), aclBatch)
			out = append(out, append(append([]string{}, s.prefix...), paths[:n]...))
			paths = paths[n:]
		}
	}
	return out
}

// aclBatch is the most paths one setfacl call gets (and so the most
// descriptors ApplyACLs holds open at once).
const aclBatch = 200

// defaultDirs are the zone directories that get the default ACL.
func (p *ACLPlan) defaultDirs() []string {
	no := map[string]bool{}
	for _, d := range p.NoDefault {
		no[d] = true
	}
	var out []string
	for _, d := range p.Dirs {
		if !no[d] {
			out = append(out, d)
		}
	}
	return out
}

// statFunc is replaced in tests.
var statFunc = os.Stat

// PlanACLs works out which files and directories the agent must read.
// It runs as root, so it can read what the agent can't yet.
func PlanACLs(cfg config.Config) (*ACLPlan, error) {
	p := &ACLPlan{}
	read := map[string]bool{}
	dirs := map[string]bool{}
	// Directories that hold named's configuration (named.conf and its
	// includes): key files are kept, and created, next to it.
	confDirs := map[string]bool{}
	var keyDirs []string
	if cfg.ZoneSource == config.SourceBIND {
		l := &namedconf.Loader{ReadFile: readRooted, Glob: globRooted, Chroot: cfg.Chroot}
		conf, err := namedconf.Read(l, cfg.ZonesFile, cfg.View)
		if err != nil {
			return nil, err
		}
		if err := namedconf.InlineKeyError(conf.InlineKeys); err != nil {
			return nil, err
		}
		files := []string{cfg.ZonesFile}
		confDirs[path.Dir(cfg.ZonesFile)] = true
		for _, inc := range conf.Includes {
			confDirs[path.Dir(inc.Path)] = true
			if inc.Readable {
				files = append(files, inc.Path)
			}
		}
		for _, f := range files {
			hasKey, hasOther, err := classify(f)
			if err != nil {
				return nil, err
			}
			if hasKey && f != cfg.ZonesFile && !hasOther {
				// A separate key file: never readable by the agent.
				p.Skipped = append(p.Skipped, f)
				continue
			}
			read[f] = true
		}
		allowed := []string{conf.Directory}
		for _, z := range conf.Zones {
			read[z.File] = true
			if _, err := statFunc(rooted(z.Journal)); err == nil {
				read[z.Journal] = true
			}
			dirs[path.Dir(z.File)] = true
			allowed = append(allowed, path.Dir(z.File))
		}
		// Files a zone pulls in with $INCLUDE need the same access as the
		// zone file, or named-compilezone can't read the zone as the agent.
		for _, z := range conf.Zones {
			if z.Format != "text" {
				continue
			}
			incs, warns, err := zoneIncludes(z.File, conf.Directory, cfg.Chroot, allowed)
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.Name, err)
			}
			p.Warnings = append(p.Warnings, warns...)
			for _, f := range incs {
				read[f] = true
				dirs[path.Dir(f)] = true
			}
		}
		// A DNSSEC key directory is never listable by the agent: unless
		// zone files live in it too, it leaves Dirs (a public K*.key file
		// $INCLUDEd from it still gets read access, and the folder x).
		keyDirs = conf.KeyDirs
		zoneDirs := map[string]bool{}
		for _, z := range conf.Zones {
			zoneDirs[path.Dir(z.File)] = true
		}
		for _, kd := range keyDirs {
			if !zoneDirs[kd] {
				delete(dirs, kd)
			}
		}
	}
	if cfg.OwnersFile != "" {
		if _, err := statFunc(rooted(cfg.OwnersFile)); err == nil {
			read[cfg.OwnersFile] = true
		}
	}
	// setfacl follows symbolic links: never grant through one a user
	// could have planted, and note what each path reaches so a component
	// swapped later is refused when the ACL is set.
	p.Warnings = append(p.Warnings, dropUntrusted(read)...)
	p.Warnings = append(p.Warnings, p.recordIDs(read)...)
	p.Warnings = append(p.Warnings, dropUntrusted(dirs)...)
	p.Warnings = append(p.Warnings, p.recordIDs(dirs)...)
	traverse := map[string]bool{}
	for f := range read {
		addParents(path.Dir(f), traverse)
	}
	for d := range dirs {
		addParents(path.Dir(d), traverse)
	}
	for d := range dirs {
		delete(traverse, d)
	}
	p.Warnings = append(p.Warnings, dropUntrusted(traverse)...)
	p.Warnings = append(p.Warnings, p.recordIDs(traverse)...)
	p.Read = sortedKeys(read)
	p.Dirs = sortedKeys(dirs)
	p.Traverse = sortedKeys(traverse)
	p.KeyDirs = keyDirs
	p.planKeyDirs(cfg.Chroot, confDirs, read)
	return p, nil
}

// planKeyDirs fills NoDefault and Strip (review A-7). A default ACL on a
// directory is inherited by every file created in it, key files included:
// `rndc-confgen -a` or `tsig-keygen > x.key` in Debian's /etc/bind, which
// is also its zone directory, would leave a key the agent can read. So a
// zone directory gets no default ACL when it holds named's configuration,
// is where the rndc key lives, or holds key material now; new zone files
// there get their ACL from the root watcher (fix-acls) instead.
func (p *ACLPlan) planKeyDirs(chroot string, confDirs, read map[string]bool) {
	keyDirs := map[string]bool{}
	for _, d := range p.KeyDirs {
		keyDirs[d] = true
	}
	for k := range keyPaths {
		keyDirs[path.Dir(k)] = true
		if chroot != "" {
			keyDirs[path.Join(chroot, path.Dir(k))] = true
		}
	}
	strip := map[string]bool{}
	for _, s := range p.Skipped {
		strip[s] = true
	}
	for _, d := range p.KeyDirs {
		keys, err := keyFilesIn(d)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			p.Warnings = append(p.Warnings, fmt.Sprintf("key-directory %s: listing it: %v", d, err))
		}
		for _, k := range keys {
			if !read[k] {
				strip[k] = true
			}
		}
	}
	var noDefault []string
	for _, d := range p.Dirs {
		keys, err := keyFilesIn(d)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil // nothing in it to inherit anything
		} else if err != nil {
			// Unlistable even as root: assume the worst.
			p.Warnings = append(p.Warnings, fmt.Sprintf("no default ACL on %s: listing it: %v", d, err))
		}
		for _, k := range keys {
			if !read[k] {
				strip[k] = true
			}
		}
		if confDirs[d] || keyDirs[d] || len(keys) > 0 || err != nil {
			noDefault = append(noDefault, d)
		}
	}
	p.NoDefault = noDefault
	if len(strip) > 0 {
		p.Strip = sortedKeys(strip)
	}
	// No ACL can take away what the mode gives everyone.
	for _, k := range p.Strip {
		if fi, err := statFunc(rooted(k)); err == nil && fi.Mode().Perm()&0o004 != 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("key file %s has mode %04o: every local user can read it; chmod o-r it", k, fi.Mode().Perm()))
		}
	}
}

// keyFilesIn lists the regular files in directory d (host path) that are
// key material by name: the rndc key and config, DNSSEC private keys, and
// any *.key file (TSIG keys, DNSSEC key pairs). Symbolic links are left
// out: fix-acls must not follow one.
func keyFilesIn(d string) ([]string, error) {
	entries, err := os.ReadDir(rooted(d))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		f := path.Join(d, e.Name())
		if e.Type().IsRegular() && (IsKeyPath(f) || strings.HasSuffix(e.Name(), ".key")) {
			out = append(out, f)
		}
	}
	return out, nil
}

// addParents adds d and its parents that others can't search.
func addParents(d string, out map[string]bool) {
	for d != "/" && d != "." && d != "" {
		if fi, err := statFunc(rooted(d)); err == nil && fi.Mode().Perm()&0o001 == 0 {
			out[d] = true
		}
		d = path.Dir(d)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func readRooted(p string) ([]byte, error) { return os.ReadFile(rooted(p)) }

func globRooted(p string) ([]string, error) {
	m, err := filepath.Glob(rooted(p))
	for i := range m {
		m[i] = strings.TrimPrefix(filepath.ToSlash(m[i]), filepath.ToSlash(Root))
	}
	return m, err
}

// classify reports whether a config file has key statements and whether
// it has anything else.
func classify(f string) (hasKey, hasOther bool, err error) {
	b, err := readRooted(f)
	if err != nil {
		return false, false, err
	}
	stmts, err := namedconf.ParseStatements(b, f)
	if err != nil {
		return false, false, err
	}
	for _, s := range stmts {
		switch s.Name() {
		case "key", "tsig-keygen":
			hasKey = true
		case "include":
		default:
			hasOther = true
		}
	}
	return hasKey, hasOther, nil
}

// ApplyACLs runs the plan's setfacl commands. With run nil, each path is
// opened without following symbolic links and must still be what the plan
// saw (openPlanned); setfacl gets the descriptors, not the paths. A path
// that changed stops enrolment: someone is racing it.
func ApplyACLs(p *ACLPlan, run func(argv []string) error) error {
	if run != nil {
		for _, c := range p.Commands() {
			if err := run(c); err != nil {
				return err
			}
		}
		return nil
	}
	for _, s := range p.sets() {
		for paths := s.paths; len(paths) > 0; {
			n := min(len(paths), aclBatch)
			if err := p.applyBatch(s, paths[:n]); err != nil {
				return err
			}
			paths = paths[n:]
		}
	}
	return nil
}

func (p *ACLPlan) applyBatch(s aclSet, paths []string) error {
	argv := append([]string{}, s.prefix...)
	files := map[string]*os.File{}
	var opened []*target
	defer func() {
		for _, t := range opened {
			t.close()
		}
	}()
	for _, f := range paths {
		t, err := p.openPlanned(f, s.dir, false)
		if err != nil {
			return fmt.Errorf("setting ACLs: %w", err)
		}
		opened = append(opened, t)
		if t.File != nil {
			files[t.Path] = t.File
		}
		argv = append(argv, t.Path)
	}
	return runSetfaclFiles(argv, files)
}

func errorsIsNotFound(err error) bool {
	_, ok := err.(*exec.Error)
	return ok || os.IsNotExist(err) || err == fs.ErrNotExist
}
