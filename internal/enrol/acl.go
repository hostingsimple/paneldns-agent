package enrol

import (
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
	Dirs     []string // zone directories: u:paneldns-agent:rx plus default u:paneldns-agent:r
	Traverse []string // parent directories not searchable by others: u:paneldns-agent:x
	Skipped  []string // files deliberately left unreadable (key material)
	Warnings []string
}

// Commands returns the setfacl command lines for the plan.
func (p *ACLPlan) Commands() [][]string {
	var out [][]string
	batch := func(prefix []string, paths []string) {
		for len(paths) > 0 {
			n := min(len(paths), 200)
			out = append(out, append(append([]string{}, prefix...), paths[:n]...))
			paths = paths[n:]
		}
	}
	u := "u:" + User
	batch([]string{"setfacl", "-m", u + ":x"}, p.Traverse)
	batch([]string{"setfacl", "-m", u + ":rx"}, p.Dirs)
	batch([]string{"setfacl", "-d", "-m", u + ":r"}, p.Dirs)
	batch([]string{"setfacl", "-m", u + ":r"}, p.Read)
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
		for _, inc := range conf.Includes {
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
	}
	if cfg.OwnersFile != "" {
		if _, err := statFunc(rooted(cfg.OwnersFile)); err == nil {
			read[cfg.OwnersFile] = true
		}
	}
	// setfacl follows symbolic links: never grant through one a user
	// could have planted.
	p.Warnings = append(p.Warnings, dropUntrusted(read)...)
	p.Warnings = append(p.Warnings, dropUntrusted(dirs)...)
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
	p.Read = sortedKeys(read)
	p.Dirs = sortedKeys(dirs)
	p.Traverse = sortedKeys(traverse)
	return p, nil
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

// ApplyACLs runs the plan's setfacl commands.
func ApplyACLs(p *ACLPlan, run func(argv []string) error) error {
	if run == nil {
		run = runSetfacl
	}
	for _, c := range p.Commands() {
		if err := run(c); err != nil {
			return err
		}
	}
	return nil
}

// runSetfacl runs one setfacl command line.
func runSetfacl(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		if errorsIsNotFound(err) {
			return fmt.Errorf("setfacl not found: install the acl package (apt install acl / dnf install acl)")
		}
		cmd := strings.Join(argv, " ")
		if len(argv) > 5 {
			cmd = strings.Join(argv[:3], " ") + " ..."
		}
		return fmt.Errorf("%s: %v: %s", cmd, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func errorsIsNotFound(err error) bool {
	_, ok := err.(*exec.Error)
	return ok || os.IsNotExist(err) || err == fs.ErrNotExist
}
