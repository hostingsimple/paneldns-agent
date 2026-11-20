package source

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hostingsimple/paneldns-agent/internal/namedconf"
	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// MaxCompiledSize caps named-compilezone output for one zone.
const MaxCompiledSize = 16 << 20

// CompileTimeout bounds one named-compilezone run.
const CompileTimeout = 2 * time.Minute

// BIND reads zones through named.conf and named-compilezone.
type BIND struct {
	ConfFile string // ZONES_FILE, host path
	Chroot   string // CHROOT
	View     string // VIEW

	// Compilezone is the named-compilezone path; "" looks it up. Set
	// NoCompilezone to use the built-in parser only.
	Compilezone   string
	NoCompilezone bool

	// Seams for tests; nil means the real OS.
	ReadFile func(string) ([]byte, error)
	Stat     func(string) (fs.FileInfo, error)
	Glob     func(string) ([]string, error)
	Run      func(ctx context.Context, argv []string) (stdout, stderr []byte, err error)
	Alive    func(pid int) Running
	// Units and UnitActive replace the systemd fallback of Running.
	Units      []string
	UnitActive func(ctx context.Context, unit string) (bool, error)

	mu       sync.Mutex
	conf     *namedconf.Conf
	zones    map[string]namedconf.Zone // by zone file path (ZoneRef.key)
	incCache map[string]incEntry
	sem      chan struct{}
}

type incEntry struct {
	stamp    string
	includes []string
}

// Kind implements Source.
func (b *BIND) Kind() string { return "bind" }

func (b *BIND) readFile(p string) ([]byte, error) {
	if b.ReadFile != nil {
		return b.ReadFile(p)
	}
	return os.ReadFile(p)
}

func (b *BIND) stat(p string) (fs.FileInfo, error) {
	if b.Stat != nil {
		return b.Stat(p)
	}
	return os.Stat(p)
}

// List implements Source.
func (b *BIND) List(ctx context.Context) (*Listing, error) {
	l := &namedconf.Loader{ReadFile: b.readFile, Glob: b.Glob, Chroot: b.Chroot}
	if l.Glob == nil {
		l.Glob = filepath.Glob
	}
	conf, err := namedconf.Read(l, b.ConfFile, b.View)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", b.ConfFile, err)
	}
	out := &Listing{
		Backend: "bind", View: conf.View, Directory: conf.Directory,
		Skipped: conf.Skipped, Other: conf.OtherViews,
	}
	for _, inc := range conf.Includes {
		if !inc.Readable {
			out.Unreadable = append(out.Unreadable, inc.Path)
			if !inc.Denied {
				out.Warnings = append(out.Warnings, fmt.Sprintf("include %s (from %s:%d) not read: %s", inc.Path, inc.From, inc.Line, inc.Err))
			}
		}
	}
	zones := map[string]namedconf.Zone{}
	seen := map[string]bool{}
	b.mu.Lock()
	if b.incCache == nil {
		b.incCache = map[string]incEntry{}
	}
	b.mu.Unlock()
	for _, z := range conf.Zones {
		if seen[z.Name] {
			out.Warnings = append(out.Warnings, fmt.Sprintf("zone %s declared twice; using the first", z.Name))
			continue
		}
		seen[z.Name] = true
		zones[z.File] = z
		out.Zones = append(out.Zones, ZoneRef{
			Name: z.Name, Fingerprint: b.fingerprint(conf, z),
			DeclaredIn: z.DeclaredIn, key: z.File,
		})
	}
	b.mu.Lock()
	b.conf, b.zones = conf, zones
	b.mu.Unlock()
	return out, nil
}

func stamp(fi fs.FileInfo, err error) string {
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "-"
		}
		return "err"
	}
	return strconv.FormatInt(fi.Size(), 10) + "@" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
}

var includeLine = regexp.MustCompile(`(?im)^\$INCLUDE[ \t]+("[^"]+"|\S+)`)

// fingerprint is the zone file's size and mtime, the journal's, the
// options that change named-compilezone's output, and the stamps of the
// files the zone $INCLUDEs (found by a cheap scan when the zone file
// changes).
func (b *BIND) fingerprint(conf *namedconf.Conf, z namedconf.Zone) string {
	zs := stamp(b.stat(z.File))
	js := stamp(b.stat(z.Journal))
	parts := []string{"f=" + zs, "j=" + js, "k=" + z.CheckNames, "i=" + z.Integrity, "F=" + z.Format}
	b.mu.Lock()
	ent, ok := b.incCache[z.File]
	b.mu.Unlock()
	if !ok || ent.stamp != zs {
		ent = incEntry{stamp: zs}
		if z.Format == "text" {
			if data, err := b.readFile(z.File); err == nil {
				for _, m := range includeLine.FindAllSubmatch(data, -1) {
					p := strings.Trim(string(m[1]), `"`)
					if !path.IsAbs(p) {
						p = path.Join(conf.Directory, p)
					} else if b.Chroot != "" {
						p = path.Join(b.Chroot, p)
					}
					ent.includes = append(ent.includes, p)
				}
			}
		}
		b.mu.Lock()
		b.incCache[z.File] = ent
		b.mu.Unlock()
	}
	for _, p := range ent.includes {
		parts = append(parts, "inc="+stamp(b.stat(p)))
	}
	return strings.Join(parts, ";")
}

func (b *BIND) lookup(ref ZoneRef) (namedconf.Zone, *namedconf.Conf, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	z, ok := b.zones[ref.key]
	if !ok || z.Name != ref.Name {
		return namedconf.Zone{}, nil, fmt.Errorf("zone %s is not in the last listing", ref.Name)
	}
	return z, b.conf, nil
}

// CompilezonePath returns the named-compilezone in use, or "".
func (b *BIND) CompilezonePath() string {
	if b.NoCompilezone {
		return ""
	}
	if b.Compilezone != "" {
		return b.Compilezone
	}
	if p, err := exec.LookPath("named-compilezone"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/named-compilezone", "/usr/bin/named-compilezone", "/usr/local/sbin/named-compilezone", "/usr/local/bin/named-compilezone"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// CompileArgs returns the named-compilezone command line for z (spec 7.3).
// The chroot is applied to the paths instead of passing -t, because -t
// needs root (docs/DECISIONS.md D-05).
func CompileArgs(bin string, conf *namedconf.Conf, z namedconf.Zone) []string {
	args := []string{bin, "-w", conf.Directory, "-j"}
	if z.Journal != z.File+".jnl" {
		args = append(args, "-J", z.Journal)
	}
	args = append(args,
		"-k", z.CheckNames,
		"-i", z.Integrity,
		"-f", z.Format,
		"-F", "text",
		"-s", "full",
		"-o", "-",
		z.Name, z.File,
	)
	return args
}

// Read implements Source.
func (b *BIND) Read(ctx context.Context, ref ZoneRef) ([]zonefile.RR, error) {
	z, conf, err := b.lookup(ref)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.sem == nil {
		b.sem = make(chan struct{}, 2) // spec 7.8: at most two at a time
	}
	sem := b.sem
	b.mu.Unlock()
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-sem }()

	origin := z.Name
	if bin := b.CompilezonePath(); bin != "" {
		out, err := b.compile(ctx, CompileArgs(bin, conf, z))
		if err != nil {
			return nil, err
		}
		return zonefile.Parse(FilterCompileOutput(out), zonefile.Options{Origin: origin, File: z.Name + " (named-compilezone)"})
	}
	// Built-in parser: no journal, text format only.
	if z.Format != "text" {
		return nil, fmt.Errorf("zone %s is in %s format; install named-compilezone to read it", z.Name, z.Format)
	}
	if _, err := b.stat(z.Journal); err == nil {
		return nil, fmt.Errorf("zone %s has a journal (%s); install named-compilezone to apply it", z.Name, z.Journal)
	}
	data, err := b.readFile(z.File)
	if err != nil {
		return nil, err
	}
	return zonefile.Parse(data, zonefile.Options{
		Origin: origin, File: z.File, IncludeDir: conf.Directory,
		IncludeRoot: b.Chroot, ReadFile: b.readFile,
	})
}

func (b *BIND) compile(ctx context.Context, argv []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, CompileTimeout)
	defer cancel()
	run := b.Run
	if run == nil {
		run = runCapped
	}
	stdout, stderr, err := run(ctx, argv)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(lastLines(stdout, 5)))
		}
		if len(msg) > 2000 {
			msg = msg[:2000] + "…"
		}
		return nil, fmt.Errorf("named-compilezone failed: %v: %s", err, msg)
	}
	return stdout, nil
}

func lastLines(b []byte, n int) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, []byte("\n"))
}

// capped is a bounded buffer.
type capped struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		c.over = true
		return 0, errors.New("output too large")
	}
	return c.buf.Write(p)
}

func runCapped(ctx context.Context, argv []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	out := &capped{limit: MaxCompiledSize}
	errb := &capped{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()
	if out.over {
		return nil, errb.buf.Bytes(), fmt.Errorf("zone larger than %d bytes", MaxCompiledSize)
	}
	return out.buf.Bytes(), errb.buf.Bytes(), err
}

// FilterCompileOutput drops the status lines some named-compilezone
// versions print on stdout next to the zone ("zone x/IN: loaded serial
// N", "dump zone to - ...", "OK").
func FilterCompileOutput(b []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), MaxCompiledSize)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if t == "OK" || (strings.HasPrefix(t, "zone ") && strings.Contains(t, ": loaded serial")) ||
			strings.HasPrefix(t, "dump zone to ") {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

// pidFiles lists where named's pid file usually is.
var pidFiles = []string{"/run/named/named.pid", "/var/run/named/named.pid", "/run/named.pid", "/var/run/named.pid", "/var/run/named/named.pid"}

// Running implements Source: named's pid file names a live process.
func (b *BIND) Running(ctx context.Context) (Running, string) {
	b.mu.Lock()
	conf := b.conf
	b.mu.Unlock()
	cands := []string{}
	if conf != nil && conf.PidFile != "" {
		cands = append(cands, conf.PidFile)
	}
	for _, p := range pidFiles {
		if b.Chroot != "" {
			cands = append(cands, path.Join(b.Chroot, p))
		}
		cands = append(cands, p)
	}
	alive := b.Alive
	if alive == nil {
		alive = processAlive
	}
	for _, p := range cands {
		data, err := b.readFile(p)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		r := alive(pid)
		return r, fmt.Sprintf("pid %d from %s", pid, p)
	}
	// The pid file's directory is often readable by named only; ask
	// systemd instead (read-only D-Bus query, no privilege needed).
	units := b.Units
	if units == nil {
		units = []string{"named.service", "named-chroot.service", "bind9.service"}
	}
	query := b.UnitActive
	if query == nil {
		query = systemdActive
	}
	for _, u := range units {
		if active, err := query(ctx, u); err == nil && active {
			return RunningYes, "systemd unit " + u + " is active"
		}
	}
	return RunningUnknown, "no readable named pid file and no active named unit"
}

// systemdActive runs `systemctl is-active --quiet unit`.
func systemdActive(ctx context.Context, unit string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return false, nil
	}
	return false, err
}

// ZoneFile returns the zone file of a zone listed by this source.
func (b *BIND) ZoneFile(ref ZoneRef) string { return ref.key }
