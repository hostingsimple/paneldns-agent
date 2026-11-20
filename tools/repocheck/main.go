// Command repocheck enforces repository rules in CI (spec 7.11, 17):
//
//	repocheck testdata   every testdata/ directory holds documentation names
//	                     and addresses only (example.com, example.net,
//	                     192.0.2.0/24, 2001:db8::/32, plus loopback, private
//	                     reverse zones and reserved TLDs)
//	repocheck workflows  every workflow pins actions by commit SHA, declares
//	                     top-level permissions, uses no pull_request_target or
//	                     workflow_run trigger, and names no environment outside
//	                     release.yml
package main

import (
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: repocheck testdata|workflows")
		os.Exit(2)
	}
	var problems []string
	var err error
	switch os.Args[1] {
	case "testdata":
		problems, err = checkTestdata(".")
	case "workflows":
		problems, err = checkWorkflows(filepath.Join(".github", "workflows"))
	default:
		fmt.Fprintln(os.Stderr, "usage: repocheck testdata|workflows")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "repocheck:", err)
		os.Exit(2)
	}
	for _, p := range problems {
		fmt.Println(p)
	}
	if len(problems) > 0 {
		fmt.Printf("%d problem(s)\n", len(problems))
		os.Exit(1)
	}
}

// ---- testdata ---------------------------------------------------------

var (
	ipv4Re = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	nameRe = regexp.MustCompile(`(?i)(?:[a-z0-9_*-]+\.)+[a-z][a-z0-9-]*`)
)

var allowedV4 = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/32"),
}

var allowedV6 = []netip.Prefix{
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
}

// Reverse-zone address space allowed in names (system and documentation
// zones).
var allowedReverseV4 = append([]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("255.0.0.0/8"),
}, allowedV4...)

// Allowed name suffixes: the spec's documentation domains and the TLDs
// reserved by RFC 2606 and RFC 6761/6762.
var allowedSuffixes = []string{"example.com", "example.net", "example", "test", "invalid", "localhost", "localdomain", "local"}

// Generic TLDs flagged when seen; all two-letter labels are treated as
// country-code TLDs except common file extensions.
var gTLDs = strings.Fields(`com net org info biz io co xyz online site app dev cloud host hosting
email shop store tech space website name pro mobi asia tel travel jobs museum aero coop int edu
gov mil top club live blog page link news digital agency network systems services solutions
group company global world one zone uk eu`)

var notCountry = map[string]bool{"md": true, "sh": true, "py": true, "pl": true, "rs": true, "js": true, "ts": true, "db": true, "gz": true, "so": true, "go": true}

func isTLD(label string) bool {
	if len(label) == 2 {
		return !notCountry[label]
	}
	for _, t := range gTLDs {
		if label == t {
			return true
		}
	}
	return false
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// reverseAllowed checks *.in-addr.arpa and *.ip6.arpa names.
func reverseAllowed(name string) bool {
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		octets := []string{"0", "0", "0", "0"}
		for i := range labels {
			if i >= 4 {
				return false
			}
			octets[i] = labels[len(labels)-1-i]
		}
		a, err := netip.ParseAddr(strings.Join(octets, "."))
		return err == nil && inPrefixes(a, allowedReverseV4)
	case strings.HasSuffix(name, ".ip6.arpa"):
		return strings.HasSuffix(name, "8.b.d.0.1.0.0.2.ip6.arpa") ||
			name == "1."+strings.Repeat("0.", 31)+"ip6.arpa"
	}
	return false
}

func nameAllowed(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if strings.HasSuffix(name, ".arpa") {
		return reverseAllowed(name)
	}
	for _, s := range allowedSuffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	labels := strings.Split(name, ".")
	return !isTLD(labels[len(labels)-1])
}

// scanText returns the forbidden names and addresses in text.
func scanText(text string) []string {
	var bad []string
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
		// Skip runs that are part of longer dotted numbers.
		if (loc[0] > 0 && (text[loc[0]-1] == '.' || isDigit(text[loc[0]-1]))) ||
			(loc[1] < len(text) && (isDigit(text[loc[1]]) || (text[loc[1]] == '.' && loc[1]+1 < len(text) && isDigit(text[loc[1]+1])))) {
			continue
		}
		s := text[loc[0]:loc[1]]
		if a, err := netip.ParseAddr(s); err == nil && !inPrefixes(a, allowedV4) {
			bad = append(bad, "address "+s)
		}
	}
	for _, s := range ipv6Re.FindAllString(text, -1) {
		if !strings.Contains(s, "::") && strings.Count(s, ":") != 7 {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Is6() && !inPrefixes(a, allowedV6) {
			bad = append(bad, "address "+s)
		}
	}
	for _, loc := range nameRe.FindAllStringIndex(text, -1) {
		s := text[loc[0]:loc[1]]
		if loc[0] > 0 && text[loc[0]-1] == '\\' && len(s) > 1 {
			s = s[1:] // the letter of an escape such as \n in JSON text
		}
		if !nameAllowed(s) {
			bad = append(bad, "name "+s)
		}
	}
	return bad
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func checkTestdata(root string) ([]string, error) {
	var problems []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !inTestdata(p) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, bad := range scanText(string(b)) {
			if !seen[bad] {
				seen[bad] = true
				problems = append(problems, fmt.Sprintf("%s: %s is not a documentation name or address", filepath.ToSlash(p), bad))
			}
		}
		return nil
	})
	sort.Strings(problems)
	return problems, err
}

func inTestdata(p string) bool {
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == "testdata" {
			return true
		}
	}
	return false
}

// ---- workflows --------------------------------------------------------

var (
	usesRe   = regexp.MustCompile(`^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)`)
	pinnedRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$`)
	trigRe   = regexp.MustCompile(`\b(pull_request_target|workflow_run)\b`)
	envRe    = regexp.MustCompile(`^\s+environment:`)
)

func checkWorkflows(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		problems = append(problems, lintWorkflow(filepath.ToSlash(p), string(b))...)
	}
	return problems, nil
}

var (
	jobRe       = regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	imageRe     = regexp.MustCompile(`^\s*(?:image|[A-Z0-9_]+_IMAGE):\s*(\S+)`)
	secretsRe   = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)`)
	tagGuard    = "startsWith(github.ref, 'refs/tags/v')"
	signingJob  = "sign-and-publish"
	releaseFile = "/release.yml"
)

type job struct {
	name, ifExpr     string
	line             int
	hasPerms, hasEnv bool
}

// lintWorkflow checks one workflow (spec 7.10, 7.11, 17):
//   - every action is pinned by a 40-character commit SHA, and every
//     container image by digest;
//   - permissions: at the top and on every job;
//   - no pull_request_target or workflow_run trigger;
//   - only release.yml's sign-and-publish job names an environment, and only
//     it reads secrets other than GITHUB_TOKEN;
//   - release.yml runs only for v* tags: no pull_request trigger, and every
//     job is guarded by the tag check;
//   - actions/setup-go never restores a cache.
func lintWorkflow(name, text string) []string {
	var problems []string
	add := func(n int, format string, a ...any) {
		problems = append(problems, fmt.Sprintf("%s:%d: ", name, n)+fmt.Sprintf(format, a...))
	}
	isRelease := strings.HasSuffix(name, releaseFile)
	hasPerms, inJobs := false, false
	var jobs []*job
	var cur *job
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		n := i + 1
		code := line
		if j := strings.Index(code, " #"); j >= 0 {
			code = code[:j]
		}
		if strings.HasPrefix(code, "#") {
			continue
		}
		if strings.HasPrefix(code, "permissions:") {
			hasPerms = true
		}
		if strings.HasPrefix(code, "jobs:") {
			inJobs = true
			continue
		}
		if inJobs && len(code) > 0 && code[0] != ' ' {
			inJobs, cur = false, nil
		}
		if inJobs {
			if m := jobRe.FindStringSubmatch(code); m != nil {
				cur = &job{name: m[1], line: n}
				jobs = append(jobs, cur)
				continue
			}
			if cur != nil && strings.HasPrefix(code, "    ") && !strings.HasPrefix(code, "     ") {
				key := strings.TrimSpace(code)
				switch {
				case strings.HasPrefix(key, "permissions:"):
					cur.hasPerms = true
				case strings.HasPrefix(key, "environment:"):
					cur.hasEnv = true
				case strings.HasPrefix(key, "if:"):
					expr := strings.TrimSpace(strings.TrimPrefix(key, "if:"))
					// A folded (>-) expression continues on deeper lines.
					for k := i + 1; k < len(lines) && strings.HasPrefix(lines[k], "      "); k++ {
						expr += " " + strings.TrimSpace(lines[k])
					}
					cur.ifExpr = expr
				}
			}
		}
		if m := usesRe.FindStringSubmatch(code); m != nil {
			u := m[1]
			if !strings.HasPrefix(u, "./") && !strings.HasPrefix(u, "docker://") && !pinnedRe.MatchString(u) {
				add(n, "action %s is not pinned by a 40-character commit SHA", u)
			}
			if strings.HasPrefix(u, "actions/setup-go@") && !stepHas(lines, i, "cache: false") {
				add(n, "actions/setup-go must run with cache: false")
			}
		}
		if m := imageRe.FindStringSubmatch(code); m != nil && !strings.Contains(m[1], "@sha256:") {
			add(n, "image %s is not pinned by digest", m[1])
		}
		if trigRe.MatchString(code) {
			add(n, "pull_request_target and workflow_run are not allowed")
		}
		if isRelease && strings.Contains(code, "pull_request") {
			add(n, "release.yml must not run for pull requests")
		}
		for _, m := range secretsRe.FindAllStringSubmatch(code, -1) {
			if m[1] == "GITHUB_TOKEN" {
				continue
			}
			if !isRelease || cur == nil || cur.name != signingJob {
				add(n, "secrets.%s may only be read by release.yml's %s job", m[1], signingJob)
			}
		}
		if envRe.MatchString(code) && !isRelease {
			add(n, "only release.yml may name an environment")
		}
	}
	if !hasPerms {
		problems = append(problems, fmt.Sprintf("%s: no top-level permissions:", name))
	}
	for _, j := range jobs {
		if !j.hasPerms {
			add(j.line, "job %s has no permissions:", j.name)
		}
		if j.hasEnv && (!isRelease || j.name != signingJob) {
			add(j.line, "job %s names an environment; only release.yml's %s may", j.name, signingJob)
		}
		if isRelease && !strings.Contains(j.ifExpr, tagGuard) {
			add(j.line, "release.yml job %s must be guarded by if: %s", j.name, tagGuard)
		}
	}
	if isRelease {
		on := strings.Contains(text, "\non:\n  push:\n    tags:")
		if !on {
			problems = append(problems, fmt.Sprintf("%s: release.yml must trigger on push of tags", name))
		}
	}
	return problems
}

// stepHas reports whether the step starting at line i (a "- uses:" line)
// contains want before the next step or job.
func stepHas(lines []string, i int, want string) bool {
	indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
	for k := i + 1; k < len(lines); k++ {
		l := lines[k]
		t := strings.TrimLeft(l, " ")
		if t == "" {
			continue
		}
		in := len(l) - len(t)
		if in <= indent {
			return false
		}
		if strings.HasPrefix(t, want) {
			return true
		}
	}
	return false
}
