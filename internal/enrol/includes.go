package enrol

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// includeRe matches a $INCLUDE directive at the start of a line, with the
// file name quoted or bare. A following origin is ignored here.
var includeRe = regexp.MustCompile(`(?i)^\$INCLUDE[ \t]+("[^"]*"|[^ \t;]+)`)

// secretRe recognises key material: a named.conf-style key statement or
// secret, or a dnssec-keygen private key file.
var secretRe = regexp.MustCompile(`(?mi)^\s*(key|tsig-keygen)\s+"?[^\s"{]+"?\s*\{|\bsecret\s+"|^Private-key-format:`)

// keyPaths are files the unit makes inaccessible (spec 7.9); an
// $INCLUDE of one of them is refused outright.
var keyPaths = map[string]bool{
	"/etc/rndc.key": true, "/etc/bind/rndc.key": true, "/etc/named/rndc.key": true,
	"/etc/rndc.conf": true, "/etc/bind/rndc.conf": true,
	"/etc/powerdns/pdns.conf": true, "/etc/pdns/pdns.conf": true,
}

// ErrIncludeRefused means a zone file $INCLUDEs a file the agent must not
// be given access to.
var ErrIncludeRefused = errors.New("$INCLUDE refused")

// zoneIncludes follows $INCLUDE in a zone file, recursively up to
// zonefile.MaxIncludeDepth, and returns every included file (host paths).
// Relative names resolve against named's directory, as named and
// named-compilezone -w do; absolute ones get the chroot prefix. An include
// outside named's directory and the zone directories, or at key material,
// is refused; one that can't be read even as root is a warning (the zone
// then fails to read and is reported, but enrolment goes on).
func zoneIncludes(zoneFile, directory, chroot string, allowed []string) (files, warnings []string, err error) {
	seen := map[string]bool{zoneFile: true}
	var walk func(file string, depth int) error
	walk = func(file string, depth int) error {
		data, err := readRooted(file)
		if err != nil {
			if file != zoneFile {
				warnings = append(warnings, fmt.Sprintf("%s: %v (the zone will fail to read until this is fixed)", file, err))
			}
			return nil
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for n := 1; sc.Scan(); n++ {
			m := includeRe.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			name := strings.Trim(m[1], `"`)
			target := name
			if !path.IsAbs(target) {
				target = path.Join(directory, target)
			} else if chroot != "" {
				target = path.Join(chroot, target)
			}
			target = path.Clean(target)
			where := fmt.Sprintf("%s:%d: $INCLUDE %s", file, n, name)
			if depth+1 > zonefile.MaxIncludeDepth {
				return fmt.Errorf("%w: %s: nested deeper than %d", ErrIncludeRefused, where, zonefile.MaxIncludeDepth)
			}
			if !under(target, allowed) {
				return fmt.Errorf("%w: %s resolves to %s, outside named's directory and the zone directories (%s); move the file there", ErrIncludeRefused, where, target, strings.Join(dedupe(allowed), ", "))
			}
			if keyPaths[strings.TrimPrefix(target, chroot)] || strings.HasSuffix(target, ".private") {
				return fmt.Errorf("%w: %s is key material, which the agent must never read", ErrIncludeRefused, where)
			}
			if seen[target] {
				continue
			}
			seen[target] = true
			b, err := readRooted(target)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
					warnings = append(warnings, fmt.Sprintf("%s: %v (the zone will fail to read until this is fixed)", where, err))
					continue
				}
				return err
			}
			if secretRe.Match(b) {
				return fmt.Errorf("%w: %s (%s) holds key material (a key statement, secret or private key), which the agent must never read", ErrIncludeRefused, where, target)
			}
			files = append(files, target)
			if err := walk(target, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	err = walk(zoneFile, 0)
	return files, warnings, err
}

// under reports whether p is one of roots or inside one.
func under(p string, roots []string) bool {
	for _, r := range roots {
		r = path.Clean(r)
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		v = path.Clean(v)
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
