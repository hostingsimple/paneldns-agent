package enrol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
)

// ErrUntrustedSymlink means a planned path goes through a symbolic link
// that someone other than root could have made. setfacl follows symbolic
// links, so granting through it would give the agent access to whatever
// the link points at.
var ErrUntrustedSymlink = errors.New("goes through a symbolic link that a user other than root can change")

// lstatOwner returns a path's mode and owner uid without following a final
// symbolic link; replaced in tests (safepath_unix.go, safepath_other.go).
var lstatOwner = lstatOwnerOS

// readlink is replaced in tests.
var readlink = os.Readlink

// maxLinks bounds the symbolic links followed in one path (the kernel's
// limit is 40).
const maxLinks = 40

// trustedPath resolves p (a host path, under Root) one component at a
// time and returns the path it reaches. A symbolic link is followed only
// when root owns it and it sits in a directory only root can change
// (owned by root, not writable by group or others, or sticky): anything
// else could be swapped for a link to /etc/shadow or a home directory
// before enrol or fix-acls, both root, set the ACL. The target must not be
// key material.
//
// This closes planted links. The race in a directory a user can write (a
// component replaced between this check and setfacl) is closed when the ACL
// is set: openPlanned walks the result again without following any link and
// hands setfacl the descriptor (fdwalk.go).
func trustedPath(p string) (string, error) { return resolveTrusted(p, false) }

// resolveTrusted is trustedPath; allowKey lets the result be key material
// (fix-acls opening a key file only to remove the agent's entry from it).
func resolveTrusted(p string, allowKey bool) (string, error) {
	p = path.Clean(p)
	links := 0
	resolved := "/"
	rest := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, c)
		mode, uid, err := lstatOwner(rooted(next))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
			// Nothing left to follow; setfacl reports a path still missing.
			resolved = path.Join(append([]string{next}, rest...)...)
			break
		}
		if mode&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if links++; links > maxLinks {
			return "", fmt.Errorf("%s: too many symbolic links", p)
		}
		dmode, duid, err := lstatOwner(rooted(resolved))
		if err != nil {
			return "", err
		}
		if uid != 0 || duid != 0 || (dmode.Perm()&0o022 != 0 && dmode&fs.ModeSticky == 0) {
			return "", fmt.Errorf("%s: %s %w", p, next, ErrUntrustedSymlink)
		}
		target, err := readlink(rooted(next))
		if err != nil {
			return "", err
		}
		rest = append(strings.Split(target, "/"), rest...)
		if path.IsAbs(target) {
			resolved = "/"
		}
	}
	if !allowKey && IsKeyPath(resolved) {
		return "", fmt.Errorf("%s resolves to %s, which is key material", p, resolved)
	}
	return resolved, nil
}

// dropUntrusted removes from paths every one trustedPath refuses, and
// returns the refusals as warnings.
func dropUntrusted(paths map[string]bool) (warnings []string) {
	for _, p := range sortedKeys(paths) {
		if _, err := trustedPath(p); err != nil {
			delete(paths, p)
			warnings = append(warnings, fmt.Sprintf("no ACL set on %s: %v", p, err))
		}
	}
	return warnings
}
