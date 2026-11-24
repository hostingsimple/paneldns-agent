// Package syspath finds the system programs the agent runs (named,
// named-compilezone, setfacl, systemctl) in a fixed list of system
// directories, never through $PATH (security review A-13): enrol and
// fix-acls run as root, and a PATH a caller set, or a directory early in
// it that someone else can write, must not decide which binary runs.
package syspath

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
)

// Dirs are searched in order. /usr/local comes last: some BIND builds
// install there.
var Dirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// ownerOK reports whether a found file (or its directory) may be run: on
// Unix owned by root and not writable by group or others (syspath_unix.go).
// Replaced in tests.
var ownerOK = ownerOKOS

// Find returns the absolute path of program name from Dirs: the first
// regular, executable file that root owns and only root can change, in a
// directory only root can change. Not found is an *exec.Error wrapping
// exec.ErrNotFound, as exec.LookPath returns.
func Find(name string) (string, error) {
	if name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("syspath: %q is not a program name", name)
	}
	var refused []string
	for _, d := range Dirs {
		p := path.Join(d, name)
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0) {
			continue
		}
		di, err := os.Stat(d)
		if err != nil {
			continue
		}
		if !ownerOK(fi) || !ownerOK(di) {
			refused = append(refused, p)
			continue
		}
		return p, nil
	}
	err := exec.ErrNotFound
	if len(refused) > 0 {
		err = fmt.Errorf("%w (refused, not owned by root or writable by others: %s)", exec.ErrNotFound, strings.Join(refused, ", "))
	}
	return "", &exec.Error{Name: name, Err: err}
}

// Command is exec.Command with the program found by Find.
func Command(name string, args ...string) (*exec.Cmd, error) {
	p, err := Find(name)
	if err != nil {
		return nil, err
	}
	return exec.Command(p, args...), nil
}

// CommandContext is exec.CommandContext with the program found by Find.
func CommandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	p, err := Find(name)
	if err != nil {
		return nil, err
	}
	return exec.CommandContext(ctx, p, args...), nil
}

// IsNotFound reports whether err says a program was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}
