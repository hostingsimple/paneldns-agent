package enrol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/hostingsimple/paneldns-agent/internal/syspath"
)

// The race between planning and setfacl (security review A-3). The plan
// checks every path for symbolic links a user could have planted
// (trustedPath), but setfacl runs later and follows links itself, so a user
// who can write a directory on the path could swap a component for a link
// in between. So enrol and fix-acls open each planned path from "/" one
// component at a time without following any link (O_PATH|O_NOFOLLOW,
// fdwalk_linux.go), check the object is the one the plan saw, and hand
// setfacl that descriptor as /proc/self/fd/N, which names the open object
// itself, not a path that can change.

// fileID identifies the object a planned path reached, as a walk that
// follows no symbolic link saw it.
type fileID struct {
	Dev, Ino uint64
	UID      uint32
	// Type is fs.ModeDir, 0 for a regular file, fs.ModeSymlink, or
	// fs.ModeIrregular for anything else.
	Type  fs.FileMode
	Nlink uint64
	// SharedParent: the directory holding it can be changed by a user other
	// than root (not owned by root, or writable by group or others and not
	// sticky).
	SharedParent bool
}

func (a fileID) same(b fileID) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.UID == b.UID && a.Type == b.Type
}

// errNoWalk means the platform has no O_PATH walk (development builds
// outside Linux): paths are used as they are.
var errNoWalk = errors.New("opening paths without following symbolic links is only supported on Linux")

// ErrPathChanged means a planned path no longer reaches the object the plan
// saw: someone replaced a component between the plan and setfacl.
var ErrPathChanged = errors.New("changed between working out the plan and setting the ACL")

// walkNoFollow opens host path p (absolute, as trustedPath returns it,
// rooted) one component at a time from "/" without following any symbolic
// link, and returns the descriptor and what it refers to. Replaced in tests.
var walkNoFollow = walkNoFollowOS

// target is a planned path opened for setfacl: Path is what to stat, read
// and pass to setfacl (/proc/self/fd/N on Linux, the path itself
// elsewhere), File the descriptor behind it (nil elsewhere).
type target struct {
	Path string
	File *os.File
}

func (t *target) close() {
	if t != nil && t.File != nil {
		t.File.Close()
	}
}

// opener opens a planned path for setfacl. dir: it must be a directory
// (else a regular file); removing: the ACL change only takes the agent's
// access away (fix-acls' Strip), so key material may be opened.
type opener func(f string, dir, removing bool) (*target, error)

// openPlain uses paths as they are (FixCommands' dry run, tests).
func openPlain(f string, _, _ bool) (*target, error) { return &target{Path: rooted(f)}, nil }

// openPlanned opens planned path f (a host path) without following any
// symbolic link a user could have made: it resolves f again with
// trustedPath (root's own links are followed, as when planning), walks the
// result with walkNoFollow, and refuses the object unless it has the
// expected type, is the very file or directory the plan saw (device, inode,
// owner), and, for a file in a directory others can change, has one link
// only (a hard link could name any file the user can't otherwise touch,
// where fs.protected_hardlinks is off).
func (p *ACLPlan) openPlanned(f string, dir, removing bool) (*target, error) {
	resolved, err := resolveTrusted(f, removing)
	if err != nil {
		return nil, err
	}
	file, id, err := walkNoFollow(rooted(resolved))
	if errors.Is(err, errNoWalk) {
		return &target{Path: rooted(f)}, nil
	}
	if err != nil {
		return nil, err
	}
	t := &target{Path: "/proc/self/fd/" + strconv.Itoa(int(file.Fd())), File: file}
	fail := func(format string, args ...any) (*target, error) {
		t.close()
		return nil, fmt.Errorf("%s: "+format, append([]any{f}, args...)...)
	}
	switch {
	case id.Type == fs.ModeSymlink:
		return fail("is a symbolic link now: %w", ErrPathChanged)
	case dir && id.Type != fs.ModeDir:
		return fail("is not a directory")
	case !dir && id.Type != 0:
		return fail("is not a regular file")
	}
	if want, ok := p.ids[f]; ok && !want.same(id) {
		return fail("%w", ErrPathChanged)
	}
	if !dir && !removing && id.Nlink > 1 && id.SharedParent {
		return fail("has %d hard links in a directory a user other than root can change; no ACL set", id.Nlink)
	}
	return t, nil
}

// recordIDs notes, for each path in paths, the object it reaches now, so
// openPlanned can tell later whether it was replaced. A path the walk
// can't open (it went through a link swapped in after trustedPath) is
// dropped with a warning; a missing one stays (setfacl reports it, fix-acls
// counts it as missing).
func (p *ACLPlan) recordIDs(paths map[string]bool) (warnings []string) {
	for _, f := range sortedKeys(paths) {
		resolved, err := trustedPath(f)
		if err != nil {
			continue // dropUntrusted already removed it
		}
		file, id, err := walkNoFollow(rooted(resolved))
		if errors.Is(err, errNoWalk) {
			return warnings
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			delete(paths, f)
			warnings = append(warnings, fmt.Sprintf("no ACL set on %s: %v", f, err))
			continue
		}
		file.Close()
		if p.ids == nil {
			p.ids = map[string]fileID{}
		}
		p.ids[f] = id
	}
	return warnings
}

// runSetfaclFiles runs one setfacl command line in which every argument
// that is the Path of an opened target is passed to setfacl as that
// descriptor (/proc/self/fd/3, 4, ... in the child), so setfacl acts on the
// opened object whatever happens to its path meanwhile.
func runSetfaclFiles(argv []string, files map[string]*os.File) error {
	args := make([]string, len(argv))
	copy(args, argv)
	var extra []*os.File
	for i, a := range args[1:] {
		if f, ok := files[a]; ok {
			extra = append(extra, f)
			args[i+1] = "/proc/self/fd/" + strconv.Itoa(2+len(extra))
		}
	}
	cmd, err := syspath.Command(args[0], args[1:]...)
	if err != nil {
		return fmt.Errorf("setfacl not found in %s: install the acl package (apt install acl / dnf install acl): %w", strings.Join(syspath.Dirs, ", "), err)
	}
	cmd.ExtraFiles = extra
	out, err := cmd.CombinedOutput()
	if err != nil {
		if errorsIsNotFound(err) {
			return fmt.Errorf("setfacl not found: install the acl package (apt install acl / dnf install acl)")
		}
		c := strings.Join(argv, " ")
		if len(argv) > 5 {
			c = strings.Join(argv[:3], " ") + " ..."
		}
		return fmt.Errorf("%s: %v: %s", c, err, strings.TrimSpace(string(out)))
	}
	return nil
}
