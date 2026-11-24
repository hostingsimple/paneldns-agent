package enrol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Perm is an ACL permission set: r=4, w=2, x=1.
type Perm uint16

// Permission bits.
const (
	PermR Perm = 4
	PermW Perm = 2
	PermX Perm = 1
)

func (p Perm) String() string {
	b := []byte("---")
	if p&PermR != 0 {
		b[0] = 'r'
	}
	if p&PermW != 0 {
		b[1] = 'w'
	}
	if p&PermX != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// ACL is a POSIX access or default ACL as the kernel stores it in the
// system.posix_acl_access / system.posix_acl_default xattrs.
type ACL struct {
	UserObj, GroupObj, Other Perm
	Mask                     Perm
	HasMask                  bool
	Users                    map[uint32]Perm // named users by uid
	Groups                   map[uint32]Perm // named groups by gid
}

// ACL xattr tags (linux/posix_acl_xattr.h).
const (
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
)

// ParseACLXattr decodes the value of a system.posix_acl_* xattr: a
// little-endian version (2) followed by 8-byte {tag, perm, id} entries.
func ParseACLXattr(b []byte) (*ACL, error) {
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return nil, fmt.Errorf("ACL xattr: bad length %d", len(b))
	}
	if v := binary.LittleEndian.Uint32(b); v != 2 {
		return nil, fmt.Errorf("ACL xattr: version %d, want 2", v)
	}
	a := &ACL{Users: map[uint32]Perm{}, Groups: map[uint32]Perm{}}
	for e := b[4:]; len(e) > 0; e = e[8:] {
		tag := binary.LittleEndian.Uint16(e)
		perm := Perm(binary.LittleEndian.Uint16(e[2:]) & 7)
		id := binary.LittleEndian.Uint32(e[4:])
		switch tag {
		case aclUserObj:
			a.UserObj = perm
		case aclUser:
			a.Users[id] = perm
		case aclGroupObj:
			a.GroupObj = perm
		case aclGroup:
			a.Groups[id] = perm
		case aclMask:
			a.Mask, a.HasMask = perm, true
		case aclOther:
			a.Other = perm
		default:
			return nil, fmt.Errorf("ACL xattr: unknown tag %#x", tag)
		}
	}
	return a, nil
}

// ACLReader returns a path's access and default ACL; nil means the path
// has none (only its mode bits). The default reader uses the xattrs.
type ACLReader func(path string) (access, def *ACL, err error)

// FixOptions configures FixACLs.
type FixOptions struct {
	UID  uint32                            // paneldns-agent's uid
	Stat func(string) (fs.FileInfo, error) // nil: statFunc
	Read ACLReader                         // nil: ReadACL (xattrs; Linux only)
	Run  func(argv []string) error         // nil: setfacl via exec, on the opened descriptors

	// open opens each planned path before it is read or changed. nil: as it
	// is for FixCommands (a dry run), and without following any symbolic
	// link for FixACLs (ACLPlan.openPlanned, review A-3).
	open opener
}

// FixResult counts what FixACLs did.
type FixResult struct {
	Fixed   []string // paths whose ACL was changed
	Fine    int      // paths that already gave the agent its access
	Missing int      // planned paths that no longer exist
	Errors  []error
}

// FixCommands works out, for every path in the plan, the setfacl calls
// that give the agent the access the plan grants, where it lacks it now.
// It never lowers anything: the agent's entry and the mask only gain the
// bits the agent needs, and a group-class entry that the wider mask would
// expose is narrowed to what it had in effect before, so nobody but the
// agent gains access. Key material is never granted anything, even if a
// plan named it.
//
// The one thing it removes is the agent's own access (review A-7): its
// default entry on the plan's NoDefault directories and any entry it has on
// the plan's Strip files (one inherited from a default ACL), both with
// setfacl -n so the mask is not recalculated and no other entry widens.
func FixCommands(p *ACLPlan, o FixOptions) (cmds map[string][][]string, res *FixResult) {
	if o.open == nil {
		o.open = openPlain
	}
	cmds, targets, res := fixCommands(p, o)
	for _, t := range targets {
		t.close()
	}
	return cmds, res
}

// fixCommands is FixCommands; it also returns the opened targets, which the
// commands name and the caller closes.
func fixCommands(p *ACLPlan, o FixOptions) (map[string][][]string, map[string]*target, *FixResult) {
	if o.Stat == nil {
		o.Stat = statFunc
	}
	if o.Read == nil {
		o.Read = ReadACL
	}
	res := &FixResult{}
	cmds := map[string][][]string{}
	targets := map[string]*target{}
	skipped := map[string]bool{}
	for _, s := range p.Skipped {
		skipped[s] = true
	}
	strip := map[string]bool{}
	for _, s := range p.Strip {
		strip[s] = true
	}
	noDefault := map[string]bool{}
	for _, d := range p.NoDefault {
		noDefault[d] = true
	}
	type want struct {
		need  Perm
		dir   bool // the path must be a directory
		def   bool // grant the default entry
		undef bool // remove the agent's default entry
		strip bool // remove the agent's entry
	}
	todo := map[string]want{}
	for _, f := range p.Read {
		todo[f] = want{need: PermR}
	}
	for _, d := range p.Traverse {
		todo[d] = want{need: PermX, dir: true}
	}
	for _, d := range p.Dirs {
		todo[d] = want{need: PermR | PermX, dir: true, def: !noDefault[d], undef: noDefault[d]}
	}
	for f := range strip {
		todo[f] = want{strip: true}
	}
	paths := make([]string, 0, len(todo))
	for k := range todo {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, f := range paths {
		w := todo[f]
		if (skipped[f] || IsKeyPath(f)) && !w.strip {
			continue
		}
		t, err := o.open(f, w.dir, w.strip)
		if errors.Is(err, fs.ErrNotExist) {
			res.Missing++
			continue
		}
		if err != nil {
			res.Errors = append(res.Errors, err)
			continue
		}
		hp := t.Path
		fi, err := o.Stat(hp)
		if errors.Is(err, fs.ErrNotExist) {
			t.close()
			res.Missing++
			continue
		}
		if err != nil {
			t.close()
			res.Errors = append(res.Errors, err)
			continue
		}
		access, def, err := o.Read(hp)
		if err != nil {
			t.close()
			res.Errors = append(res.Errors, fmt.Errorf("%s: reading ACL: %w", f, err))
			continue
		}
		agent := "u:" + strconv.FormatUint(uint64(o.UID), 10)
		var c [][]string
		if w.strip {
			if access != nil && hasUser(access, o.UID) {
				c = append(c, []string{"setfacl", "-n", "-x", agent, hp})
			}
		} else if spec := accessFix(fi.Mode(), access, o.UID, w.need); spec != "" {
			c = append(c, []string{"setfacl", "-m", spec, hp})
		}
		if w.def && fi.IsDir() {
			if spec := defaultFix(def, o.UID); spec != "" {
				c = append(c, []string{"setfacl", "-d", "-m", spec, hp})
			}
		}
		if w.undef && fi.IsDir() && def != nil && hasUser(def, o.UID) {
			c = append(c, []string{"setfacl", "-n", "-d", "-x", agent, hp})
		}
		if len(c) == 0 {
			t.close()
			res.Fine++
			continue
		}
		cmds[f] = c
		targets[f] = t
	}
	return cmds, targets, res
}

// FixACLs runs FixCommands' setfacl calls. Each path is opened without
// following symbolic links and must still be the object the plan saw; its
// ACL is read through, and setfacl acts on, that descriptor.
func FixACLs(p *ACLPlan, o FixOptions) *FixResult {
	if o.open == nil {
		o.open = p.openPlanned
	}
	cmds, targets, res := fixCommands(p, o)
	defer func() {
		for _, t := range targets {
			t.close()
		}
	}()
	run := o.Run
	if run == nil {
		files := map[string]*os.File{}
		for _, t := range targets {
			if t.File != nil {
				files[t.Path] = t.File
			}
		}
		run = func(argv []string) error { return runSetfaclFiles(argv, files) }
	}
	keys := make([]string, 0, len(cmds))
	for k := range cmds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, f := range keys {
		ok := true
		for _, c := range cmds[f] {
			if err := run(c); err != nil {
				res.Errors = append(res.Errors, fmt.Errorf("%s: %w", f, err))
				ok = false
				break
			}
		}
		if ok {
			res.Fixed = append(res.Fixed, f)
		}
	}
	return res
}

func hasUser(a *ACL, uid uint32) bool {
	_, ok := a.Users[uid]
	return ok
}

// accessFix returns the setfacl -m spec that gives uid the need bits on a
// path with this mode and access ACL (nil: mode bits only), or "" when it
// already has them.
func accessFix(mode fs.FileMode, a *ACL, uid uint32, need Perm) string {
	if a == nil {
		g := Perm(mode.Perm()>>3) & 7
		a = &ACL{UserObj: Perm(mode.Perm()>>6) & 7, GroupObj: g, Other: Perm(mode.Perm()) & 7, Mask: g}
	} else if !a.HasMask {
		c := *a
		c.Mask = c.GroupObj
		a = &c
	}
	return entryFix(a, uid, need, true)
}

// defaultFix returns the setfacl -d -m spec that makes new files in a
// directory inherit read for uid, or "".
func defaultFix(d *ACL, uid uint32) string {
	if d == nil {
		// No default ACL yet: as enrol does, setfacl builds one from the
		// directory's mode bits plus the agent's entry.
		return "u:" + strconv.FormatUint(uint64(uid), 10) + ":r"
	}
	if !d.HasMask {
		c := *d
		c.Mask = c.GroupObj
		d = &c
	}
	// Inheritance needs the agent's own entry: "other" bits don't count.
	return entryFix(d, uid, PermR, false)
}

// entryFix computes the entries to set on a: uid's entry with need added,
// a mask with need added (never lower than the current one), and every
// other group-class entry the wider mask would expose cut back to what
// the old mask let through. allowOther accepts the "other" bits when uid
// has no entry of its own.
func entryFix(a *ACL, uid uint32, need Perm, allowOther bool) string {
	cur, has := a.Users[uid]
	if has {
		if cur&a.Mask&need == need {
			return ""
		}
	} else if allowOther && a.Other&need == need {
		// No entry of its own: the agent gets the "other" bits.
		return ""
	}
	newMask := a.Mask | need
	widened := newMask &^ a.Mask
	ids := func(m map[uint32]Perm) []uint32 {
		out := make([]uint32, 0, len(m))
		for id := range m {
			out = append(out, id)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	id := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	entries := []string{"u:" + id(uid) + ":" + (cur | need).String()}
	if widened != 0 {
		if a.GroupObj&widened != 0 {
			entries = append(entries, "g::"+(a.GroupObj&a.Mask).String())
		}
		for _, u := range ids(a.Users) {
			if u != uid && a.Users[u]&widened != 0 {
				entries = append(entries, "u:"+id(u)+":"+(a.Users[u]&a.Mask).String())
			}
		}
		for _, g := range ids(a.Groups) {
			if a.Groups[g]&widened != 0 {
				entries = append(entries, "g:"+id(g)+":"+(a.Groups[g]&a.Mask).String())
			}
		}
	}
	entries = append(entries, "m::"+newMask.String())
	return strings.Join(entries, ",")
}

// IsKeyPath reports paths fix-acls must never touch whatever a plan says:
// the key files the unit makes inaccessible and DNSSEC private keys.
func IsKeyPath(p string) bool {
	base := path.Base(p)
	return keyPaths[p] || keyPaths[strings.TrimPrefix(p, "/var/named/chroot")] ||
		keyPaths[strings.TrimPrefix(p, "/var/named/run-root")] ||
		strings.HasSuffix(base, ".private") || base == "rndc.key" || base == "rndc.conf"
}
