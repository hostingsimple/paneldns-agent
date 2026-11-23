package enrol

import (
	"encoding/binary"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

const agentUID = 990

// xattr builds a system.posix_acl_* value.
func xattr(entries ...[3]uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, uint16(e[0]))
		b = binary.LittleEndian.AppendUint16(b, uint16(e[1]))
		b = binary.LittleEndian.AppendUint32(b, e[2])
	}
	return b
}

func TestParseACLXattr(t *testing.T) {
	const none = 0xffffffff
	// getfacl: user::rw- user:990:r-- group::r-x mask::--- other::---
	a, err := ParseACLXattr(xattr(
		[3]uint32{aclUserObj, 6, none}, [3]uint32{aclUser, 4, agentUID}, [3]uint32{aclGroupObj, 5, none},
		[3]uint32{aclGroup, 6, 25}, [3]uint32{aclMask, 0, none}, [3]uint32{aclOther, 0, none}))
	if err != nil {
		t.Fatal(err)
	}
	want := &ACL{UserObj: 6, GroupObj: 5, Mask: 0, HasMask: true, Users: map[uint32]Perm{agentUID: 4}, Groups: map[uint32]Perm{25: 6}}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("got %+v", a)
	}
	for _, bad := range [][]byte{nil, {2, 0, 0}, append(binary.LittleEndian.AppendUint32(nil, 1), make([]byte, 8)...), xattr([3]uint32{0x40, 4, none}), append(xattr(), 1)} {
		if _, err := ParseACLXattr(bad); err == nil {
			t.Errorf("%x accepted", bad)
		}
	}
	if s := (PermR | PermX).String(); s != "r-x" {
		t.Fatal(s)
	}
}

type fakeFS map[string]struct {
	mode        fs.FileMode
	access, def *ACL
}

func (f fakeFS) stat(p string) (fs.FileInfo, error) {
	e, ok := f[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return modeFI{e.mode}, nil
}

func (f fakeFS) read(p string) (*ACL, *ACL, error) {
	e := f[p]
	return e.access, e.def, nil
}

func TestFixCommands(t *testing.T) {
	const dir = fs.ModeDir
	tests := []struct {
		name     string
		kind     string // read, dir, traverse
		mode     fs.FileMode
		access   *ACL
		def      *ACL
		want     []string // setfacl argv without the path
		wantFine int
	}{
		{name: "new 0600 file: inherited entry masked to ---", kind: "read", mode: 0o600,
			// What cPanel's new zone files look like: the default ACL gave
			// user:paneldns-agent:r and group::r-x, mode 0600 made the mask ---.
			access: &ACL{UserObj: 6, GroupObj: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 4}},
			// The mask gains r for the agent; group:: is cut to what the
			// old mask let through, so named's group gains nothing.
			want: []string{"setfacl -m u:990:r--,g::---,m::r--"}},
		{name: "new 0600 file without any ACL", kind: "read", mode: 0o600,
			want: []string{"setfacl -m u:990:r--,m::r--"}},
		{name: "0640 file with the ACL in place: no-op", kind: "read", mode: 0o640,
			access: &ACL{UserObj: 6, GroupObj: 4, Mask: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4}}, wantFine: 1},
		{name: "0660 file keeps group write", kind: "read", mode: 0o660,
			want: []string{"setfacl -m u:990:r--,m::rw-"}},
		{name: "0660 file with an ACL but no agent entry keeps group write", kind: "read", mode: 0o660,
			access: &ACL{UserObj: 6, GroupObj: 6, Mask: 6, HasMask: true, Users: map[uint32]Perm{}},
			want:   []string{"setfacl -m u:990:r--,m::rw-"}},
		{name: "replaced 0644 file: other bits suffice", kind: "read", mode: 0o644, wantFine: 1},
		{name: "agent entry without read", kind: "read", mode: 0o640,
			access: &ACL{UserObj: 6, GroupObj: 4, Mask: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 0}},
			want:   []string{"setfacl -m u:990:r--,m::r--"}},
		{name: "other entries are not widened by the new mask", kind: "read", mode: 0o600,
			access: &ACL{UserObj: 6, GroupObj: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4, 1000: 7}, Groups: map[uint32]Perm{50: 6, 51: 2}},
			want:   []string{"setfacl -m u:990:r--,g::---,u:1000:---,g:50:---,m::r--"}},
		{name: "zone dir without ACLs gets rx and the default", kind: "dir", mode: dir | 0o750,
			want: []string{"setfacl -m u:990:r-x,m::r-x", "setfacl -d -m u:990:r"}},
		{name: "zone dir with a masked default entry", kind: "dir", mode: dir | 0o750,
			access: &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 5}},
			def:    &ACL{UserObj: 7, GroupObj: 5, Mask: 0, HasMask: true, Users: map[uint32]Perm{agentUID: 4}},
			want:   []string{"setfacl -d -m u:990:r--,g::---,m::r--"}},
		{name: "zone dir whose default lacks the agent", kind: "dir", mode: dir | 0o755,
			access: &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 5}},
			// 0755 gives the agent rx through "other", but inheritance
			// needs its own default entry.
			def:  &ACL{UserObj: 7, GroupObj: 5, Other: 5, Users: map[uint32]Perm{}},
			want: []string{"setfacl -d -m u:990:r--,m::r-x"}},
		{name: "zone dir already fine", kind: "dir", mode: dir | 0o750,
			access: &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 5}},
			def:    &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 4}}, wantFine: 1},
		{name: "parent dir gets x only", kind: "traverse", mode: dir | 0o700,
			want: []string{"setfacl -m u:990:--x,m::--x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const p = "/var/named/x"
			plan := &ACLPlan{}
			switch tt.kind {
			case "read":
				plan.Read = []string{p}
			case "dir":
				plan.Dirs = []string{p}
			case "traverse":
				plan.Traverse = []string{p}
			}
			f := fakeFS{p: {tt.mode, tt.access, tt.def}}
			cmds, res := FixCommands(plan, FixOptions{UID: agentUID, Stat: f.stat, Read: f.read})
			var got []string
			for _, c := range cmds[p] {
				if c[len(c)-1] != p {
					t.Fatalf("command not on %s: %q", p, c)
				}
				got = append(got, strings.Join(c[:len(c)-1], " "))
			}
			if !reflect.DeepEqual(got, tt.want) || res.Fine != tt.wantFine || len(res.Errors) != 0 {
				t.Fatalf("got %q fine %d errors %v; want %q fine %d", got, res.Fine, res.Errors, tt.want, tt.wantFine)
			}
		})
	}
}

func TestFixNeverTouchesKeyFiles(t *testing.T) {
	plan := &ACLPlan{
		// A plan that wrongly names key files must still leave them alone.
		Read: []string{"/etc/named.conf", "/etc/rndc.key", "/var/named/Kexample.com.+013+12345.private",
			"/var/named/chroot/etc/rndc.key", "/var/named/example.com.db"},
		Dirs:    []string{"/var/named"},
		Skipped: []string{"/etc/named.keys.conf"},
	}
	plan.Read = append(plan.Read, "/etc/named.keys.conf")
	f := fakeFS{}
	for _, p := range append(append([]string{}, plan.Read...), plan.Dirs...) {
		m := fs.FileMode(0o600)
		if p == "/var/named" {
			m = fs.ModeDir | 0o750
		}
		f[p] = struct {
			mode        fs.FileMode
			access, def *ACL
		}{mode: m}
	}
	var ran [][]string
	res := FixACLs(plan, FixOptions{UID: agentUID, Stat: f.stat, Read: f.read, Run: func(a []string) error { ran = append(ran, a); return nil }})
	touched := map[string]bool{}
	for _, c := range ran {
		touched[c[len(c)-1]] = true
	}
	want := map[string]bool{"/etc/named.conf": true, "/var/named/example.com.db": true, "/var/named": true}
	if !reflect.DeepEqual(touched, want) {
		t.Fatalf("touched %v", touched)
	}
	if !reflect.DeepEqual(res.Fixed, []string{"/etc/named.conf", "/var/named", "/var/named/example.com.db"}) {
		t.Fatalf("fixed %v", res.Fixed)
	}
}

func TestFixACLsErrorsAndMissing(t *testing.T) {
	plan := &ACLPlan{Read: []string{"/var/named/a.db", "/var/named/b.db", "/var/named/gone.db"}}
	f := fakeFS{"/var/named/a.db": {mode: 0o600}, "/var/named/b.db": {mode: 0o600}}
	res := FixACLs(plan, FixOptions{UID: agentUID, Stat: f.stat, Read: f.read, Run: func(a []string) error {
		if a[len(a)-1] == "/var/named/a.db" {
			return errors.New("setfacl: Read-only file system")
		}
		return nil
	}})
	if !reflect.DeepEqual(res.Fixed, []string{"/var/named/b.db"}) || len(res.Errors) != 1 || res.Missing != 1 {
		t.Fatalf("%+v", res)
	}
	readErr := FixACLs(plan, FixOptions{UID: agentUID, Stat: f.stat, Read: func(string) (*ACL, *ACL, error) {
		return nil, nil, errors.New("boom")
	}, Run: func([]string) error { t.Fatal("ran setfacl after a read error"); return nil }})
	if len(readErr.Errors) != 2 || !strings.Contains(readErr.Errors[0].Error(), "reading ACL") {
		t.Fatalf("%+v", readErr)
	}
}

// Review A-7: fix-acls never grants the default ACL on a NoDefault
// directory and removes the agent's own default entry an older version
// left there; it removes the agent's entry from Strip files and grants
// them nothing, even when a plan also names them for reading.
func TestFixCommandsKeyDirectories(t *testing.T) {
	const dir = fs.ModeDir
	dirOK := &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 5}}
	tests := []struct {
		name     string
		kind     string // nodefault, strip, strip+read
		mode     fs.FileMode
		access   *ACL
		def      *ACL
		want     []string
		wantFine int
	}{
		{name: "old agent default entry removed", kind: "nodefault", mode: dir | 0o750, access: dirOK,
			def:  &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{agentUID: 4, 1000: 4}},
			want: []string{"setfacl -n -d -x u:990"}},
		{name: "no default ACL: rx only, none added", kind: "nodefault", mode: dir | 0o750,
			want: []string{"setfacl -m u:990:r-x,m::r-x"}},
		{name: "default ACL of others left alone", kind: "nodefault", mode: dir | 0o750, access: dirOK,
			def: &ACL{UserObj: 7, GroupObj: 5, Mask: 5, HasMask: true, Users: map[uint32]Perm{1000: 4}}, wantFine: 1},
		{name: "inherited entry on a key file removed", kind: "strip", mode: 0o640,
			access: &ACL{UserObj: 6, GroupObj: 4, Mask: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4}},
			want:   []string{"setfacl -n -x u:990"}},
		{name: "masked inherited entry removed too", kind: "strip", mode: 0o600,
			access: &ACL{UserObj: 6, GroupObj: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4}},
			want:   []string{"setfacl -n -x u:990"}},
		{name: "key file without an agent entry: nothing granted", kind: "strip", mode: 0o600, wantFine: 1},
		{name: "key file a plan also names for reading: stripped, not granted", kind: "strip+read", mode: 0o640,
			access: &ACL{UserObj: 6, GroupObj: 4, Mask: 4, HasMask: true, Users: map[uint32]Perm{agentUID: 4}},
			want:   []string{"setfacl -n -x u:990"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const p = "/etc/bind/x"
			plan := &ACLPlan{}
			switch tt.kind {
			case "nodefault":
				plan.Dirs, plan.NoDefault = []string{p}, []string{p}
			case "strip":
				plan.Strip = []string{p}
			case "strip+read":
				plan.Strip, plan.Read = []string{p}, []string{p}
			}
			f := fakeFS{p: {tt.mode, tt.access, tt.def}}
			cmds, res := FixCommands(plan, FixOptions{UID: agentUID, Stat: f.stat, Read: f.read})
			var got []string
			for _, c := range cmds[p] {
				if c[len(c)-1] != p {
					t.Fatalf("command not on %s: %q", p, c)
				}
				got = append(got, strings.Join(c[:len(c)-1], " "))
			}
			if !reflect.DeepEqual(got, tt.want) || res.Fine != tt.wantFine || len(res.Errors) != 0 {
				t.Fatalf("got %q fine %d errors %v; want %q fine %d", got, res.Fine, res.Errors, tt.want, tt.wantFine)
			}
		})
	}
}
