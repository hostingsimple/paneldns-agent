package enrol

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWalk replaces walkNoFollow: host paths (Root removed) in objs open a
// real temporary file (so the descriptor is genuine) and report the given
// id; anything else is missing.
func fakeWalk(t *testing.T, objs map[string]*fileID) {
	t.Helper()
	old := walkNoFollow
	tmp := filepath.Join(t.TempDir(), "obj")
	if err := os.WriteFile(tmp, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	walkNoFollow = func(p string) (*os.File, fileID, error) {
		id, ok := objs[strings.TrimPrefix(filepath.ToSlash(p), Root)]
		if !ok {
			return nil, fileID{}, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		if id == nil {
			return nil, fileID{}, errors.New(p + ": /x is a symbolic link or not a directory: " + ErrPathChanged.Error())
		}
		f, err := os.Open(tmp)
		if err != nil {
			t.Fatal(err)
		}
		return f, *id, nil
	}
	t.Cleanup(func() { walkNoFollow = old })
}

// The race of review A-3: what the plan saw is what setfacl gets, or
// nothing.
func TestOpenPlannedRefusesWhatChanged(t *testing.T) {
	withRoot(t, map[string]string{"/var/named/a.db": "", "/var/named/b.db": "", "/var/named/k.private": ""})
	zone := &fileID{Dev: 1, Ino: 10, UID: 0, Nlink: 1}
	dir := &fileID{Dev: 1, Ino: 2, UID: 0, Type: fs.ModeDir}
	objs := map[string]*fileID{"/var/named/a.db": zone, "/var/named": dir, "/var/named/b.db": {Dev: 1, Ino: 11, Nlink: 1}}
	fakeWalk(t, objs)
	p := &ACLPlan{Read: []string{"/var/named/a.db", "/var/named/b.db"}, Dirs: []string{"/var/named"}}
	read := map[string]bool{"/var/named/a.db": true, "/var/named/b.db": true}
	if w := p.recordIDs(read); len(w) != 0 {
		t.Fatalf("warnings %v", w)
	}
	p.recordIDs(map[string]bool{"/var/named": true})
	if len(p.ids) != 3 {
		t.Fatalf("ids %v", p.ids)
	}
	open := func(f string, isDir, removing bool) error {
		tg, err := p.openPlanned(f, isDir, removing)
		if err == nil {
			if tg.File == nil || !strings.HasPrefix(tg.Path, "/proc/self/fd/") {
				t.Errorf("%s: target %+v", f, tg)
			}
			tg.close()
		}
		return err
	}
	if err := open("/var/named/a.db", false, false); err != nil {
		t.Fatalf("unchanged file refused: %v", err)
	}
	if err := open("/var/named", true, false); err != nil {
		t.Fatalf("unchanged directory refused: %v", err)
	}

	// Swapped for another file (same name, new inode).
	objs["/var/named/a.db"] = &fileID{Dev: 1, Ino: 99, UID: 0, Nlink: 1}
	if err := open("/var/named/a.db", false, false); !errors.Is(err, ErrPathChanged) {
		t.Errorf("replaced file: %v", err)
	}
	// A component became a symbolic link.
	objs["/var/named/a.db"] = nil
	if err := open("/var/named/a.db", false, false); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("link in the path: %v", err)
	}
	// The last component is a link now.
	objs["/var/named/a.db"] = &fileID{Dev: 1, Ino: 10, Type: fs.ModeSymlink}
	if err := open("/var/named/a.db", false, false); !errors.Is(err, ErrPathChanged) {
		t.Errorf("last component a link: %v", err)
	}
	// Same inode, new owner (chowned in between).
	objs["/var/named/a.db"] = &fileID{Dev: 1, Ino: 10, UID: 1001, Nlink: 1}
	if err := open("/var/named/a.db", false, false); !errors.Is(err, ErrPathChanged) {
		t.Errorf("new owner: %v", err)
	}
	// Wrong type.
	objs["/var/named"] = &fileID{Dev: 1, Ino: 2}
	if err := open("/var/named", true, false); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("directory turned file: %v", err)
	}
	// Gone: reported as missing.
	delete(objs, "/var/named/a.db")
	if err := open("/var/named/a.db", false, false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

func TestOpenPlannedHardLinks(t *testing.T) {
	withRoot(t, map[string]string{"/var/named/a.db": "", "/srv/a.db": "", "/var/named/k.private": ""})
	objs := map[string]*fileID{
		"/var/named/a.db":      {Ino: 1, Nlink: 2, SharedParent: true},
		"/srv/a.db":            {Ino: 2, Nlink: 2},
		"/var/named/k.private": {Ino: 3, Nlink: 2, SharedParent: true},
	}
	fakeWalk(t, objs)
	p := &ACLPlan{}
	if _, err := p.openPlanned("/var/named/a.db", false, false); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("hard link in a shared directory: %v", err)
	}
	// In a directory only root can change, a second link is root's doing.
	if tg, err := p.openPlanned("/srv/a.db", false, false); err != nil {
		t.Errorf("hard link in a root-only directory: %v", err)
	} else {
		tg.close()
	}
	// Taking the agent's entry away is always safe, and key files may be
	// opened for that only.
	if tg, err := p.openPlanned("/var/named/k.private", false, true); err != nil {
		t.Errorf("strip: %v", err)
	} else {
		tg.close()
	}
	if _, err := p.openPlanned("/var/named/k.private", false, false); err == nil || !strings.Contains(err.Error(), "key material") {
		t.Errorf("grant on a key: %v", err)
	}
}

func TestRecordIDsDropsPathsThatTurnedIntoLinks(t *testing.T) {
	withRoot(t, map[string]string{"/var/named/a.db": "", "/var/named/b.db": ""})
	fakeWalk(t, map[string]*fileID{"/var/named/a.db": {Ino: 1, Nlink: 1}, "/var/named/b.db": nil})
	p := &ACLPlan{}
	paths := map[string]bool{"/var/named/a.db": true, "/var/named/b.db": true, "/var/named/new.db": true}
	w := p.recordIDs(paths)
	if len(w) != 1 || !strings.Contains(w[0], "/var/named/b.db") || paths["/var/named/b.db"] {
		t.Fatalf("warnings %v paths %v", w, paths)
	}
	if !paths["/var/named/a.db"] || !paths["/var/named/new.db"] {
		t.Fatalf("paths %v", paths)
	}
}

// FixACLs runs nothing for a path that changed after the plan, and reads
// the ACL through the opened descriptor.
func TestFixACLsRefusesChangedPath(t *testing.T) {
	withRoot(t, map[string]string{"/var/named/a.db": "", "/var/named/b.db": ""})
	objs := map[string]*fileID{"/var/named/a.db": {Ino: 1, Nlink: 1}, "/var/named/b.db": {Ino: 2, Nlink: 1}}
	fakeWalk(t, objs)
	plan := &ACLPlan{Read: []string{"/var/named/a.db", "/var/named/b.db"}}
	plan.recordIDs(map[string]bool{"/var/named/a.db": true, "/var/named/b.db": true})
	objs["/var/named/b.db"] = &fileID{Ino: 3, Nlink: 1} // swapped
	var stated []string
	var ran [][]string
	res := FixACLs(plan, FixOptions{UID: agentUID,
		Stat: func(p string) (fs.FileInfo, error) { stated = append(stated, p); return modeFI{0o600}, nil },
		Read: func(string) (*ACL, *ACL, error) { return nil, nil, nil },
		Run:  func(a []string) error { ran = append(ran, a); return nil },
	})
	if len(res.Errors) != 1 || !errors.Is(res.Errors[0], ErrPathChanged) || len(res.Fixed) != 1 || res.Fixed[0] != "/var/named/a.db" {
		t.Fatalf("%+v", res)
	}
	if len(stated) != 1 || !strings.HasPrefix(stated[0], "/proc/self/fd/") || len(ran) != 1 || ran[0][len(ran[0])-1] != stated[0] {
		t.Fatalf("stat %v ran %v", stated, ran)
	}
}
