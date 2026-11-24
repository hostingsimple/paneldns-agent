//go:build linux

package enrol

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/hostingsimple/paneldns-agent/internal/config"
)

func TestWalkNoFollow(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "conf/dns"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "conf/dns/a.db"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "secret"), []byte("s"), 0o600))
	must(os.Symlink(filepath.Join(dir, "conf"), filepath.Join(dir, "link")))
	must(os.Symlink(filepath.Join(dir, "secret"), filepath.Join(dir, "conf/dns/b.db")))

	f, id, err := walkNoFollowOS(filepath.Join(dir, "conf/dns/a.db"))
	must(err)
	var st syscall.Stat_t
	must(syscall.Stat(filepath.Join(dir, "conf/dns/a.db"), &st))
	if id.Ino != st.Ino || id.Type != 0 || id.Nlink != 1 || id.UID != uint32(os.Getuid()) {
		t.Errorf("id %+v, stat ino %d", id, st.Ino)
	}
	// The descriptor names the file itself: /proc/self/fd/N reaches it.
	b, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	f.Close()
	if err == nil && string(b) != "x" {
		t.Errorf("read through the descriptor: %q", b)
	}
	if f, id, err := walkNoFollowOS(filepath.Join(dir, "conf/dns")); err != nil || id.Type != fs.ModeDir {
		t.Errorf("dir: %+v %v", id, err)
	} else {
		f.Close()
	}
	// A link in the middle fails; a link at the end is reported as a link.
	if _, _, err := walkNoFollowOS(filepath.Join(dir, "link/dns/a.db")); !errors.Is(err, ErrPathChanged) {
		t.Errorf("link in the middle: %v", err)
	}
	if f, id, err := walkNoFollowOS(filepath.Join(dir, "conf/dns/b.db")); err != nil || id.Type != fs.ModeSymlink {
		t.Errorf("link at the end: %+v %v", id, err)
	} else {
		f.Close()
	}
	if _, _, err := walkNoFollowOS(filepath.Join(dir, "conf/missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

// The A-3 race end to end with the real walk. The plan sees a real
// directory; then a user swaps it, at the worst moment: after fix-acls has
// checked the path again for links (trustedPath) and just before it opens
// it. Swapped for a link, the walk fails; swapped for another real
// directory, the object is not the one planned. Either way nothing is set
// and the decoy keeps no agent entry. Needs setfacl and ACL support.
func TestFixACLsRaceSwapped(t *testing.T) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl not installed")
	}
	for _, swap := range []string{"link", "directory"} {
		t.Run(swap, func(t *testing.T) {
			withRoot(t, map[string]string{
				"/etc/named.conf":                  `options { directory "/home/u/conf/dns"; }; zone "example.com" { type master; file "example.com.db"; };`,
				"/home/u/conf/dns/example.com.db":  "",
				"/home/u/decoy/dns/example.com.db": "secret",
			})
			cfg := config.Defaults()
			cfg.ZonesFile = "/etc/named.conf"
			plan, err := PlanACLs(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.ids) == 0 {
				t.Fatal("the plan recorded no objects")
			}
			conf := filepath.Join(Root, "home/u/conf")
			decoy := filepath.Join(Root, "home/u/decoy")
			swapped := false
			walkNoFollow = func(p string) (*os.File, fileID, error) {
				if !swapped && strings.HasPrefix(p, conf+"/") {
					swapped = true
					if err := os.Rename(conf, conf+".old"); err != nil {
						t.Fatal(err)
					}
					if swap == "link" {
						err = os.Symlink(decoy, conf)
					} else {
						err = os.Rename(decoy, conf)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return walkNoFollowOS(p)
			}
			defer func() { walkNoFollow = walkNoFollowOS }()
			res := FixACLs(plan, FixOptions{UID: 64999})
			joined := ""
			for _, e := range res.Errors {
				joined += e.Error() + "\n"
			}
			if strings.Contains(joined, "Operation not supported") {
				t.Skip("no ACLs on this file system")
			}
			if !swapped || len(res.Errors) == 0 || !strings.Contains(joined, ErrPathChanged.Error()) {
				t.Fatalf("swapped %v, result %+v", swapped, res)
			}
			for _, f := range []string{filepath.Join(decoy, "dns/example.com.db"), filepath.Join(conf, "dns/example.com.db"), filepath.Join(conf, "dns")} {
				if out, _ := exec.Command("getfacl", "-n", "-p", f).Output(); strings.Contains(string(out), "64999") {
					t.Errorf("%s got the agent's entry:\n%s", f, out)
				}
			}
			// Enrol, after the swap: refused too (the link by the re-check,
			// the directory by the walk).
			if err := ApplyACLs(plan, nil); err == nil {
				t.Errorf("ApplyACLs after the swap: no error")
			}
		})
	}
}
