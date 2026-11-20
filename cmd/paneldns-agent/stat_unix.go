//go:build unix

package main

import (
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/hostingsimple/paneldns-agent/internal/check"
)

// statFile returns mode and owner names for the --check mode checks.
func statFile(p string) (check.FileMode, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return check.FileMode{}, err
	}
	fm := check.FileMode{Mode: fi.Mode(), Accessible: true}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		fm.User = strconv.FormatUint(uint64(st.Uid), 10)
		fm.Group = strconv.FormatUint(uint64(st.Gid), 10)
		if u, err := user.LookupId(fm.User); err == nil {
			fm.User = u.Username
		}
		if g, err := user.LookupGroupId(fm.Group); err == nil {
			fm.Group = g.Name
		}
	}
	return fm, nil
}
