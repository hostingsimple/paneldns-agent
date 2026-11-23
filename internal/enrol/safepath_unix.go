//go:build unix

package enrol

import (
	"io/fs"
	"os"
	"syscall"
)

func lstatOwnerOS(p string) (fs.FileMode, uint32, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.Mode(), ^uint32(0), nil
	}
	return fi.Mode(), st.Uid, nil
}
