//go:build unix

package syspath

import (
	"io/fs"
	"syscall"
)

func ownerOKOS(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Uid == 0 && fi.Mode().Perm()&0o022 == 0
}
