//go:build !unix

package enrol

import (
	"io/fs"
	"os"
)

// lstatOwnerOS has no owner outside Unix (development builds): every
// symbolic link counts as untrusted.
func lstatOwnerOS(p string) (fs.FileMode, uint32, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0, 0, err
	}
	return fi.Mode(), ^uint32(0), nil
}
