//go:build linux

package enrol

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

// oPath is O_PATH: the generic Linux value, used by amd64 and arm64 (the
// syscall package defines it on arm64 only).
const oPath = 0x200000

// walkNoFollowOS opens p from "/" one component at a time with
// openat(O_PATH|O_NOFOLLOW): every component but the last with O_DIRECTORY,
// so a symbolic link there fails (ENOTDIR), and the last without, so a link
// there is opened as the link itself and reported as one. Nothing is
// followed, so the descriptor refers to what p names right now, with no
// link in between.
func walkNoFollowOS(p string) (*os.File, fileID, error) {
	if !strings.HasPrefix(p, "/") {
		return nil, fileID{}, fmt.Errorf("%s: not an absolute path", p)
	}
	var parts []string
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".":
		case "..":
			return nil, fileID{}, fmt.Errorf("%s: has a .. component", p)
		default:
			parts = append(parts, c)
		}
	}
	fd, err := syscall.Open("/", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileID{}, &fs.PathError{Op: "open", Path: "/", Err: err}
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, fileID{}, &fs.PathError{Op: "fstat", Path: "/", Err: err}
	}
	shared := false
	for i, c := range parts {
		last := i == len(parts)-1
		flags := oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
		if !last {
			flags |= syscall.O_DIRECTORY
		}
		shared = sharedDir(&st)
		nfd, err := syscall.Openat(fd, c, flags, 0)
		syscall.Close(fd)
		sofar := "/" + path.Join(parts[:i+1]...)
		if err != nil {
			if !last && (errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP)) {
				return nil, fileID{}, fmt.Errorf("%s: %s is a symbolic link or not a directory: %w", p, sofar, ErrPathChanged)
			}
			return nil, fileID{}, &fs.PathError{Op: "open", Path: sofar, Err: err}
		}
		fd = nfd
		if err := syscall.Fstat(fd, &st); err != nil {
			syscall.Close(fd)
			return nil, fileID{}, &fs.PathError{Op: "fstat", Path: sofar, Err: err}
		}
	}
	id := fileID{
		Dev: uint64(st.Dev), Ino: uint64(st.Ino), UID: st.Uid, Nlink: uint64(st.Nlink),
		Type: fileType(st.Mode), SharedParent: shared,
	}
	return os.NewFile(uintptr(fd), p), id, nil
}

func fileType(m uint32) fs.FileMode {
	switch m & syscall.S_IFMT {
	case syscall.S_IFDIR:
		return fs.ModeDir
	case syscall.S_IFREG:
		return 0
	case syscall.S_IFLNK:
		return fs.ModeSymlink
	}
	return fs.ModeIrregular
}

// sharedDir reports whether a user other than root can add, remove or
// rename entries in the directory st describes.
func sharedDir(st *syscall.Stat_t) bool {
	return st.Uid != 0 || (st.Mode&0o022 != 0 && st.Mode&syscall.S_ISVTX == 0)
}
