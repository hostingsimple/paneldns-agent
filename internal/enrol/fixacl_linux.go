//go:build linux

package enrol

import (
	"errors"
	"syscall"
)

// ReadACL reads a path's access and default ACL from its xattrs. It
// follows symlinks, as setfacl does.
var ReadACL ACLReader = func(p string) (access, def *ACL, err error) {
	if access, err = readACLXattr(p, "system.posix_acl_access"); err != nil {
		return nil, nil, err
	}
	if def, err = readACLXattr(p, "system.posix_acl_default"); err != nil {
		return nil, nil, err
	}
	return access, def, nil
}

func readACLXattr(p, name string) (*ACL, error) {
	buf := make([]byte, 512)
	for {
		n, err := syscall.Getxattr(p, name, buf)
		switch {
		case err == nil:
			return ParseACLXattr(buf[:n])
		case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
			// No ACL (or a file system without ACLs: setfacl reports that).
			return nil, nil
		case errors.Is(err, syscall.ERANGE) && len(buf) < 1<<16:
			buf = make([]byte, len(buf)*4)
		default:
			return nil, err
		}
	}
}
