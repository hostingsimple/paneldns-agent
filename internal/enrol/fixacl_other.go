//go:build !linux

package enrol

import "errors"

// ReadACL is only implemented on Linux (development builds elsewhere).
var ReadACL ACLReader = func(string) (*ACL, *ACL, error) {
	return nil, nil, errors.New("reading POSIX ACLs is only supported on Linux")
}
