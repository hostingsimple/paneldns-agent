//go:build !unix

package syspath

import "io/fs"

// ownerOKOS has no owner to check outside Unix (development builds).
func ownerOKOS(fs.FileInfo) bool { return true }
