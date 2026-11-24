//go:build !linux

package enrol

import "os"

// walkNoFollowOS has no O_PATH outside Linux (development builds): paths
// are used as they are.
func walkNoFollowOS(string) (*os.File, fileID, error) { return nil, fileID{}, errNoWalk }
