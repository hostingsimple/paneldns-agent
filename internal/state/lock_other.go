//go:build !unix

package state

import "sync"

// The agent runs on Linux. Elsewhere (development builds) a process-local
// mutex stands in for flock.
var mu sync.Mutex

func lockFile(string) (func(), error) {
	mu.Lock()
	return mu.Unlock, nil
}
