//go:build unix

package source

import (
	"errors"
	"syscall"
)

// processAlive sends signal 0: no error or EPERM means the process exists
// (it belongs to another user, such as named).
func processAlive(pid int) Running {
	err := syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return RunningYes
	}
	if errors.Is(err, syscall.ESRCH) {
		return RunningNo
	}
	return RunningUnknown
}
