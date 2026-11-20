//go:build unix

package main

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

// runAsAgent runs a command as the agent user, so --check sees exactly
// the access the service will have.
func runAsAgent(name string, args ...string) ([]byte, error) {
	u, err := user.Lookup(enrol.User)
	if err != nil {
		return nil, err
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	return cmd.CombinedOutput()
}
