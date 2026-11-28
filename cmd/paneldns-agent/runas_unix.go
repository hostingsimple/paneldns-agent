//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/hostingsimple/paneldns-agent/internal/enrol"
	"github.com/hostingsimple/paneldns-agent/internal/state"
)

// errNoAgentUser means the agent user doesn't exist (the package creates it).
var errNoAgentUser = errors.New("user " + enrol.User + " not found")

// agentCommand builds a command that runs as the agent user, with a fixed
// PATH and no inherited environment.
func agentCommand(name string, args ...string) (*exec.Cmd, error) {
	u, err := user.Lookup(enrol.User)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil, errNoAgentUser
		}
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %s: uid %q: %w", enrol.User, u.Uid, err)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("user %s: gid %q: %w", enrol.User, u.Gid, err)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	return cmd, nil
}

// runAsAgent runs a command as the agent user, so --check sees exactly
// the access the service will have.
func runAsAgent(name string, args ...string) ([]byte, error) {
	cmd, err := agentCommand(name, args...)
	if err != nil {
		return nil, err
	}
	return cmd.CombinedOutput()
}

// execAsAgent runs a command as the agent user with its output streamed
// to stdout and stderr, and returns its exit status.
func execAsAgent(stdout, stderr io.Writer, name string, args ...string) (int, error) {
	cmd, err := agentCommand(name, args...)
	if err != nil {
		return 0, err
	}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// repairCheckState gives the agent user back the files a root --check of
// agent 0.1.6 or older left owned by root: sequence.json and its lock
// (t105). The service can't take a sequence number while they belong to
// root. Only inside a state directory the agent user owns, and only
// regular files with one link that root owns: --state-dir is whatever the
// admin typed, and the directory itself is never changed.
func repairCheckState(dir string, out io.Writer) error {
	u, err := user.Lookup(enrol.User)
	if err != nil {
		return nil // reported by the caller's fallback
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	di, err := os.Lstat(dir)
	if err != nil || !di.IsDir() {
		return nil
	}
	if st, ok := di.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		return nil
	}
	for _, n := range []string{state.SequenceFile, state.LockFile} {
		p := filepath.Join(dir, n)
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || st.Nlink != 1 {
			continue
		}
		if err := os.Lchown(p, uid, gid); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		fmt.Fprintf(out, "gave %s back to %s (an earlier --check run as root left it owned by root)\n", p, enrol.User)
	}
	return nil
}
