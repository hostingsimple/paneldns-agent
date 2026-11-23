package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

// stdin is replaced in tests.
var stdin io.Reader = os.Stdin

func cmdEnrol(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("enrol", stderr)
	url := fs.String("url", "", "PanelDNS URL (https)")
	code := fs.String("code", "", "one-time enrolment code from the dashboard; - reads it from standard input")
	configPath := fs.String("config", config.DefaultPath, "config file to write")
	stateDir := fs.String("state-dir", config.StateDir, "state directory")
	noACL := fs.Bool("no-acl", false, "print the setfacl commands instead of running them")
	noStart := fs.Bool("no-start", false, "don't enable and start the service")
	if fs.Parse(args) != nil {
		return 2
	}
	c, err := enrolCode(*code, os.Getenv("PANELDNS_ENROL_CODE"), stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent enrol:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_, err = enrol.Run(ctx, enrol.Options{
		URL: *url, Code: c, ConfigPath: *configPath, StateDir: *stateDir, Out: stdout,
		After: afterEnrol(afterOptions{configPath: *configPath, stateDir: *stateDir, noACL: *noACL, noStart: *noStart, out: stdout}),
	})
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent enrol:", err)
		return 1
	}
	return 0
}

// enrolCode picks the enrolment code: "--code -" reads one line from
// standard input; no --code uses PANELDNS_ENROL_CODE. Both keep the code
// out of the process list. A code given on the command line works, but
// any local user can read it from /proc/PID/cmdline while enrol runs and
// race it to PanelDNS with a key of their own, so it draws a warning.
func enrolCode(flagCode, env string, in io.Reader, stderr io.Writer) (string, error) {
	switch flagCode {
	case "-":
		line, err := bufio.NewReader(io.LimitReader(in, 4096)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("reading the code from standard input: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			return "", errors.New("--code -: no code on standard input")
		}
		return line, nil
	case "":
		return env, nil
	}
	fmt.Fprintln(stderr, "warning: a code given with --code is visible to other users of this server in the process list while enrol runs;"+
		" pass it on standard input instead (--code - <<< 'CODE') or in PANELDNS_ENROL_CODE")
	return flagCode, nil
}
