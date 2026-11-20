package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

func cmdEnrol(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("enrol", stderr)
	url := fs.String("url", "", "PanelDNS URL (https)")
	code := fs.String("code", "", "one-time enrolment code from the dashboard")
	configPath := fs.String("config", config.DefaultPath, "config file to write")
	stateDir := fs.String("state-dir", config.StateDir, "state directory")
	if fs.Parse(args) != nil {
		return 2
	}
	if *code == "" {
		// The code may come from the environment, keeping it out of shell history.
		if v := os.Getenv("PANELDNS_ENROL_CODE"); v != "" {
			*code = v
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_, err := enrol.Run(ctx, enrol.Options{
		URL: *url, Code: *code, ConfigPath: *configPath, StateDir: *stateDir, Out: stdout,
		After: afterEnrol(*configPath, *stateDir, stdout),
	})
	if err != nil {
		fmt.Fprintln(stderr, "paneldns-agent enrol:", err)
		return 1
	}
	return 0
}
