package main

import (
	"context"
	"fmt"
	"io"

	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/enrol"
)

// afterEnrol runs the steps after a successful enrolment (t043 adds read
// ACLs, --check and enabling the unit).
func afterEnrol(configPath, stateDir string, out io.Writer) func(context.Context, config.Config, enrol.Detected) error {
	return func(ctx context.Context, cfg config.Config, d enrol.Detected) error {
		fmt.Fprintln(out, "Next: systemctl enable --now paneldns-agent")
		return nil
	}
}
