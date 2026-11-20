// Command paneldns-agent reads the zones of a hosting server's own DNS
// (BIND or PowerDNS) and pushes them, signed, to the PanelDNS ingest API.
// It only ever connects out; nothing connects to it.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hostingsimple/paneldns-agent/internal/version"
)

const usage = `paneldns-agent: Panel Sync agent for PanelDNS

Usage:
  paneldns-agent run       [--config FILE]   run the sync loop (systemd ExecStart)
  paneldns-agent --check   [--config FILE] [--zone NAME] [--json]
  paneldns-agent enrol     --url URL --code CODE [--config FILE]
  paneldns-agent version
`

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.Version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
