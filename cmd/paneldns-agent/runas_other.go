//go:build !unix

package main

import (
	"errors"
	"io"
)

var errNoAgentUser = errors.New("not supported on this system")

func runAsAgent(string, ...string) ([]byte, error) {
	return nil, errors.New("not supported on this system")
}

func execAsAgent(io.Writer, io.Writer, string, ...string) (int, error) {
	return 0, errNoAgentUser
}

func repairCheckState(string, io.Writer) error { return nil }
