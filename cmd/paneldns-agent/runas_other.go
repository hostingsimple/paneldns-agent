//go:build !unix

package main

import "errors"

func runAsAgent(string, ...string) ([]byte, error) {
	return nil, errors.New("not supported on this system")
}
