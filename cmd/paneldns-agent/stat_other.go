//go:build !unix

package main

import (
	"os"

	"github.com/hostingsimple/paneldns-agent/internal/check"
)

// statFile on non-Unix systems reports no owner (development builds only).
func statFile(p string) (check.FileMode, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return check.FileMode{}, err
	}
	return check.FileMode{Mode: fi.Mode(), Accessible: true}, nil
}
