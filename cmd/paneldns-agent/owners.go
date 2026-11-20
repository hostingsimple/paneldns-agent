package main

import (
	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/engine"
	"github.com/hostingsimple/paneldns-agent/internal/owners"
)

// newOwners returns the owner lookup for OWNERS_FILE, or nil when unset.
func newOwners(cfg config.Config) engine.Owners {
	if cfg.OwnersFile == "" {
		return nil
	}
	return &owners.File{Path: cfg.OwnersFile}
}
