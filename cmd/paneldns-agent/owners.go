package main

import (
	"github.com/hostingsimple/paneldns-agent/internal/config"
	"github.com/hostingsimple/paneldns-agent/internal/engine"
)

// newOwners returns the panel owner lookup for OWNERS_FILE (t043).
func newOwners(config.Config) engine.Owners { return nil }
