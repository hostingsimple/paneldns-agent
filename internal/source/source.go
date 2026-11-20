// Package source lists and reads the zones of the local DNS server: BIND
// (named.conf plus named-compilezone) or the PowerDNS local API (spec 7.3).
package source

import (
	"context"

	"github.com/hostingsimple/paneldns-agent/internal/zonefile"
)

// ZoneRef is one primary zone found by List.
type ZoneRef struct {
	Name string // lower case, no trailing dot
	// Fingerprint changes whenever the zone's content may have changed
	// (spec 7.4 step 2). Equal fingerprints mean "skip".
	Fingerprint string
	// DeclaredIn is the config file declaring the zone (BIND), used to
	// notice an include that became unreadable.
	DeclaredIn string

	key string // backend handle: zone file (BIND) or zone id (PowerDNS)
}

// Listing is the result of one List call.
type Listing struct {
	Backend   string
	Zones     []ZoneRef
	View      string              // BIND view in use ("" = no views)
	Directory string              // BIND options { directory }
	Skipped   int                 // non-primary zones skipped
	Other     map[string][]string // zones only in other views -> views
	// Unreadable lists config files (includes) that could not be read.
	Unreadable []string
	Warnings   []string
}

// Running is what a source knows about its DNS server's process.
type Running int

// Running states.
const (
	RunningUnknown Running = iota
	RunningYes
	RunningNo
)

func (r Running) String() string {
	switch r {
	case RunningYes:
		return "running"
	case RunningNo:
		return "not running"
	}
	return "unknown"
}

// Source is a zone backend.
type Source interface {
	// Kind is the ZONE_SOURCE value.
	Kind() string
	// List finds the primary zones. An error means the listing can't be
	// trusted (no inventory or deletions are sent from it).
	List(ctx context.Context) (*Listing, error)
	// Read returns the zone's records, parsed but not stripped.
	Read(ctx context.Context, z ZoneRef) ([]zonefile.RR, error)
	// Running reports whether the DNS server appears to be running.
	Running(ctx context.Context) (Running, string)
}
