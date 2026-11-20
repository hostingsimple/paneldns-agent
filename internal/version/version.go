// Package version holds the agent's version string.
//
// Release builds set it with
//
//	-ldflags "-X github.com/hostingsimple/paneldns-agent/internal/version.Version=1.2.3"
//
// so the binary carries no build path, host name or time stamp and stays
// reproducible.
package version

import (
	"strconv"
	"strings"
)

// Version is the semantic version of this build, without a leading "v".
var Version = "0.1.0-dev"

// UserAgent is the User-Agent header value sent with every request
// (spec 7.6).
func UserAgent() string { return "paneldns-agent/" + Version }

// Less reports whether semantic version a is lower than b. A leading "v"
// is ignored; a pre-release ("1.2.0-rc1") is lower than its release.
// Unparseable versions compare as equal (never "outdated" by accident).
func Less(a, b string) bool {
	pa, oka := parse(a)
	pb, okb := parse(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa.n[i] != pb.n[i] {
			return pa.n[i] < pb.n[i]
		}
	}
	switch {
	case pa.pre == pb.pre:
		return false
	case pa.pre == "":
		return false
	case pb.pre == "":
		return true
	}
	return pa.pre < pb.pre
}

type semver struct {
	n   [3]int
	pre string
}

func parse(s string) (semver, bool) {
	var v semver
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v.n[i] = n
	}
	return v, true
}
