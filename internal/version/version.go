// Package version holds the agent's version string.
//
// Release builds set it with
//
//	-ldflags "-X github.com/hostingsimple/paneldns-agent/internal/version.Version=1.2.3"
//
// so the binary carries no build path, host name or time stamp and stays
// reproducible.
package version

// Version is the semantic version of this build, without a leading "v".
var Version = "0.1.0-dev"

// UserAgent is the User-Agent header value sent with every request
// (spec 7.6).
func UserAgent() string { return "paneldns-agent/" + Version }
