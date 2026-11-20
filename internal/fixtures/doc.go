// Package fixtures checks (and with -update regenerates) the shared test
// files in the top-level testdata/ directory that the PanelDNS app copies
// and pins by checksum: the Ed25519 request-signing vector, the
// canonical-hash fixture and testdata/SHA256SUMS. See testdata/README.md.
//
// Regenerate after a deliberate protocol change only:
//
//	go test ./internal/fixtures -update
//
// The inputs (zone files, vector parameters) are fixed; -update rewrites
// the expected outputs and the checksums.
package fixtures
