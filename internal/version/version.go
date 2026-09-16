// Package version holds the aivault release version as the single source of
// truth for the binary, the `aivault version` command, and release stamping.
package version

// Version is the semantic version. Release tooling can stamp it (with the
// Commit/Date metadata below) via:
//
//	-ldflags "-X github.com/ZN9-KYANT/aivault/internal/version.Version=v1.0.0 \
//	          -X ...version.Commit=abc1234 -X ...version.Date=2026-09-16"
var Version = "1.0.0"

// Build metadata; "none"/"unknown" for plain `go build` output.
var (
	Commit = "none"
	Date   = "unknown"
)
