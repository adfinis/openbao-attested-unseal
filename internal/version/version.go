// Package version exposes build metadata for the command binaries.
package version

const unknown = "unknown"

var (
	version   = "0.0.0-dev"
	commit    = unknown
	buildDate = unknown
	dirty     = unknown
)

// Info contains version metadata embedded at build time.
type Info struct {
	Version   string
	Commit    string
	BuildDate string
	Dirty     string
}

// BuildInfo returns the current build metadata.
func BuildInfo() Info {
	return Info{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		Dirty:     dirty,
	}
}
