package epa

import (
	"runtime/debug"
	"strings"
)

// Version is the zero-epa release version. It defaults to "dev" and is overridden
// at build time via -ldflags "-X github.com/gematik/zero-lab/go/epa.Version=<v>".
// It ends up in the x-useragent header, which the ePA aggregators validate
// (ClientId/Version, version max 15 chars of [a-zA-Z0-9.-]) — so builds must
// inject a plain semantic version, not a raw `git describe` string.
var Version = "dev"

// ResolveVersion returns the ldflags-injected Version when set, otherwise the module
// version embedded by `go install …@vX.Y.Z` (read from the build info).
func ResolveVersion() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}
	return Version
}
