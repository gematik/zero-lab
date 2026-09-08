package common

import (
	"runtime/debug"
	"strings"
)

// Version is the ti CLI release version. It defaults to "dev" and is overridden
// at build time via
// -ldflags "-X github.com/gematik/zero-lab/go/ti/internal/common.Version=<v>".
var Version = "dev"

// ResolveVersion returns the ldflags-injected Version when set, otherwise the module
// version embedded by `go install module@vX.Y.Z` (read from the build info). This makes
// installed binaries report their tag version without needing ldflags.
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
