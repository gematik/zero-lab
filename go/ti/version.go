package main

import (
	"runtime/debug"
	"strings"
)

// Version is the ti CLI release version. It defaults to "dev" and is overridden
// at build time via -ldflags "-X main.Version=<v>".
var Version = "dev"

// resolveVersion returns the ldflags-injected Version when set, otherwise the module
// version embedded by `go install module@vX.Y.Z` (read from the build info). This makes
// installed binaries report their tag version without needing ldflags.
func resolveVersion() string {
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
