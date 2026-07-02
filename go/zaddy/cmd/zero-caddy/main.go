package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/gematik/zero-lab/go/zaddy"
)

// Version is the zero-caddy release version. It defaults to "dev" and is overridden
// at build time via -ldflags "-X main.Version=<v>".
var Version = "dev"

// resolveVersion returns the ldflags-injected Version when set, otherwise the module
// version embedded by `go install …@vX.Y.Z` (read from the build info).
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

// fullVersion combines the zero-caddy version with the upstream Caddy version as
// SemVer build metadata, e.g. "0.16.0+caddy2.11.4".
func fullVersion() string {
	caddyVersion, _ := caddy.Version()
	return fmt.Sprintf("%s+caddy%s", resolveVersion(), strings.TrimPrefix(caddyVersion, "v"))
}

func main() {
	fmt.Fprintf(os.Stderr, "zero-caddy %s\n", fullVersion())
	caddycmd.Main()
}
