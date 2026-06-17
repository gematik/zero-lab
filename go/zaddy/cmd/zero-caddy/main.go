package main

import (
	"fmt"
	"os"
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

// fullVersion combines the zero-caddy version with the upstream Caddy version as
// SemVer build metadata, e.g. "0.16.0+caddy2.11.4".
func fullVersion() string {
	caddyVersion, _ := caddy.Version()
	return fmt.Sprintf("%s+caddy%s", Version, strings.TrimPrefix(caddyVersion, "v"))
}

func main() {
	fmt.Fprintf(os.Stderr, "zero-caddy %s\n", fullVersion())
	caddycmd.Main()
}
