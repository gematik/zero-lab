package main

import (
	"fmt"
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/gematik/zero-lab/go/zaddy"
)

// Version is the zero-caddy release version. It defaults to "dev" and is overridden
// at build time via -ldflags "-X main.Version=<v>".
var Version = "dev"

func main() {
	fmt.Fprintf(os.Stderr, "zero-caddy %s\n", Version)
	caddycmd.Main()
}
