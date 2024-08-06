package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/gematik/zero-lab/go/zaddy"
)

func main() {
	caddycmd.Main()
}
