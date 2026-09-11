package testca

import (
	"os"
	"testing"
)

// RequireNetwork skips t unless GEMPKI_NETWORK_TESTS=1 is set. Tests that
// reach the live gematik endpoints opt in through it, so the default
// `go test ./...` stays offline-clean the way RequireOpenSSL keeps it
// toolchain-clean.
func RequireNetwork(t *testing.T) {
	t.Helper()
	if os.Getenv("GEMPKI_NETWORK_TESTS") != "1" {
		t.Skip("set GEMPKI_NETWORK_TESTS=1 to run tests against the live TI endpoints")
	}
}
