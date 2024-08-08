package zerver_test

import (
	"os"
	"testing"

	zerver "github.com/gematik/zero-lab/go/pdp"
)

func TestLoadEnv(t *testing.T) {
	zerver.LoadEnv("~/.env2")
	t.Log("Env loaded")
	t.Log("FOO", os.Getenv("FOO"))
}
