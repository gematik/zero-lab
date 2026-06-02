package gempki

import (
	"bytes"
	_ "embed"
	"fmt"
)

//go:embed roots-test.json
var dataRootsTest []byte

//go:embed roots-dev-ref.json
var dataRootsDevRef []byte

//go:embed roots-prod.json
var dataRootsProd []byte

func LoadRootsEmbedded(env Environment) (*Roots, error) {
	var data []byte
	switch env {
	case EnvTest:
		data = dataRootsTest
	case EnvDev, EnvRef:
		data = dataRootsDevRef
	case EnvProd:
		data = dataRootsProd
	default:
		return nil, fmt.Errorf("unknown environment: %s", env)
	}

	return parseRoots(env, bytes.NewReader(data))
}
