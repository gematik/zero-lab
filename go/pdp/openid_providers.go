package pdp

import (
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"gopkg.in/yaml.v2"
)

const defaultOpenidProvidersFile = "openid-providers.yaml"

// openidProviders is the flat openid-providers.yaml schema — the same shape pep loads, reusing each
// provider's package config type. The PDP and pep share the file format without a shared package.
type openidProviders struct {
	OIDC   []oidc.Config            `yaml:"oidc"`
	Gemidp []gemidp.ClientConfig    `yaml:"gemidp"`
	OIDF   *oidf.RelyingPartyConfig `yaml:"oidf"`
}

// LoadOpenidProviders reads the flat openid-providers.yaml. ${VAR} placeholders expand from the environment.
// Relative paths inside the OIDF config resolve against the file's directory (set by the caller via
// OidfRelyingPartyConfig.BaseDir).
func LoadOpenidProviders(path string) ([]oidc.Config, []gemidp.ClientConfig, *oidf.RelyingPartyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read providers %q: %w", path, err)
	}
	var op openidProviders
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &op); err != nil {
		return nil, nil, nil, fmt.Errorf("parse providers %q: %w", path, err)
	}
	return op.OIDC, op.Gemidp, op.OIDF, nil
}
