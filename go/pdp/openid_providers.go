// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
