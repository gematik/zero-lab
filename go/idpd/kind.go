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

package idpd

import (
	"fmt"
	"log/slog"

	"github.com/gematik/zero-lab/go/openid/providers"
)

// TypeIDPD is the provider type of the IDP-Dienst.
const TypeIDPD = "idpd"

// Kind is the kind of IDP-Dienst providers, a list of [ClientConfig]. adjust, if not nil, sets what the program
// decides for every entry.
func Kind(adjust func(*ClientConfig)) providers.Kind {
	return func(decode providers.Decode, env providers.Env) (providers.Built, error) {
		var configs []ClientConfig
		if err := decode(&configs); err != nil {
			return providers.Built{}, err
		}
		var built providers.Built
		for i := range configs {
			config := configs[i]
			if config.RedirectURI == "" {
				config.RedirectURI = env.RedirectURI
			}
			if adjust != nil {
				adjust(&config)
			}
			client, err := NewClientFromConfig(config, env.HTTPClient)
			if err != nil {
				return providers.Built{}, fmt.Errorf("[%d] (%s): %w", i, config.ClientID, err)
			}
			built.Providers = append(built.Providers, client.Provider())
			slog.Info("configured openid provider", "type", TypeIDPD, "name", config.Name, "issuer", client.Issuer())
		}
		return built, nil
	}
}

// Provider is the client with what a chooser shows of it.
func (c *Client) Provider() providers.Provider {
	return providers.Provider{
		Issuer:  c.Issuer(),
		Name:    c.config.Name,
		LogoURI: c.config.LogoURI,
		Type:    TypeIDPD,
		Client:  c,
	}
}
