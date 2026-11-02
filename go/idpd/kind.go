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

	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oauth/providers"
)

// ProviderType implements [providers.Typed].
func (c *Client) ProviderType() string { return "idpd" }

// Kind is the kind of IDP-Dienst providers, a list of [ClientConfig]. adjust, if not nil, sets what the program
// decides for every entry.
func Kind(adjust func(*ClientConfig)) providers.Kind {
	return func(node *yaml.Node, env providers.Env) (providers.Built, error) {
		var configs []ClientConfig
		if err := providers.Decode(node, &configs); err != nil {
			return providers.Built{}, err
		}
		var clients []oidc.Client
		for i := range configs {
			config := configs[i]
			if config.RedirectURI == "" {
				config.RedirectURI = env.RedirectURI
			}
			if adjust != nil {
				adjust(&config)
			}
			client, err := NewClientFromConfig(config)
			if err != nil {
				return providers.Built{}, fmt.Errorf("[%d] (%s): %w", i, config.ClientID, err)
			}
			clients = append(clients, client)
			slog.Info("configured openid provider", "type", "idpd", "name", client.Name(), "issuer", client.Issuer())
		}
		return providers.Built{Clients: clients}, nil
	}
}
