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

package oidf

import (
	"context"

	"github.com/gematik/zero-lab/go/openid/providers"
)

// TypeOIDF is the provider type of a federation's members.
const TypeOIDF = "oidf"

// Provider implements [providers.Federation]: it resolves issuer in the federation.
func (rp *RelyingParty) Provider(ctx context.Context, issuer string) (providers.Provider, error) {
	client, err := rp.Client(ctx, issuer)
	if err != nil {
		return providers.Provider{}, err
	}
	current := client.provider()
	return providers.Provider{
		Issuer:  client.Issuer(),
		Name:    current.metadata.OrganizationName,
		LogoURI: current.metadata.LogoURI,
		Type:    TypeOIDF,
		Client:  client,
	}, nil
}

// Providers implements [providers.Federation].
func (rp *RelyingParty) Providers(ctx context.Context) ([]providers.Info, error) {
	idps, err := rp.Federation().FetchIdpList(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]providers.Info, 0, len(idps))
	for _, idp := range idps {
		infos = append(infos, providers.Info{Issuer: idp.Issuer, Name: idp.OrganizationName, LogoURI: idp.LogoURI, Type: TypeOIDF})
	}
	return infos, nil
}

// Kind is the kind of a federation's relying party, one [RelyingPartyConfig], with apiKey as its
// [RelyingPartyConfig.APIKey] and documents as its [RelyingPartyConfig.Documents]. built, if not nil, gets the
// relying party, for a program that serves its entity statement too.
func Kind(apiKey string, documents Documents, built func(*RelyingParty)) providers.Kind {
	return func(decode providers.Decode, env providers.Env) (providers.Built, error) {
		config := new(RelyingPartyConfig)
		if err := decode(config); err != nil {
			return providers.Built{}, err
		}
		config.APIKey = apiKey
		config.HTTPClient = env.HTTPClient
		config.Documents = documents
		// providers.Build runs at start-up and hands no context down; the bound keeps a master that does not
		// answer from holding the start for longer than one fetch may take.
		ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
		defer cancel()
		rp, err := NewRelyingParty(ctx, config, env.BaseDir)
		if err != nil {
			return providers.Built{}, err
		}
		if built != nil {
			built(rp)
		}
		return providers.Built{Federation: rp}, nil
	}
}
