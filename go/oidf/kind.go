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
	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/oauth/providers"
)

// TypeOIDF is the provider type of a federation's members.
const TypeOIDF = "oidf"

// ProviderType implements [providers.Typed].
func (c *RelyingPartyClient) ProviderType() string { return TypeOIDF }

// Providers implements [providers.Federation].
func (rp *RelyingParty) Providers() ([]providers.Info, error) {
	idps, err := rp.Federation().FetchIdpList()
	if err != nil {
		return nil, err
	}
	infos := make([]providers.Info, 0, len(idps))
	for _, idp := range idps {
		infos = append(infos, providers.Info{Issuer: idp.Issuer, Name: idp.OrganizationName, LogoURI: idp.LogoURI, Type: TypeOIDF})
	}
	return infos, nil
}

// Kind is the kind of a federation's relying party, one [RelyingPartyConfig]. built, if not nil, gets the relying
// party, for a program that serves its entity statement too.
func Kind(built func(*RelyingParty)) providers.Kind {
	return func(node *yaml.Node, env providers.Env) (providers.Built, error) {
		config := new(RelyingPartyConfig)
		if err := providers.Decode(node, config); err != nil {
			return providers.Built{}, err
		}
		config.BaseDir = env.BaseDir
		rp, err := NewRelyingPartyFromConfig(config)
		if err != nil {
			return providers.Built{}, err
		}
		if built != nil {
			built(rp)
		}
		return providers.Built{Federation: rp}, nil
	}
}
