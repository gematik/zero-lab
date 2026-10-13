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

package authzserver

import (
	"fmt"
	"net/http"

	"github.com/gematik/zero-lab/go/gemidp"
)

// OpenidProviderInfo represents the information about an OpenID Provider
type OpenidProviderInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

// OpenidProvidersEndpoint serves the list of OpenID Providers supported by the server
func (s *Server) OpenidProvidersEndpoint(w http.ResponseWriter, r *http.Request) error {
	providers, err := s.OpenidProviders()
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", err.Error())
	}
	return writeJSON(w, http.StatusOK, providers)
}

// OpenidProviders returns the list of OpenID Providers supported by the server
func (s *Server) OpenidProviders() ([]OpenidProviderInfo, error) {
	providers := make([]OpenidProviderInfo, 0, len(s.openidProviders))
	for _, op := range s.openidProviders {
		info := OpenidProviderInfo{
			Issuer:  op.Issuer(),
			LogoURI: op.LogoURI(),
			Name:    op.Name(),
		}
		switch op.(type) {
		case *gemidp.Client:
			info.Type = "gemidp"
		default:
			info.Type = "oidc"
		}
		providers = append(providers, info)
	}
	if s.oidfRelyingParty != nil {
		idps, err := s.oidfRelyingParty.Federation().FetchIdpList()
		if err != nil {
			return nil, fmt.Errorf("fetching idp list from federation: %w", err)
		}
		for _, op := range idps {
			providers = append(providers, OpenidProviderInfo{
				Issuer:  op.Issuer,
				LogoURI: op.LogoURI,
				Name:    op.OrganizationName,
				Type:    "oidf",
			})
		}
	}

	return providers, nil
}
