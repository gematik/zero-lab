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
	"context"
	"net/http"
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
	providers, err := s.OpenidProviders(r.Context())
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", err.Error())
	}
	return writeJSON(w, http.StatusOK, providers)
}

// OpenidProviders returns the list of OpenID Providers supported by the server
func (s *Server) OpenidProviders(ctx context.Context) ([]OpenidProviderInfo, error) {
	infos, err := s.providers.Providers(ctx)
	if err != nil {
		return nil, err
	}
	list := make([]OpenidProviderInfo, 0, len(infos))
	for _, info := range infos {
		list = append(list, OpenidProviderInfo{Issuer: info.Issuer, LogoURI: info.LogoURI, Name: info.Name, Type: info.Type})
	}
	return list, nil
}
