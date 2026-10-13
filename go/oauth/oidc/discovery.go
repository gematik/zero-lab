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

package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func FetchDiscoveryDocument(url string, httpClient *http.Client) (*DiscoveryDocument, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("unable to get discovery document: %w", err)
	}
	defer resp.Body.Close()

	var doc DiscoveryDocument
	err = json.NewDecoder(resp.Body).Decode(&doc)
	if err != nil {
		return nil, fmt.Errorf("unable to decode discovery document: %w", err)
	}

	return &doc, nil
}
