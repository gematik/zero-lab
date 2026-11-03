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

package openid

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DiscoveryDocument is the part of the provider metadata (OpenID Connect Discovery 1.0 §3) this package reads.
type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// FetchDiscoveryDocument fetches the metadata of the provider issuer (OpenID Connect Discovery 1.0 section 4). The
// document has to answer with 200 and name exactly issuer (section 4.3).
//
// The comparison knows no exception. Entra ID's multi-tenant documents (/common, /organizations) name the issuer
// https://login.microsoftonline.com/{tenantid}/v2.0, which no ID token carries, so verifying an ID token against it
// could never succeed either; a single tenant's document names itself, with the tenant as its GUID, and that GUID is
// what the configuration has to hold.
func FetchDiscoveryDocument(issuer string, httpClient *http.Client) (*DiscoveryDocument, error) {
	// Section 4.1: a terminating / is removed before the path is appended, and stays part of the issuer.
	location := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(location)
	if err != nil {
		return nil, fmt.Errorf("unable to get discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: discovery document status %d", location, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: unable to read discovery document: %w", location, err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("%s: discovery document larger than %d bytes", location, maxResponseBytes)
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%s: unable to decode discovery document: %w", location, err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("%s: discovery document names the issuer %q, configured is %q", location, doc.Issuer, issuer)
	}

	return &doc, nil
}
