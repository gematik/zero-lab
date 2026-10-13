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

package pep

const ProtectedResourceMetadataUriPath = "/.well-known/oauth-protected-resource"

// Implementation of protected resource metadata
// according to https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-01.html
type ProtectedResourceMetadata struct {
	Resource                             string   `json:"resource"`                                           // REQUIRED
	AuthorizationServers                 []string `json:"authorization_servers,omitempty"`                    // OPTIONAL
	JwksURI                              string   `json:"jwks_uri,omitempty"`                                 // OPTIONAL
	ScopesSupported                      []string `json:"scopes_supported,omitempty"`                         // RECOMMENDED
	BearerMethodsSupported               []string `json:"bearer_methods_supported,omitempty"`                 // OPTIONAL
	ResourceSigningAlgValuesSupported    []string `json:"resource_signing_alg_values_supported,omitempty"`    // OPTIONAL
	ResourceEncryptionAlgValuesSupported []string `json:"resource_encryption_alg_values_supported,omitempty"` // OPTIONAL
	ResourceEncryptionEncValuesSupported []string `json:"resource_encryption_enc_values_supported,omitempty"` // OPTIONAL
	ResourceDocumentation                string   `json:"resource_documentation,omitempty"`                   // OPTIONAL
	ResourcePolicyURI                    string   `json:"resource_policy_uri,omitempty"`                      // OPTIONAL
	ResourceTosURI                       string   `json:"resource_tos_uri,omitempty"`                         // OPTIONAL
}
