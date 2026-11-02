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
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// UserType is a value of gematik's user_type_supported claim: the kind of user a provider authenticates.
type UserType string

// The user types an OpenID provider can declare.
const (
	UserTypeIP  UserType = "IP"  // Insured Person
	UserTypeHP  UserType = "HP"  // Health Professional
	UserTypeHCI UserType = "HCI" // Health Care Institution
)

// EntityStatement holds the claims of an OpenID Federation entity statement, the signed JWT in which an
// entity, or the federation master about an entity, publishes keys and metadata. A value says nothing about
// its signature; only statements returned by OpenidFederation have been verified.
type EntityStatement struct {
	ExpiresAt      int64     `json:"exp"`
	IssuedAt       int64     `json:"iat"`
	Issuer         string    `json:"iss"`
	Subject        string    `json:"sub"`
	AuthorityHints []string  `json:"authority_hints"`
	Jwks           *Jwks     `json:"jwks"`
	Metadata       *Metadata `json:"metadata"`
}

// Metadata is the metadata claim of an entity statement, one member per entity type.
type Metadata struct {
	OpenidRelyingParty *OpenIDRelyingPartyMetadata `json:"openid_relying_party,omitempty"`
	OpenidProvider     *OpenIDProviderMetadata     `json:"openid_provider,omitempty"`
	FederationEntity   *FederationEntityMetadata   `json:"federation_entity"`
}

// OpenIDProviderMetadata is the openid_provider metadata of an identity provider.
type OpenIDProviderMetadata struct {
	AuthorizationEndpoint                 string   `json:"authorization_endpoint"`
	ClientRegistrationTypesSupported      []string `json:"client_registration_types_supported"`
	GrantTypesSupported                   []string `json:"grant_types_supported"`
	IDTokenEncryptionAlgValuesSupported   []string `json:"id_token_encryption_alg_values_supported"`
	IDTokenEncryptionEncValuesSupported   []string `json:"id_token_encryption_enc_values_supported"`
	IDTokenSigningAlgValuesSupported      []string `json:"id_token_signing_alg_values_supported"`
	Issuer                                string   `json:"issuer"`
	LogoURI                               string   `json:"logo_uri"`
	OrganizationName                      string   `json:"organization_name"`
	PushedAuthorizationRequestEndpoint    string   `json:"pushed_authorization_request_endpoint"`
	RequestAuthenticationMethodsSupported struct {
		Ar  []string `json:"ar"`
		Par []string `json:"par"`
	} `json:"request_authentication_methods_supported"`
	RequirePushedAuthorizationRequests         bool       `json:"require_pushed_authorization_requests"`
	ResponseModesSupported                     []string   `json:"response_modes_supported"`
	ResponseTypesSupported                     []string   `json:"response_types_supported"`
	ScopesSupported                            []string   `json:"scopes_supported"`
	SignedJwksURI                              string     `json:"signed_jwks_uri"`
	SubjectTypesSupported                      []string   `json:"subject_types_supported"`
	TokenEndpoint                              string     `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string   `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string   `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserTypeSupported                          []UserType `json:"user_type_supported"`
}

// OpenIDRelyingPartyMetadata is the openid_relying_party metadata this relying party publishes.
type OpenIDRelyingPartyMetadata struct {
	SignedJwksURI                      string   `json:"signed_jwks_uri,omitempty"`
	Jwks                               *Jwks    `json:"jwks"`
	OrganizationName                   string   `json:"organization_name"`
	ClientName                         string   `json:"client_name"`
	LogoURI                            string   `json:"logo_uri"`
	RedirectURIs                       []string `json:"redirect_uris"`
	ResponseTypes                      []string `json:"response_types"`
	ClientRegistrationTypes            []string `json:"client_registration_types"`
	GrantTypes                         []string `json:"grant_types"`
	RequirePushedAuthorizationRequests bool     `json:"require_pushed_authorization_requests"`
	TokenEndpointAuthMethod            string   `json:"token_endpoint_auth_method"`
	DefaultACRValues                   []string `json:"default_acr_values"`
	IDTokenSignedResponseAlg           string   `json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg        string   `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc        string   `json:"id_token_encrypted_response_enc"`
	Scope                              string   `json:"scope"`
}

// FederationEntityMetadata is the federation_entity metadata; the federation master's names its fetch and
// IdP list endpoints.
type FederationEntityMetadata struct {
	Name                    string   `json:"name,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	HomepageURI             string   `json:"homepage_uri,omitempty"`
	FederationFetchEndpoint string   `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint  string   `json:"federation_list_endpoint,omitempty"`
	IdpListEndpoint         string   `json:"idp_list_endpoint,omitempty"`
}

func tokenToEntityStatement(token jwt.Token) (*EntityStatement, error) {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal token: %w", err)
	}
	var es EntityStatement
	err = json.Unmarshal(tokenJSON, &es)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal entity statement: %w", err)
	}
	return &es, nil
}
