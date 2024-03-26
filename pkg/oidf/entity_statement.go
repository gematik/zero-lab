package oidf

import (
	"encoding/json"
	"fmt"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type UserType string

const (
	UserTypeIP  UserType = "IP"  // Insured Person
	UserTypeHP  UserType = "HP"  // Health Professional
	UserTypeHCI UserType = "HCI" // Health Care Institution
)

type EntityStatement struct {
	ExpiresAt      int64      `json:"exp"`
	IssuedAt       int64      `json:"iat"`
	Issuer         string     `json:"iss"`
	Subject        string     `json:"sub"`
	AuthorityHints []string   `json:"authority_hints"`
	Jwks           *util.Jwks `json:"jwks"`
	Metadata       *Metadata  `json:"metadata"`
}

type Metadata struct {
	OpenidRelyingParty *OpenIDRelyingPartyMetadata `json:"openid_relying_party"`
	OpenidProvider     *OpenIDProviderMetadata     `json:"openid_provider"`
	FederationEntity   *FederationEntityMetadata   `json:"federation_entity"`
}

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
	SignedJwksUri                              string     `json:"signed_jwks_uri"`
	SubjectTypesSupported                      []string   `json:"subject_types_supported"`
	TokenEndpoint                              string     `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported          []string   `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string   `json:"token_endpoint_auth_signing_alg_values_supported"`
	UserTypeSupported                          []UserType `json:"user_type_supported"`
}

type OpenIDRelyingPartyMetadata struct {
	SignedJwksUri                      string     `json:"signed_jwks_uri,omitempty"`
	Jwks                               *util.Jwks `json:"jwks"`
	OrganizationName                   string     `json:"organization_name"`
	ClientName                         string     `json:"client_name"`
	LogoURI                            string     `json:"logo_uri"`
	RedirectURIs                       []string   `json:"redirect_uris"`
	ResponseTypes                      []string   `json:"response_types"`
	ClientRegistrationTypes            []string   `json:"client_registration_types"`
	GrantTypes                         []string   `json:"grant_types"`
	RequirePushedAuthorizationRequests bool       `json:"require_pushed_authorization_requests"`
	TokenEndpointAuthMethod            string     `json:"token_endpoint_auth_method"`
	DefaultACRValues                   []string   `json:"default_acr_values"`
	IDTokenSignedResponseAlg           string     `json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg        string     `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc        string     `json:"id_token_encrypted_response_enc"`
	Scope                              string     `json:"scope"`
}

type FederationEntityMetadata struct {
	Name                    string   `json:"name,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	HomepageURI             string   `json:"homepage_uri,omitempty"`
	FederationFetchEndpoint string   `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint  string   `json:"federation_list_endpoint,omitempty"`
	IdpListEndpoint         string   `json:"idp_list_endpoint,omitempty"`
}

func tokenToEntityStatement(token jwt.Token) (*EntityStatement, error) {
	tokenJson, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal token: %w", err)
	}
	var es EntityStatement
	err = json.Unmarshal(tokenJson, &es)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal entity statement: %w", err)
	}
	return &es, nil
}
