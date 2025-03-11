package oauth2server

// OAuth2 Authorization Server Metadata
// See https://datatracker.ietf.org/doc/html/rfc8414
type Metadata struct {
	Issuer                                             string   `json:"issuer" yaml:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint" yaml:"token_endpoint"`
	JwksURI                                            string   `json:"jwks_uri,omitempty" yaml:"jwks_uri"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty" yaml:"registration_endpoint"`
	ScopesSupported                                    []string `json:"scopes_supported" yaml:"scopes_supported"`
	ResponseTypesSupported                             []string `json:"response_types_supported" yaml:"response_types_supported"`
	ResponseModesSupported                             []string `json:"response_modes_supported" yaml:"response_modes_supported"`
	GrantTypesSupported                                []string `json:"grant_types_supported" yaml:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported" yaml:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported" yaml:"token_endpoint_auth_signing_alg_values_supported"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty" yaml:"service_documentation"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty" yaml:"ui_locales_supported"`
	OPPolicyURI                                        string   `json:"op_policy_uri,omitempty" yaml:"op_policy_uri"`
	OPTosURI                                           string   `json:"op_tos_uri,omitempty" yaml:"op_tos_uri"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty" yaml:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty" yaml:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty" yaml:"revocation_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty" yaml:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty" yaml:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty" yaml:"introspection_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported" yaml:"code_challenge_methods_supported"`
}

// Extend the standard OAuth2 server metadata from RFC8414
type ExtendedMetadata struct {
	Metadata
	NonceEndpoint           string `json:"nonce_endpoint"`
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
}
