package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
)

type ParameterOption func(params url.Values)

func WithAlternateRedirectURI(redirectUri string) ParameterOption {
	return func(params url.Values) {
		if redirectUri != "" {
			params.Set("redirect_uri", redirectUri)
		}
	}
}

func WithOpenidProviderIssuer(issuer string) ParameterOption {
	return func(params url.Values) {
		if issuer != "" {
			params.Set("op_issuer", issuer)
		}
	}
}

type Client interface {
	AuthCodeURL(state, nonce, verifier string, opts ...ParameterOption) (string, error)
	Exchange(code, verifier string, opts ...ParameterOption) (*TokenResponse, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

func GenerateCodeVerifier() string {
	n := 128
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic("Random number generation failed")
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func S256ChallengeFromVerifier(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

// OAuth2 Authorization Server Metadata
// See https://datatracker.ietf.org/doc/html/rfc8414
type ServerMetadata struct {
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
