package oauth2server

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
)

type Config struct {
	BaseDir                    string                   `yaml:"-"`
	Issuer                     string                   `yaml:"issuer" validate:"required"`
	SignPrivateKeyPath         string                   `yaml:"sign_private_key_path"`
	EncPublicKeyPath           string                   `yaml:"enc_public_key_path"`
	ScopesSupported            []string                 `yaml:"scopes_supported"`
	MetadataTemplate           ExtendedMetadata         `yaml:"metadata_template"`
	DefaultOPIssuer            string                   `yaml:"default_op_issuer"`
	OidcProviders              []oidc.Config            `yaml:"oidc_providers" validate:"dive"`
	GematikIdp                 []gemidp.ClientConfig    `yaml:"gematik_idp" validate:"dive"`
	ClientsPolicyPath          string                   `yaml:"clients_policy_path"`
	Clients                    []ClientMetadata         `yaml:"clients" validate:"omitempty,dive"`
	OidfRelyingPartyConfigPath string                   `yaml:"oidf_relying_party_path"`
	OidfRelyingPartyConfig     *oidf.RelyingPartyConfig `yaml:"oidf_relying_party" validate:"omitempty"`
	Endpoints                  EndpointsConfig          `yaml:"endpoints"`
	// some values maybe set  programmatically
	NonceService              nonce.Service
	VerifyClientAssertionFunc VerifyClientAssertionFunc
}

type EndpointsConfig struct {
	AuthorizationServerMetadata string `yaml:"authorization_server_metadata"`
	Jwks                        string `yaml:"jwks"`
	Nonce                       string `yaml:"nonce"`
	OpenIDProviders             string `yaml:"openid_providers"`
	Authorization               string `yaml:"authorization"`
	Par                         string `yaml:"par"`
	OPCallback                  string `yaml:"op_callback"`
	GemIDPCallback              string `yaml:"gemidp_callback"`
	Token                       string `yaml:"token"`
	EntityStatement             string `yaml:"entity_statement"`
}

func (s *EndpointsConfig) applyDefaults(baseURI *url.URL) {
	basePath := strings.TrimRight(baseURI.Path, "/")
	if basePath == "/" {
		basePath = ""
	}

	if s.AuthorizationServerMetadata == "" {
		s.AuthorizationServerMetadata = basePath + "/.well-known/oauth-authorization-server"
	}
	if s.Jwks == "" {
		s.Jwks = basePath + "/jwks"
	}
	if s.Nonce == "" {
		s.Nonce = basePath + "/nonce"
	}
	if s.OpenIDProviders == "" {
		s.OpenIDProviders = basePath + "/openid-providers"
	}
	if s.Authorization == "" {
		s.Authorization = basePath + "/auth"
	}
	if s.Par == "" {
		s.Par = basePath + "/par"
	}
	if s.OPCallback == "" {
		s.OPCallback = basePath + "/op-callback"
	}
	if s.GemIDPCallback == "" {
		s.GemIDPCallback = basePath + "/gemidp-callback"
	}
	if s.Token == "" {
		s.Token = basePath + "/token"
	}
	if s.EntityStatement == "" {
		s.EntityStatement = basePath + "/.well-known/openid-federation"
	}
}

func absPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
