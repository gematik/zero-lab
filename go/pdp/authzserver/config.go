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
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
)

type Config struct {
	BaseDir                    string                   `yaml:"-"`
	Issuer                     string                   `yaml:"issuer" validate:"required"`
	SignJwkPath                string                   `yaml:"sign_jwk_path"`
	ScopesSupported            []string                 `yaml:"scopes_supported"`
	MetadataTemplate           ExtendedMetadata         `yaml:"metadata_template"`
	DefaultIDPIss              string                   `yaml:"default_idp_iss"`
	OidcProviders              []oidc.Config            `yaml:"oidc_providers" validate:"dive"`
	GematikIdp                 []gemidp.ClientConfig    `yaml:"gematik_idp" validate:"dive"`
	ClientsPolicyPath          string                   `yaml:"clients_policy_path"`
	Products                   []Product                `yaml:"products" validate:"omitempty,dive"`
	Clients                    []Client                 `yaml:"clients" validate:"omitempty,dive"`
	OidfRelyingPartyConfigPath string                   `yaml:"oidf_relying_party_path"`
	OidfRelyingPartyConfig     *oidf.RelyingPartyConfig `yaml:"oidf_relying_party" validate:"omitempty"`
	Endpoints                  EndpointsConfig          `yaml:"endpoints" validate:"omitempty"`
	// some values may be set programmatically
	NonceService nonce.Service
	// Store is the kv backend for sessions + nonces. The command opens the Postgres store from
	// DATABASE_URL (it owns the driver dependency) and injects it here; nil ⇒ an in-memory store
	// (tests and dev).
	Store kv.Store
}

type EndpointsConfig struct {
	AuthorizationServerMetadata string `yaml:"authorization_server_metadata"`
	Jwks                        string `yaml:"jwks"`
	Nonce                       string `yaml:"nonce"`
	OpenIDProviders             string `yaml:"openid_providers"`
	Authorization               string `yaml:"authorization"`
	PushedAuthorizationRequest  string `yaml:"pushed_authorization_request"`
	OPCallback                  string `yaml:"op_callback"`
	GemIDPCallback              string `yaml:"gemidp_callback"`
	Token                       string `yaml:"token"`
	Introspection               string `yaml:"introspection"`
	EntityStatement             string `yaml:"entity_statement"`
	Registration                string `yaml:"registration"`
}

func (s *EndpointsConfig) applyDefaults(baseURI *url.URL) {
	basePath := strings.TrimRight(baseURI.Path, "/")
	if basePath == "/" {
		basePath = ""
	}

	if s.AuthorizationServerMetadata == "" {
		s.AuthorizationServerMetadata = "/.well-known/oauth-authorization-server"
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
	if s.PushedAuthorizationRequest == "" {
		s.PushedAuthorizationRequest = basePath + "/par"
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
	if s.Introspection == "" {
		s.Introspection = basePath + "/introspect"
	}
	if s.EntityStatement == "" {
		s.EntityStatement = "/.well-known/openid-federation"
	}
	if s.Registration == "" {
		s.Registration = basePath + "/register"
	}
}

func absPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}
