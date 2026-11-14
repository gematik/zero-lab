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
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/openid/providers"
)

// Config is the authorization_server section of pdp.yaml. Relative paths resolve against BaseDir.
type Config struct {
	BaseDir           string           `yaml:"-"`
	Issuer            string           `yaml:"issuer"`
	SignJwkPath       string           `yaml:"sign_jwk_path"`
	SigningKey        *SigningKey      `yaml:"-"`
	ScopesSupported   []string         `yaml:"scopes_supported"`
	MetadataTemplate  ExtendedMetadata `yaml:"metadata_template"`
	DefaultIDPIss     string           `yaml:"default_idp_iss"`
	ClientsPolicyPath string           `yaml:"clients_policy_path"`
	Products          []Product        `yaml:"products"`
	Clients           []Client         `yaml:"clients"`
	Endpoints         EndpointsConfig  `yaml:"endpoints"`
	// Providers and RelyingParty are built by the caller from the providers file; nil means none.
	Providers    *providers.Set     `yaml:"-"`
	RelyingParty *oidf.RelyingParty `yaml:"-"`
	// Sessions, NonceRedemptions and Replays are the state replicas share: authorization sessions, the single
	// use of client-assertion nonces, and the DPoP proofs accepted (RFC 9449 Section 11.1). The command picks the
	// backend and builds them; the server refuses to start without any of them rather than keep one in its own
	// memory, which another replica would not see.
	Sessions         SessionStore      `yaml:"-"`
	NonceRedemptions nonce.Redemptions `yaml:"-"`
	Replays          dpop.Replays      `yaml:"-"`
	// NonceKeys seal the client-assertion nonces; all replicas that share the stores share them as well.
	NonceKeys nonce.Keys `yaml:"-"`
	// Clock is the time tokens, sessions, nonces and DPoP proofs are issued and judged at; nil means the
	// system clock.
	Clock func() time.Time `yaml:"-"`
}

// EndpointsConfig holds the paths the server mounts its endpoints at. An empty field takes its default.
type EndpointsConfig struct {
	AuthorizationServerMetadata string `yaml:"authorization_server_metadata"`
	Jwks                        string `yaml:"jwks"`
	Nonce                       string `yaml:"nonce"`
	OpenIDProviders             string `yaml:"openid_providers"`
	Authorization               string `yaml:"authorization"`
	PushedAuthorizationRequest  string `yaml:"pushed_authorization_request"`
	OPCallback                  string `yaml:"op_callback"`
	IDPDCallback                string `yaml:"idpd_callback"`
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
	if s.IDPDCallback == "" {
		s.IDPDCallback = basePath + "/idpd-callback"
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

// Validate reports what a configuration cannot do without. What needs I/O is checked when it is loaded.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return errors.New("issuer is required")
	}
	for i, product := range c.Products {
		if product.ProductID == "" {
			return fmt.Errorf("products[%d]: product_id is required", i)
		}
	}
	for i, client := range c.Clients {
		switch {
		case client.ClientID == "":
			return fmt.Errorf("clients[%d]: client_id is required", i)
		case client.ProductID == "":
			return fmt.Errorf("clients[%d]: product_id is required", i)
		case len(client.PublicJWK) == 0:
			return fmt.Errorf("clients[%d]: public_jwk is required", i)
		}
	}
	return nil
}
