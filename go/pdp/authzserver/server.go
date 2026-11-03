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

// Package authzserver implements the PDP's OAuth 2.0 authorization server: pushed authorization requests
// (RFC 9126) with login at an upstream OpenID Provider, private_key_jwt client authentication (RFC 7523),
// DPoP-bound tokens (RFC 9449) and token introspection (RFC 7662).
package authzserver

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/openid/providers"
)

const (
	// defaultSessionTTL bounds a pending authorization session before a policy sets its ExpiresAt.
	defaultSessionTTL = 15 * time.Minute
	// defaultNonceTTL bounds how long an issued replay nonce stays redeemable.
	defaultNonceTTL = 5 * time.Minute
)

// Server is the authorization server. Build it with New.
type Server struct {
	Metadata         ExtendedMetadata
	endpointPaths    *EndpointsConfig
	clientsRegistry  ClientsRegistry
	productsRegistry *ProductsRegistry
	providers        *providers.Set
	oidfRelyingParty *oidf.RelyingParty
	defaultIDPIss    string
	sessionStore     SessionStore
	signer           jose.Signer
	signerKeyID      string
	jwks             *jose.JSONWebKeySet
	nonceService     *nonce.Service
	dpopVerifier     *dpop.Verifier
}

// NewFromConfigFile builds a server from a YAML file holding a Config. Unlike pdp.LoadConfigFile it expands
// no environment variables, and relative paths resolve against the working directory.
func NewFromConfigFile(filename string) (*Server, error) {
	cfg := new(Config)
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file '%s': %w", filename, err)
	}
	if err := decodeYAML(yamlFile, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config file '%s': %w", filename, err)
	}

	return New(*cfg)
}

// New builds a server from cfg. Without Config.Store, sessions and nonces live in process memory, for one
// replica only. It refuses to start without Config.SigningKey: a replica with a key of its own signs tokens
// nobody else can verify. For the same reason it refuses a Store without Config.NonceKeys.
func New(cfg Config) (*Server, error) {
	if cfg.Providers == nil {
		cfg.Providers = providers.New(nil)
	}
	s := &Server{
		Metadata:  cfg.MetadataTemplate,
		providers: cfg.Providers,
	}

	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URI: %w", err)
	}
	s.endpointPaths = &cfg.Endpoints
	s.endpointPaths.applyDefaults(issuerURL)

	s.initMetadata(issuerURL, cfg)
	s.defaultIDPIss = cfg.DefaultIDPIss

	// load clients registry
	if len(cfg.Clients) > 0 {
		if s.clientsRegistry, err = NewStaticClientsRegistry(cfg.Clients); err != nil {
			return nil, fmt.Errorf("load clients registry: %w", err)
		}
	} else {
		slog.Warn("no OAuth2 clients configured")
	}

	if err := s.initSigningKey(cfg); err != nil {
		return nil, err
	}

	if err := s.initProducts(cfg); err != nil {
		return nil, err
	}

	// One kv.Store backs the session store and the nonce service. The caller injects a Postgres-backed
	// store via Config.Store (built in the command, which owns the driver dependency); without it we use
	// an in-memory store (tests and dev).
	store, nonceKeys := cfg.Store, cfg.NonceKeys
	if store == nil {
		store = kv.NewMemory()
		if nonceKeys == nil {
			if nonceKeys, err = nonce.NewEphemeralKeys(); err != nil {
				return nil, fmt.Errorf("nonce keys: %w", err)
			}
		}
	}
	if nonceKeys == nil {
		return nil, errors.New("a store shared by replicas needs NonceKeys: nonces under a per-process key fail at every other replica")
	}
	s.sessionStore = newKVSessionStore(store, defaultSessionTTL)

	s.initRelyingParty(cfg)

	s.nonceService, err = nonce.New(nonceKeys, nonceServicePurpose, defaultNonceTTL, recordNonce(store))
	if err != nil {
		return nil, fmt.Errorf("nonce service: %w", err)
	}

	s.dpopVerifier, err = dpop.NewVerifier(dpop.Config{
		MaxAge: 5 * time.Minute,
		Replay: kv.NewReplayCache(store),
	})
	if err != nil {
		return nil, fmt.Errorf("dpop verifier: %w", err)
	}

	return s, nil
}

// initMetadata fills the authorization-server metadata document (RFC 8414).
func (s *Server) initMetadata(issuerURL *url.URL, cfg Config) {
	s.Metadata.Issuer = cfg.Issuer
	s.Metadata.ScopesSupported = cfg.ScopesSupported

	s.Metadata.AuthorizationEndpoint = buildURI(issuerURL, s.endpointPaths.Authorization)
	s.Metadata.TokenEndpoint = buildURI(issuerURL, s.endpointPaths.Token)
	s.Metadata.IntrospectionEndpoint = buildURI(issuerURL, s.endpointPaths.Introspection)
	s.Metadata.IntrospectionEndpointAuthMethodsSupported = []string{"private_key_jwt"}
	s.Metadata.JwksURI = buildURI(issuerURL, s.endpointPaths.Jwks)
	s.Metadata.OpenidProvidersEndpoint = buildURI(issuerURL, s.endpointPaths.OpenIDProviders)
	s.Metadata.NonceEndpoint = buildURI(issuerURL, s.endpointPaths.Nonce)
	s.Metadata.PushedAuthorizationRequestEndpoint = buildURI(issuerURL, s.endpointPaths.PushedAuthorizationRequest)
	s.Metadata.RequirePushedAuthorizationRequests = true
	s.Metadata.RegistrationEndpoint = buildURI(issuerURL, s.endpointPaths.Registration)

	s.Metadata.ResponseTypesSupported = []string{"code"}
	s.Metadata.ResponseModesSupported = []string{"query"}
	s.Metadata.GrantTypesSupported = []string{
		GrantTypeAuthorizationCode,
		GrantTypeRefreshToken,
		GrantTypeClientCredentials,
	}
	s.Metadata.TokenEndpointAuthMethodsSupported = []string{"private_key_jwt"}
	s.Metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	s.Metadata.CodeChallengeMethodsSupported = []string{"S256"}
}

// initProducts builds the products registry from inline config (products:) and/or the gematik
// clients-policy file (clients_policy_path).
func (s *Server) initProducts(cfg Config) error {
	products := make([]*Product, 0, len(cfg.Products))
	if cfg.ClientsPolicyPath != "" {
		filename := absPath(cfg.BaseDir, cfg.ClientsPolicyPath)
		loaded, err := LoadProductsFile(filename)
		if err != nil {
			return fmt.Errorf("load products file: %w", err)
		}
		products = append(products, loaded...)
		slog.Info("loaded products policy", "path", filename, "count", len(loaded))
	}
	for i := range cfg.Products {
		products = append(products, &cfg.Products[i])
	}
	s.productsRegistry = NewProductsRegistry(products)
	return nil
}

// initRelyingParty configures the optional OpenID Federation relying party.
func (s *Server) initRelyingParty(cfg Config) {
	s.oidfRelyingParty = cfg.RelyingParty

	// Inject the products' oidc_redirect_uri into the served entity statement so the federation accepts the
	// AS callback URLs the products register. oidf stays registry-agnostic — it just runs this func hook.
	if s.oidfRelyingParty != nil && s.productsRegistry != nil {
		registry := s.productsRegistry
		s.oidfRelyingParty.AddEntityStatementHook(func(es *oidf.EntityStatement) {
			if es.Metadata == nil || es.Metadata.OpenidRelyingParty == nil {
				return
			}
			rpMeta := es.Metadata.OpenidRelyingParty
			seen := make(map[string]struct{}, len(rpMeta.RedirectURIs))
			for _, u := range rpMeta.RedirectURIs {
				seen[u] = struct{}{}
			}
			for _, u := range registry.AllOIDCRedirectURIs() {
				if _, ok := seen[u]; ok {
					continue
				}
				seen[u] = struct{}{}
				rpMeta.RedirectURIs = append(rpMeta.RedirectURIs, u)
			}
		})
	}
}

// MetadataEndpoint serves the authorization server metadata document (RFC 8414).
func (s *Server) MetadataEndpoint(w http.ResponseWriter, _ *http.Request) error {
	return writeJSON(w, http.StatusOK, s.Metadata)
}

// JWKS serves the JSON Web Key Set for the server.
func (s *Server) JWKS(w http.ResponseWriter, _ *http.Request) error {
	return writeJSON(w, http.StatusOK, s.jwks)
}

// generateNonce returns a cryptographically secure URL-safe random nonce of the given size.
func generateNonce(size int) string {
	nonceBytes := make([]byte, size)
	if _, err := rand.Read(nonceBytes); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(nonceBytes)
}

func buildURI(baseURL *url.URL, path string) string {
	result := *baseURL
	result.Path = path
	return result.String()
}
