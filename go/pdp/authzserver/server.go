package authzserver

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/pep"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/valkey-io/valkey-go"
	"gopkg.in/yaml.v3"
)

type Server struct {
	Metadata                  ExtendedMetadata
	nonProdMode               bool
	endpointPaths             *EndpointsConfig
	clientsRegistry           ClientsRegistry
	openidProviders           []oidc.Client
	oidfRelyingParty          *oidf.RelyingParty
	defaultOPIssuer           string
	clientsPolicy             *ClientsPolicy
	sessionStore              AuthzServerSessionStore
	sigPrK                    jwk.Key
	jwks                      jwk.Set
	tokenVerifier             *pep.PEP
	nonceService              nonce.Service
	verifyClientAssertionFunc VerifyClientAssertionFunc
	dpopMaxAge                time.Duration
	valkey                    valkey.Client
}

func NewFromConfigFile(filename string) (*Server, error) {
	cfg := new(Config)
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file '%s': %w", filename, err)
	}
	if err := yaml.Unmarshal(yamlFile, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config file '%s': %w", filename, err)
	}

	return New(*cfg)
}

func New(cfg Config) (*Server, error) {
	s := &Server{
		Metadata:        cfg.MetadataTemplate,
		openidProviders: make([]oidc.Client, 0),
		nonProdMode:     cfg.NonProdMode,
	}

	if s.nonProdMode {
		slog.Warn("Authorization server is running in non-production mode")
	}

	if err := s.initValkey(cfg); err != nil {
		return nil, err
	}

	issuerUrl, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URI: %w", err)
	}
	s.endpointPaths = &cfg.Endpoints
	s.endpointPaths.applyDefaults(issuerUrl)

	if err := s.initOpenidProviders(cfg); err != nil {
		return nil, err
	}

	s.initMetadata(issuerUrl, cfg)
	s.defaultOPIssuer = cfg.DefaultOPIssuer

	// load clients registry
	if len(cfg.Clients) > 0 {
		s.clientsRegistry = &StaticClientsRegistry{Clients: cfg.Clients}
	} else {
		slog.Warn("no OAuth2 clients configured")
	}

	if err := s.initSigningKey(cfg); err != nil {
		return nil, err
	}

	// Reuse the PEP as a token verifier for the server's own tokens (e.g. introspection). No
	// resource is configured, so the audience is not restricted to a single resource server.
	if s.tokenVerifier, err = pep.NewBuilder().WithJWKSet(s.jwks).Build(); err != nil {
		return nil, fmt.Errorf("create token verifier: %w", err)
	}

	if err := s.initClientsPolicy(cfg); err != nil {
		return nil, err
	}

	// session store is mock atm
	s.sessionStore = newMockSessionStore()

	if err := s.initRelyingParty(cfg); err != nil {
		return nil, err
	}

	if err := s.initGematikIdp(cfg); err != nil {
		return nil, err
	}

	// TODO: configure nonce service
	s.nonceService, err = nonce.NewHashicorpNonceService()
	if err != nil {
		return nil, fmt.Errorf("create nonce service: %w", err)
	}

	// TODO: configure client assertion verification function
	if cfg.VerifyClientAssertionFunc != nil {
		s.verifyClientAssertionFunc = cfg.VerifyClientAssertionFunc
	}

	// TODO: configure DPoP validity period
	s.dpopMaxAge = 5 * time.Minute

	return s, nil
}

// initValkey creates the optional Valkey client used for distributed state.
func (s *Server) initValkey(cfg Config) error {
	if cfg.ValkeyConfig == nil {
		return nil
	}
	opt := valkey.ClientOption{
		InitAddress: []string{fmt.Sprintf("%s:%d", cfg.ValkeyConfig.Host, cfg.ValkeyConfig.Port)},
	}
	if cfg.ValkeyConfig.Username != "" {
		opt.Username = cfg.ValkeyConfig.Username
	}
	if cfg.ValkeyConfig.UseTLS {
		opt.TLSConfig = &tls.Config{}
	}
	var err error
	if s.valkey, err = valkey.NewClient(opt); err != nil {
		return fmt.Errorf("create valkey client: %w", err)
	}
	return nil
}

// initOpenidProviders configures the statically-listed OIDC providers.
func (s *Server) initOpenidProviders(cfg Config) error {
	for _, c := range cfg.OidcProviders {
		client, err := oidc.NewClient(c)
		if err != nil {
			return fmt.Errorf("create oidc client: %w", err)
		}
		slog.Info("created oidc client", "issuer", client.Issuer())
		s.openidProviders = append(s.openidProviders, client)
	}
	return nil
}

// initMetadata fills the authorization-server metadata document (RFC 8414).
func (s *Server) initMetadata(issuerUrl *url.URL, cfg Config) {
	s.Metadata.Issuer = cfg.Issuer
	s.Metadata.ScopesSupported = cfg.ScopesSupported

	s.Metadata.AuthorizationEndpoint = buildURI(issuerUrl, s.endpointPaths.Authorization)
	s.Metadata.TokenEndpoint = buildURI(issuerUrl, s.endpointPaths.Token)
	s.Metadata.IntrospectionEndpoint = buildURI(issuerUrl, s.endpointPaths.Introspection)
	s.Metadata.IntrospectionEndpointAuthMethodsSupported = []string{"client_secret_basic", "none"}
	s.Metadata.JwksURI = buildURI(issuerUrl, s.endpointPaths.Jwks)
	s.Metadata.OpenidProvidersEndpoint = buildURI(issuerUrl, s.endpointPaths.OpenIDProviders)
	s.Metadata.NonceEndpoint = buildURI(issuerUrl, s.endpointPaths.Nonce)
	s.Metadata.PushedAuthorizationRequestEndpoint = buildURI(issuerUrl, s.endpointPaths.PushedAuthorizationRequest)
	s.Metadata.RegistrationEndpoint = buildURI(issuerUrl, s.endpointPaths.Registration)

	s.Metadata.ResponseTypesSupported = []string{"code"}
	s.Metadata.ResponseModesSupported = []string{"query"}
	s.Metadata.GrantTypesSupported = []string{
		GrantTypeAuthorizationCode,
		GrantTypeRefreshToken,
		GrantTypeClientCredentials,
		GrantTypeJWTBearer,
	}
	s.Metadata.TokenEndpointAuthMethodsSupported = []string{"none", "client_secret_basic"}
	s.Metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	s.Metadata.CodeChallengeMethodsSupported = []string{"S256"}
}

// initSigningKey loads the signing JWK (or generates a random one) and builds the JWK set.
func (s *Server) initSigningKey(cfg Config) error {
	sigPrK, err := loadJwkFromFile(absPath(cfg.BaseDir, cfg.SignJwkPath))
	if err != nil {
		slog.Warn("failed to load signing key, will create random", "path", cfg.SignJwkPath, "error", err)
		if sigPrK, err = GenerateRandomJwk(); err != nil {
			return fmt.Errorf("generate signing key: %w", err)
		}
	}
	s.sigPrK = sigPrK

	sigPuK, err := sigPrK.PublicKey()
	if err != nil {
		return fmt.Errorf("get public key: %w", err)
	}
	s.jwks = jwk.NewSet()
	s.jwks.AddKey(sigPuK)
	return nil
}

func loadJwkFromFile(filename string) (jwk.Key, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read signing key file '%s': %w", filename, err)
	}
	return jwk.ParseKey(bytes)
}

// initClientsPolicy loads the optional clients policy file.
func (s *Server) initClientsPolicy(cfg Config) error {
	if cfg.ClientsPolicyPath == "" {
		return nil
	}
	filename := absPath(cfg.BaseDir, cfg.ClientsPolicyPath)
	var err error
	if s.clientsPolicy, err = LoadClientsPolicy(filename); err != nil {
		return fmt.Errorf("load clients policy: %w", err)
	}
	slog.Info("loaded clients policy", "path", filename)
	return nil
}

// initRelyingParty configures the optional OpenID Federation relying party.
func (s *Server) initRelyingParty(cfg Config) error {
	var err error
	switch {
	case cfg.OidfRelyingPartyConfigPath != "":
		filename := absPath(cfg.BaseDir, cfg.OidfRelyingPartyConfigPath)
		if s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfigFile(filename); err != nil {
			return fmt.Errorf("load relying party config: %w", err)
		}
		slog.Info("loaded relying party config", "path", filename)
	case cfg.OidfRelyingPartyConfig != nil:
		cfg.OidfRelyingPartyConfig.BaseDir = cfg.BaseDir
		if s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfig(cfg.OidfRelyingPartyConfig); err != nil {
			return fmt.Errorf("create relying party: %w", err)
		}
	}
	return nil
}

// initGematikIdp configures the optional gematik IDP-Dienst clients.
func (s *Server) initGematikIdp(cfg Config) error {
	for _, c := range cfg.GematikIdp {
		client, err := gemidp.NewClientFromConfig(c)
		if err != nil {
			return fmt.Errorf("create gematik IDP-Dienst client: %w", err)
		}
		slog.Info("created gematik IDP-Dienst client", "issuer", client.Issuer())
		s.openidProviders = append(s.openidProviders, client)
	}
	return nil
}

// MetadataEndpoint serves the authorization server metadata document (RFC 8414).
func (s *Server) MetadataEndpoint(w http.ResponseWriter, r *http.Request) error {
	return writeJSON(w, http.StatusOK, s.Metadata)
}

// JWKS serves the JSON Web Key Set for the server.
func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) error {
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
