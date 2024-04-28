package oauth2server

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/gematik/zero-lab/pkg/gemidp"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gopkg.in/yaml.v3"
)

type Config struct {
	baseDir              string
	Issuer               string                `yaml:"issuer"`
	SignPrivateKeyPath   string                `yaml:"sign_private_key_path"`
	EncPublicKeyPath     string                `yaml:"enc_public_key_path"`
	ScopesSupported      []string              `yaml:"scopes_supported"`
	MetadataTemplate     Metadata              `yaml:"metadata_template"`
	OidcProviders        []oidc.Config         `yaml:"oidc_providers"`
	GematikIdp           []gemidp.ClientConfig `yaml:"gematik_idp"`
	ClientsPolicyPath    string                `yaml:"clients_policy_path"`
	OidfRelyingPartyPath string                `yaml:"oidf_relying_party_path"`
}

func LoadConfigFile(path string) (*Config, error) {

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	expanded := os.ExpandEnv(string(content))

	cfg := new(Config)
	cfg.baseDir = filepath.Dir(path)

	err = yaml.Unmarshal([]byte(expanded), cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config file: %w", err)
	}

	return cfg, nil
}

func NewServerFromConfigFile(path string) (*Server, error) {
	cfg, err := LoadConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}

	return New(cfg)
}

func New(cfg *Config) (*Server, error) {
	s := &Server{
		Metadata:        cfg.MetadataTemplate,
		identityIssuers: make([]oidc.Client, 0),
	}

	for _, c := range cfg.OidcProviders {
		client, err := oidc.NewClient(&c)
		if err != nil {
			return nil, fmt.Errorf("create oidc client: %w", err)
		}
		slog.Info("created oidc client", "issuer", client.Issuer())
		s.identityIssuers = append(s.identityIssuers, client)
	}

	s.Metadata.Issuer = cfg.Issuer
	s.Metadata.ScopesSupported = cfg.ScopesSupported

	// set urls explicitly using the issuer
	s.Metadata.AuthorizationEndpoint = fmt.Sprint(s.Metadata.Issuer, "/auth")
	s.Metadata.TokenEndpoint = fmt.Sprint(s.Metadata.Issuer, "/token")
	s.Metadata.JwksURI = fmt.Sprint(s.Metadata.Issuer, "/jwks")

	// set supported parameters explicitly
	s.Metadata.ResponseTypesSupported = []string{"code"}
	s.Metadata.ResponseModesSupported = []string{"query"}
	s.Metadata.GrantTypesSupported = []string{"authorization_code"}
	s.Metadata.TokenEndpointAuthMethodsSupported = []string{"none"}
	s.Metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	s.Metadata.CodeChallengeMethodsSupported = []string{"S256"}

	// load signing key
	sigPrK, err := loadJwkFromPem(cfg.SignPrivateKeyPath)
	if err != nil {
		slog.Warn("failed to load signing key, will create random", "path", cfg.SignPrivateKeyPath)
		sigPrK, err = util.RandomJWK()
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
	}
	s.sigPrK = sigPrK

	// create JWK set
	sigPuK, err := sigPrK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	s.jwks = jwk.NewSet()
	s.jwks.AddKey(sigPuK)

	// load encryption key
	encPuK, err := loadJwkFromPem(cfg.EncPublicKeyPath)
	if err != nil {
		slog.Warn("failed to load encryption key, will create random", "path", cfg.EncPublicKeyPath)
		encPrK, err := util.RandomJWK()
		if err != nil {
			return nil, fmt.Errorf("generate encryption key: %w", err)
		}
		encPuK, err = encPrK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
	}
	s.encPuK = encPuK

	// load clients policy
	filename := filepath.Join(cfg.baseDir, cfg.ClientsPolicyPath)
	s.clientsPolicy, err = LoadClientsPolicy(filename)
	if err != nil {
		return nil, fmt.Errorf("load clients policy: %w", err)
	}
	slog.Info("loaded clients policy", "path", filename)

	// session store is mock atm
	s.sessionStore = newMockSessionStore()

	// if relying party config is provided, load it
	if cfg.OidfRelyingPartyPath != "" {
		filename = filepath.Join(cfg.baseDir, cfg.OidfRelyingPartyPath)
		s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfigFile(filename)
		if err != nil {
			return nil, fmt.Errorf("load relying party config: %w", err)
		}
		slog.Info("loaded relying party config", "path", filename)
	}

	// configure gematik IDP-Dienst client if configured
	for _, c := range cfg.GematikIdp {
		client, err := gemidp.NewClientFromConfig(c)
		if err != nil {
			return nil, fmt.Errorf("create gematik IDP-Dienst client: %w", err)
		}
		slog.Info("created gematik IDP-Dienst client", "issuer", client.Issuer())
		s.identityIssuers = append(s.identityIssuers, client)
	}

	return s, nil
}

func loadJwkFromPem(path string) (jwk.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return jwk.ParseKey(data, jwk.WithPEM(true))
}
