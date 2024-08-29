package authzserver

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"

	"github.com/gematik/zero-lab/go/libzero/gemidp"
	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/gematik/zero-lab/go/libzero/oidc"
	"github.com/gematik/zero-lab/go/libzero/oidf"
	"github.com/gematik/zero-lab/go/libzero/util"
	"github.com/go-playground/validator/v10"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"gopkg.in/yaml.v3"
)

type Config struct {
	BaseDir              string                `yaml:"-"`
	Issuer               string                `yaml:"issuer" validate:"required"`
	SignPrivateKeyPath   string                `yaml:"sign_private_key_path"`
	EncPublicKeyPath     string                `yaml:"enc_public_key_path"`
	ScopesSupported      []string              `yaml:"scopes_supported"`
	MetadataTemplate     oauth2.ServerMetadata `yaml:"metadata_template"`
	OidcProviders        []oidc.Config         `yaml:"oidc_providers" validate:"dive"`
	GematikIdp           []gemidp.ClientConfig `yaml:"gematik_idp"`
	ClientsPolicyPath    string                `yaml:"clients_policy_path"`
	ClientsPolicy        *ClientsPolicy        `yaml:"clients_policy"`
	OidfRelyingPartyPath string                `yaml:"oidf_relying_party_path"`
}

func LoadConfigFile(path string) (*Config, error) {

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	expanded := os.ExpandEnv(string(content))

	cfg := new(Config)
	cfg.BaseDir = filepath.Dir(path)

	err = yaml.Unmarshal([]byte(expanded), cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config file: %w", err)
	}

	return cfg, nil
}

func NewFromConfigFile(path string) (*Server, error) {
	cfg, err := LoadConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}

	return New(cfg)
}

func absPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func New(cfg *Config) (*Server, error) {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return fld.Tag.Get("yaml")
	})

	s := &Server{
		Metadata: ExtendedMetadata{
			ServerMetadata: cfg.MetadataTemplate,
		},
		identityIssuers: make([]oidc.Client, 0),
	}

	for _, c := range cfg.OidcProviders {
		client, err := oidc.NewClient(c)
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
	s.Metadata.OpenidProvidersEndpoint = fmt.Sprint(s.Metadata.Issuer, "/openid-providers")

	// set supported parameters explicitly
	s.Metadata.ResponseTypesSupported = []string{"code"}
	s.Metadata.ResponseModesSupported = []string{"query"}
	s.Metadata.GrantTypesSupported = []string{
		GrantTypeAuthorizationCode,
		GrantTypeRefreshToken,
		GrantTypeClientCredentials,
		GrantTypeJWTBearer,
	}
	s.Metadata.TokenEndpointAuthMethodsSupported = []string{"none"}
	s.Metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	s.Metadata.CodeChallengeMethodsSupported = []string{"S256"}

	// load signing key
	sigPrK, err := loadJwkFromPem(absPath(cfg.BaseDir, cfg.SignPrivateKeyPath))
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
	encPuK, err := loadJwkFromPem(absPath(cfg.BaseDir, cfg.EncPublicKeyPath))
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
	if cfg.ClientsPolicyPath != "" {
		filename := absPath(cfg.BaseDir, cfg.ClientsPolicyPath)
		s.clientsPolicy, err = LoadClientsPolicy(filename)
		if err != nil {
			return nil, fmt.Errorf("load clients policy: %w", err)
		}
		slog.Info("loaded clients policy", "path", filename)
	}
	// session store is mock atm
	s.sessionStore = newMockSessionStore()

	// if relying party config is provided, load it
	if cfg.OidfRelyingPartyPath != "" {
		filename := absPath(cfg.BaseDir, cfg.OidfRelyingPartyPath)
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
