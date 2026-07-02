package pdp

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v2"
)

type Config struct {
	BindAddress       string             `yaml:"bind_address"`
	BaseDir           string             `yaml:"-"`
	AuthzServerConfig authzserver.Config `yaml:"authorization_server" validate:"required"`
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

	cfg.AuthzServerConfig.BaseDir = cfg.BaseDir

	// Providers come from a shared openid-providers.yaml (same format pep uses). Path from
	// PDP_OPENID_PROVIDERS_PATH, else openid-providers.yaml next to the config file. When present it is the
	// source of OIDC/gemidp/OIDF providers; absent, any inline providers in pdp.yaml are kept (back-compat).
	providersPath := os.Getenv("PDP_OPENID_PROVIDERS_PATH")
	if providersPath == "" {
		providersPath = filepath.Join(cfg.BaseDir, defaultOpenidProvidersFile)
	}
	if _, statErr := os.Stat(providersPath); statErr == nil {
		oidcs, gemidps, rp, err := LoadOpenidProviders(providersPath)
		if err != nil {
			return nil, err
		}
		cfg.AuthzServerConfig.OidcProviders = oidcs
		cfg.AuthzServerConfig.GematikIdp = gemidps
		if rp != nil {
			rp.BaseDir = filepath.Dir(providersPath)
			cfg.AuthzServerConfig.OidfRelyingPartyConfig = rp
		}
	} else if os.Getenv("PDP_OPENID_PROVIDERS_PATH") != "" {
		return nil, fmt.Errorf("PDP_OPENID_PROVIDERS_PATH %q: %w", providersPath, statErr)
	}

	return cfg, nil
}

type PDP struct {
	BindAddress string
	AuthzServer *authzserver.Server
}

func New(config Config) (*PDP, error) {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return fld.Tag.Get("yaml")
	})

	err := validate.Struct(config)
	if err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	authzServer, err := authzserver.New(config.AuthzServerConfig)
	if err != nil {
		return nil, fmt.Errorf("create authorization server: %w", err)
	}

	pdp := &PDP{
		AuthzServer: authzServer,
	}

	if config.BindAddress == "" {
		pdp.BindAddress = ":8011"
	} else {
		pdp.BindAddress = config.BindAddress
	}

	return pdp, nil
}
