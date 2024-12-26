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
	Address           string             `yaml:"address"`
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

	return cfg, nil
}

type PDP struct {
	Address     string
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

	if config.Address == "" {
		pdp.Address = ":8011"
	} else {
		pdp.Address = config.Address
	}

	return pdp, nil
}
