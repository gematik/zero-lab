package pep

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Address          string                  `yaml:"address" validate:"required"`
	AuthzIssuer      string                  `yaml:"authz_issuer" validate:"required"`
	SecurityProfiles []SecurityProfileConfig `yaml:"security_profiles" validate:"required"`
}

type SecurityProfileConfig struct {
	Name string `yaml:"name" validate:"required"`
}

func New(config Config) (*PEP, error) {
	p := &PEP{
		httpClient:  http.Client{},
		authzIssuer: config.AuthzIssuer,
	}

	err := p.reloadMetadata(context.Background())
	if err != nil {
		return nil, err
	}

	return p, nil
}

func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal config file: %w", err)
	}

	// validate config
	validate := validator.New()
	err = validate.Struct(config)
	if err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

func NewFromConfigFile(path string) (*PEP, error) {
	config, err := LoadConfigFile(path)
	if err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}

	return New(*config)
}
