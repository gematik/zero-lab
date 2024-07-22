package pep

import (
	"fmt"
	"os"
	"regexp"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Address          string                  `yaml:"address" validate:"required"`
	AuthzIssuer      string                  `yaml:"authz_issuer" validate:"required"`
	SecurityProfiles []SecurityProfileConfig `yaml:"security_profiles" validate:"required"`
	Resources        []ResourceConfig        `yaml:"resources" validate:"required"`
}

type SecurityProfileConfig struct {
	Name string `yaml:"name" validate:"required"`
}

type ResourceConfig struct {
	Pattern         *regexp.Regexp `yaml:"pattern" validate:"required"`
	Destination     string         `yaml:"destination" validate:"required"`
	SecurityProfile string         `yaml:"security_profile" validate:"required"`
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
