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

package epa

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert/yaml"
)

type Config struct {
	BaseDir      string        `yaml:"-"` // set to the base directory of config files when loading
	ProxyConfigs []ProxyConfig `yaml:"proxies" validate:"required,dive,required"`
}

func (c *Config) GetProxyConfigByName(name string) (*ProxyConfig, bool) {
	for _, proxy := range c.ProxyConfigs {
		if proxy.Name == name {
			return &proxy, true
		}
	}
	return nil, false
}

func (c *Config) GetDefaultProxyConfig() (*ProxyConfig, bool) {
	if len(c.ProxyConfigs) > 0 {
		return &c.ProxyConfigs[0], true
	}
	return nil, false
}

func LoadConfigFile(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// expand environment variables $
	expanded := os.ExpandEnv(string(content))

	cfg := new(Config)
	cfg.BaseDir = filepath.Dir(path)

	err = yaml.Unmarshal([]byte(expanded), cfg)
	if err != nil {
		return nil, fmt.Errorf("decode config file: %w", err)
	}

	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return fld.Tag.Get("yaml")
	})

	err = validate.Struct(cfg)
	if err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	for pc := range cfg.ProxyConfigs {
		cfg.ProxyConfigs[pc].BaseDir = cfg.BaseDir
	}

	return cfg, nil
}
