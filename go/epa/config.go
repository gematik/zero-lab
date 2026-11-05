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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stretchr/testify/assert/yaml"
)

// Config is the content of a configuration file: the proxies to run.
type Config struct {
	BaseDir      string        `yaml:"-"` // set to the base directory of config files when loading
	ProxyConfigs []ProxyConfig `yaml:"proxies"`
}

// Validate reports the first thing wrong with the configuration.
func (c *Config) Validate() error {
	if len(c.ProxyConfigs) == 0 {
		return errors.New("proxies: at least one is required")
	}
	for i := range c.ProxyConfigs {
		if err := c.ProxyConfigs[i].Validate(); err != nil {
			return fmt.Errorf("proxies[%d]: %w", i, err)
		}
	}
	return nil
}

// GetProxyConfigByName returns a copy of the proxy configuration called name, if any.
func (c *Config) GetProxyConfigByName(name string) (*ProxyConfig, bool) {
	for _, proxy := range c.ProxyConfigs {
		if proxy.Name == name {
			return &proxy, true
		}
	}
	return nil, false
}

// GetDefaultProxyConfig returns the first proxy configuration, if any.
func (c *Config) GetDefaultProxyConfig() (*ProxyConfig, bool) {
	if len(c.ProxyConfigs) > 0 {
		return &c.ProxyConfigs[0], true
	}
	return nil, false
}

// LoadConfigFile reads the YAML file at path, expands environment variables in it and
// validates the result. Relative paths in it resolve against the file's directory.
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

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	for pc := range cfg.ProxyConfigs {
		cfg.ProxyConfigs[pc].BaseDir = cfg.BaseDir
	}

	return cfg, nil
}

// Validate reports the first thing wrong with the proxy's configuration. It names the setting and never its
// value, which may be a key.
func (c *ProxyConfig) Validate() error {
	switch {
	case c.Name == "":
		return errors.New("name is required")
	case c.Timeout <= 0:
		return errors.New("timeout must be greater than zero")
	case c.VsdmHmacKeyHex == "":
		return errors.New("vsdm_hmac_key_hex is required")
	case c.VsdmHmacKeyID == "":
		return errors.New("vsdm_hmac_key_id is required")
	}
	switch c.Env {
	case EnvDev, EnvTest, EnvRef, EnvProd:
	default:
		return errors.New("env must be dev, test, ref or prod")
	}
	switch c.VAUCertVerify {
	case "", "off", "warn", "enforce":
	default:
		return errors.New("vau_cert_verify must be off, warn or enforce")
	}
	return nil
}
