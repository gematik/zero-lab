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

// Package pdp assembles the zero-pdp Policy Decision Point from its configuration file.
package pdp

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// Config is the content of pdp.yaml. BaseDir is not part of the file: it is the file's directory, against
// which relative paths in the configuration resolve.
type Config struct {
	BindAddress       string             `yaml:"bind_address"`
	BaseDir           string             `yaml:"-"`
	AuthzServerConfig authzserver.Config `yaml:"authorization_server"`
}

// LoadConfigFile reads pdp.yaml from path, expanding ${VAR} placeholders from the environment. Providers
// come from PDP_OPENID_PROVIDERS_PATH, which must then exist, else from openid-providers.yaml next to path
// if present; that file replaces any providers set inline.
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
	if _, statErr := os.Stat(providersPath); statErr == nil { //nolint:gosec // the path comes from the operator's environment or configuration file, not a request
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

// PDP is a configured Policy Decision Point: its authorization server and the address to serve it on.
type PDP struct {
	BindAddress string
	AuthzServer *authzserver.Server
}

// New validates config and builds the authorization server. BindAddress defaults to ":8011".
func New(config Config) (*PDP, error) {
	if err := config.AuthzServerConfig.Validate(); err != nil {
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
