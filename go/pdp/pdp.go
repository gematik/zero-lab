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
	"net/http"
	"os"
	"path/filepath"

	"github.com/gematik/zero-lab/go/idpd"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/openid/providers"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// Config is the content of pdp.yaml. BaseDir is not part of the file: it is the file's directory, against
// which relative paths in the configuration resolve.
type Config struct {
	BindAddress       string             `yaml:"bind_address"`
	BaseDir           string             `yaml:"-"`
	AuthzServerConfig authzserver.Config `yaml:"authorization_server"`
	// ProvidersPath is the providers file, empty if there is none.
	ProvidersPath string `yaml:"-"`
	// OIDFAPIKey is the key of gematik's development federation; the program supplies it.
	OIDFAPIKey string `yaml:"-"`
	// HTTPClient carries the requests to the providers and the federation; the program supplies it, and
	// with it their TLS verification. Nil leaves each provider library's default.
	HTTPClient *http.Client `yaml:"-"`
}

const defaultOpenidProvidersFile = "openid-providers.yaml"

// LoadConfigFile reads pdp.yaml from path, expanding ${VAR} placeholders from the environment. An unknown key is
// an error, so an outdated file stops the start. Providers come from providersPath, which must then exist, else
// from openid-providers.yaml next to path if present; [New] loads them.
func LoadConfigFile(path, providersPath string) (*Config, error) {
	cfg := new(Config)
	cfg.BaseDir = filepath.Dir(path)
	if err := loadYAML(path, cfg); err != nil {
		return nil, err
	}

	cfg.AuthzServerConfig.BaseDir = cfg.BaseDir

	cfg.ProvidersPath = providersPath
	explicit := cfg.ProvidersPath != ""
	if !explicit {
		cfg.ProvidersPath = filepath.Join(cfg.BaseDir, defaultOpenidProvidersFile)
	}
	if _, statErr := os.Stat(cfg.ProvidersPath); statErr != nil {
		if explicit {
			return nil, fmt.Errorf("providers file %q: %w", cfg.ProvidersPath, statErr)
		}
		cfg.ProvidersPath = ""
	}
	return cfg, nil
}

// loadProviders builds the providers of config's file, and hands the relying party to the server, which also
// serves its entity statement.
func loadProviders(config *Config) error {
	server := &config.AuthzServerConfig
	if config.ProvidersPath == "" {
		return nil
	}
	entries, err := providerEntries(config.ProvidersPath)
	if err != nil {
		return err
	}
	set, err := providers.Build(entries, providers.Env{BaseDir: filepath.Dir(config.ProvidersPath), HTTPClient: config.HTTPClient}, providers.Kinds{
		"oidc": providers.OIDC,
		"idpd": idpd.Kind(nil),
		"oidf": oidf.Kind(config.OIDFAPIKey, func(rp *oidf.RelyingParty) { server.RelyingParty = rp }),
	})
	if err != nil {
		return fmt.Errorf("providers %q: %w", config.ProvidersPath, err)
	}
	server.Providers = set
	return nil
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

	if err := loadProviders(&config); err != nil {
		return nil, err
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
