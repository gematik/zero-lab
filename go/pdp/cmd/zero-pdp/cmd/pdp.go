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

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func createPdp() (*pdp.PDP, error) {
	configFile := expandHome(viper.GetString("config_file"))
	if configFile == "" {
		cobra.CheckErr("config file is required. Use --config-file/-f flag or environment variable")
	}
	config, err := pdp.LoadConfigFile(configFile)
	if err != nil {
		slog.Error("Failed to load config file", "error", err)
		os.Exit(1)
	}

	slog.Debug("Loaded config file", "config_file", configFile, "config", fmt.Sprintf("%+v", config))

	config.AuthzServerConfig.Store = openStore()

	slog.Info("Creating Zero Trust PDP", "version", pdp.Version, "config_file", configFile, "workdir", viper.GetString("workdir"))
	return pdp.New(*config)
}

// openStore returns the kv backend: Postgres when DATABASE_URL is set, otherwise an in-memory store
// (sessions + nonces are not durable across restarts).
func openStore() kv.Store {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Warn("DATABASE_URL not set — using in-memory kv store (sessions + nonces are not durable)")
		return kv.NewMemory()
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		slog.Error("Failed to open postgres kv store", "error", err)
		os.Exit(1)
	}
	slog.Info("Using postgres kv store")
	return store
}
