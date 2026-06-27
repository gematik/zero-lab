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

	// PDP_NON_PROD=true forces NonProdMode (the mock IdP) regardless of the config file — for the airgapped
	// compose harness. The mock_idp claims still come from the config file.
	if viper.GetBool("non_prod") {
		config.AuthzServerConfig.NonProdMode = true
	}

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
