package cmd

import (
	"fmt"
	"log/slog"
	"os"

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

	slog.Info("Creating Zero Trust PDP", "version", pdp.Version, "config_file", configFile, "workdir", viper.GetString("workdir"))
	return pdp.New(*config)
}
