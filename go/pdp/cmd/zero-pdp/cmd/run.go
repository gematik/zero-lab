package cmd

import (
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/libzero"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(runCmd)
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Zero Trust PDP",
	Run: func(cmd *cobra.Command, args []string) {
		configFile := pdp.ExpandPath(viper.GetString("config_file"))
		config, err := pdp.LoadConfigFile(configFile)
		if err != nil {
			slog.Error("Failed to load config file", "error", err)
			os.Exit(1)
		}

		slog.Info("Starting Zero Trust PDP", "version", libzero.Version, "config_file", configFile, "config", config)
		pdp, err := pdp.New(config)
		if err != nil {
			slog.Error("Failed to create PDP", "error", err)
			os.Exit(1)
		}

		slog.Info("Zero Trust PDP started", "pdp", pdp)

		e := echo.New()

		pdp.AuthzServer.MountRoutes(e.Group(""))

		e.Logger.Fatal(e.Start(":1323"))
	},
}