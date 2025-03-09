package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/pdp"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Zero Trust PDP",
	Run: func(cmd *cobra.Command, args []string) {
		configFile := expandHome(viper.GetString("config_file"))
		if configFile == "" {
			cobra.CheckErr("config file is required. Use --config-file/-f flag or environment variable")
		}
		config, err := pdp.LoadConfigFile(configFile)
		if err != nil {
			slog.Error("Failed to load config file", "error", err)
			os.Exit(1)
		}

		slog.Info("Starting Zero Trust PDP", "version", pdp.Version, "config_file", configFile)
		pdp, err := pdp.New(*config)
		if err != nil {
			slog.Error("Failed to create PDP", "error", err, "config", fmt.Sprintf("%+v", *config))
			os.Exit(1)
		}

		e := echo.New()
		e.Use(middleware.Recover())

		pdp.AuthzServer.MountRoutes(e.Group(""))

		for _, route := range e.Routes() {
			slog.Info("Route", "method", route.Method, "path", route.Path)
		}

		slog.Debug("Zero Trust PDP configured", "pdp", pdp)
		slog.Info(fmt.Sprintf("starting Zero Trust PDP at %s", pdp.Address))
		e.Logger.Fatal(e.Start(pdp.Address))

	},
}
