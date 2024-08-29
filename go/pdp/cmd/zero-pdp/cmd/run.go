package cmd

import (
	"log/slog"
	"os"

	"github.com/gematik/zero-lab/go/libzero"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	runCmd.Flags().StringP("addr", "a", ":8081", "Address to listen on")
	viper.BindPFlag("addr", runCmd.Flags().Lookup("addr"))
	rootCmd.AddCommand(runCmd)
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the Zero Trust PDP",
	Run: func(cmd *cobra.Command, args []string) {
		configFile := pdp.ExpandPath(viper.GetString("config_file"))
		if configFile == "" {
			cobra.CheckErr("config file is required. Use --config-file/-f flag or environment variable")
		}
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

		e := echo.New()
		e.Use(middleware.Recover())

		pdp.AuthzServer.MountRoutes(e.Group(""))

		addr := viper.GetString("addr")
		slog.Info("starting Zero Trust PDP", "pdp", pdp, "addr", addr)
		e.Logger.Fatal(e.Start(addr))

	},
}
