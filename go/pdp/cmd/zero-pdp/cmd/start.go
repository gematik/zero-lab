package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Zero Trust PDP",
	Run: func(cmd *cobra.Command, args []string) {
		pdp, err := createPdp()
		if err != nil {
			slog.Error("Failed to create PDP", "error", err)
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
