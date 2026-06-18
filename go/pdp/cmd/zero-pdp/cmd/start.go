package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
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

		mux := http.NewServeMux()
		pdp.AuthzServer.MountRoutes(mux)

		// recover -> logger -> mux, all wrapped by the OAuth error normalizer so every
		// error response (incl. 404/405) uses the OAuth JSON shape.
		handler := authzserver.OAuthErrors(authzserver.Logger(authzserver.Recover(mux)))

		slog.Debug("Zero Trust PDP configured", "pdp", pdp)
		slog.Info(fmt.Sprintf("starting Zero Trust PDP at %s", pdp.BindAddress))
		if err := http.ListenAndServe(pdp.BindAddress, handler); err != nil {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	},
}
