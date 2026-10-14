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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

		// Every request to the AS is small and answered at once, so whole-request deadlines
		// bound slow clients as well as slow headers.
		srv := &http.Server{
			Addr:              pdp.BindAddress,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		slog.Debug("Zero Trust PDP configured", "pdp", pdp)
		slog.Info(fmt.Sprintf("starting Zero Trust PDP at %s", pdp.BindAddress))
		if err := serve(srv); err != nil {
			slog.Error("server stopped", "error", err)
			os.Exit(1)
		}
	},
}

// serve runs srv until SIGINT or SIGTERM, then drains in-flight requests within the
// Kubernetes termination grace period (30 s by default).
func serve(srv *http.Server) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
