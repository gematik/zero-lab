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

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

func runStart(opts *options, args []string) error {
	flags := newFlags("start", opts)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := opts.prepare(); err != nil {
		return err
	}
	server, err := createPdp(opts)
	if err != nil {
		return fmt.Errorf("create PDP: %w", err)
	}

	mux := http.NewServeMux()
	server.AuthzServer.MountRoutes(mux)

	// recover -> logger -> mux, all wrapped by the OAuth error normalizer so every
	// error response (incl. 404/405) uses the OAuth JSON shape.
	handler := authzserver.OAuthErrors(authzserver.Logger(authzserver.Recover(mux)))

	// Every request to the AS is small and answered at once, so whole-request deadlines
	// bound slow clients as well as slow headers.
	srv := &http.Server{
		Addr:              server.BindAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	slog.Debug("Zero Trust PDP configured", "pdp", server)
	slog.Info("starting Zero Trust PDP at " + server.BindAddress)
	if err := serve(srv); err != nil {
		return fmt.Errorf("server stopped: %w", err)
	}
	return nil
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

func createPdp(opts *options) (*pdp.PDP, error) {
	configFile := expandHome(opts.configFile)
	config, err := pdp.LoadConfigFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("load config file: %w", err)
	}
	slog.Debug("Loaded config file", "config_file", configFile)

	if config.AuthzServerConfig.Store, err = openStore(); err != nil {
		return nil, err
	}
	if config.AuthzServerConfig.SigningKey, err = config.AuthzServerConfig.LoadSigningKey(); err != nil {
		return nil, fmt.Errorf("load the signing key: %w", err)
	}

	slog.Info("Creating Zero Trust PDP", "version", pdp.Version, "config_file", configFile, "workdir", opts.workdir)
	return pdp.New(*config)
}

// openStore returns the kv backend: Postgres when DATABASE_URL is set, otherwise an in-memory store
// (sessions + nonces are not durable across restarts).
func openStore() (kv.Store, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Warn("DATABASE_URL not set — using in-memory kv store (sessions + nonces are not durable)")
		return kv.NewMemory(), nil
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres kv store: %w", err)
	}
	slog.Info("Using postgres kv store")
	return store, nil
}

// expandHome expands a leading ~ to $HOME.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~") {
		home, _ := os.UserHomeDir()
		path = strings.Replace(path, "~", home, 1)
	}
	return path
}

func runVersion(opts *options, args []string) error {
	flags := newFlags("version", opts)
	if err := flags.Parse(args); err != nil {
		return err
	}
	fmt.Printf("Zero Policy Decision Point v%s\n", pdp.ResolveVersion())
	expanded, err := filepath.Abs(opts.configFile)
	if err != nil {
		fmt.Printf("Error expanding config file: %s\n", err)
	} else {
		fmt.Println("Config file:", expanded)
	}
	fmt.Println("Working directory:", opts.workdir)
	return nil
}
