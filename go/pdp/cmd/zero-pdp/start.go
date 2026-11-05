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
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

const (
	// storeKeyPathEnv names the key file of the persistent store and of the nonces. All replicas share it.
	storeKeyPathEnv = "PDP_STORE_KEY_PATH"
	// storePurpose names the records of the authorization server in the key derivation.
	storePurpose = "pdp/authzserver"
	// oidfDevAPIKeyEnv holds the key of gematik's development federation; a value, not a file, see
	// docs/conventions/naming-and-config.md.
	oidfDevAPIKeyEnv = "PDP_OIDF_DEV_API_KEY" //nolint:gosec // the name of the variable, not a key
	// reapEvery is how often expired rows leave the store.
	reapEvery = 10 * time.Minute
)

func runStart(opts *options, args []string) error {
	flags := newFlags("start", opts)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := opts.prepare(); err != nil {
		return err
	}
	server, store, err := createPdp(opts)
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

	slog.Info("starting Zero Trust PDP at " + server.BindAddress)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go kv.Reap(ctx, store, reapEvery)
	if err := serve(ctx, srv); err != nil {
		return fmt.Errorf("server stopped: %w", err)
	}
	return nil
}

// serve runs srv until ctx ends, then drains in-flight requests within the Kubernetes
// termination grace period (30 s by default).
func serve(ctx context.Context, srv *http.Server) error {
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

func createPdp(opts *options) (*pdp.PDP, kv.Store, error) {
	configFile := expandHome(opts.configFile)
	config, err := pdp.LoadConfigFile(configFile, os.Getenv("PDP_OPENID_PROVIDERS_PATH"))
	if err != nil {
		return nil, nil, fmt.Errorf("load config file: %w", err)
	}
	config.OIDFAPIKey = os.Getenv(oidfDevAPIKeyEnv)
	slog.Debug("Loaded config file", "config_file", configFile)

	store, nonceKeys, err := openStore(os.Getenv("DATABASE_URL"), os.Getenv(storeKeyPathEnv))
	if err != nil {
		return nil, nil, err
	}
	config.AuthzServerConfig.Store, config.AuthzServerConfig.NonceKeys = store, nonceKeys
	if config.AuthzServerConfig.SigningKey, err = config.AuthzServerConfig.LoadSigningKey(); err != nil {
		return nil, nil, fmt.Errorf("load the signing key: %w", err)
	}

	slog.Info("Creating Zero Trust PDP", "version", pdp.Version, "config_file", configFile, "workdir", opts.workdir)
	server, err := pdp.New(*config)
	if err != nil {
		return nil, nil, err
	}
	return server, store, nil
}

// openStore returns the kv backend and the keys of the replay nonces. With a DSN it is Postgres, sealed under
// the ring in the key file, which it refuses to go without (server rules 5, 17). Without one it is an in-memory
// store, unsealed, for one replica: sessions and nonces are not durable across restarts and not shared.
func openStore(dsn, keyPath string) (kv.Store, nonce.Keys, error) {
	if dsn == "" {
		slog.Warn("DATABASE_URL not set: using an in-memory kv store, for a single replica only (sessions and nonces are not durable and not shared)")
		if keyPath != "" {
			ring, err := kv.LoadKeyring(keyPath)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", storeKeyPathEnv, err)
			}
			return kv.NewMemory(), ring, nil
		}
		slog.Warn(storeKeyPathEnv + " not set: nonces are sealed under a key of this process alone, which no other replica can open and a restart forgets")
		keys, err := nonce.NewEphemeralKeys()
		if err != nil {
			return nil, nil, fmt.Errorf("nonce keys: %w", err)
		}
		return kv.NewMemory(), keys, nil
	}
	if keyPath == "" {
		return nil, nil, fmt.Errorf("DATABASE_URL is set but %s is not: a persistent store must hold ciphertext only; make a key file with: printf 'k1 %%s\\n' \"$(openssl rand -base64 32)\"", storeKeyPathEnv)
	}
	ring, err := kv.LoadKeyring(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", storeKeyPathEnv, err)
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open postgres kv store: %w", err)
	}
	slog.Info("Using postgres kv store, sealed", "keys", ring.String())
	return kv.NewSealed(store, ring, storePurpose), ring, nil
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
