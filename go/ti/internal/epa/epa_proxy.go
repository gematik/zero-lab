package epa

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/spf13/cobra"
)

func newEpaProxyCmd() *cobra.Command {
	var addr string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run a local HTTP proxy that forwards to ePA APIs",
		Long: "Run a local HTTP proxy that wraps the existing epa.Proxy. The chosen auth\n" +
			"identity is loaded once at startup. /information endpoints work without\n" +
			"entitlement plumbing; VAU-bound endpoints that require Proof-of-PN will\n" +
			"fail at first call until PN/POPP is wired up later.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			env, _, err := resolveEpaEnv()
			if err != nil {
				return err
			}
			am, err := buildAuthMethod()
			if err != nil {
				return err
			}
			sf, err := am.SecurityFunctions(cmd.Context())
			if err != nil {
				return fmt.Errorf("building security functions: %w", err)
			}
			pool, err := epaCertPool(cmd.Context(), env)
			if err != nil {
				return err
			}
			proxy, err := epa.NewProxyWithSecurityFunctions(env, sf, "ti-epa", timeout, pool)
			if err != nil {
				return fmt.Errorf("creating proxy: %w", err)
			}
			return serveProxy(cmd.Context(), proxy, addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", ":8082", "address to listen on")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-request timeout to ePA aggregators")
	addEpaEnvFlag(cmd)
	addAuthMethodFlags(cmd)
	return cmd
}

func serveProxy(ctx context.Context, proxy *epa.Proxy, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: proxy,
	}

	// Cancel-on-signal so Ctrl-C and `kill` shut the listener down cleanly,
	// closing VAU sessions via proxy.Close in the deferred path.
	sigCtx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("ti epa proxy listening", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-sigCtx.Done():
		fmt.Fprintln(os.Stderr, "shutting down...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		proxy.Close()
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		proxy.Close()
		return err
	}
}
