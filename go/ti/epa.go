package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/state"
	"github.com/spf13/cobra"
)

// certPoolTTL is how long an assembled gempki-backed TLS root pool stays warm
// in our state store before we refetch roots and the TSL. The TSL itself is
// cached for 5 minutes under the `pki:` prefix in the same SQLite store; this
// longer outer TTL avoids the XML re-parse and pool re-assembly on every CLI
// invocation.
const certPoolTTL = 24 * time.Hour

func newEpaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "epa",
		Short: "ePA (electronic patient record) commands",
		Long: "Commands for working with the ePA aggregators.\n\n" +
			"Select an environment with --epa-env, " + epaEnvEnv + " env var, or `ti epa use <env>`.\n" +
			"Available environments: dev, test, ref (default), prod.\n\n" +
			"Auth (for commands that need it) is selected with --auth-method connector|p12.",
	}
	cmd.PersistentFlags().StringVarP(&outputFlag, "output", "o", "text", "output format: text, json")

	cmd.AddCommand(newEpaUseCmd())
	cmd.AddCommand(newEpaEnvCmd())
	cmd.AddCommand(newEpaProvidersCmd())
	cmd.AddCommand(newEpaRecordCmd())
	cmd.AddCommand(newEpaConnectCmd())
	cmd.AddCommand(newEpaSessionCmd())
	cmd.AddCommand(newEpaProxyCmd())
	cmd.AddCommand(newEpaCacheCmd())

	return cmd
}

// telematikDir returns $XDG_CONFIG_HOME/telematik — the shared TI config root.
// CLI-owned files in this directory carry a `cli-` prefix so they don't
// collide with files written by other TI tools that
// share this directory.
func telematikDir() string {
	return filepath.Join(xdgConfigHome(), "telematik")
}

func epaStateFile() string {
	return filepath.Join(telematikDir(), "cli-state.db")
}

// loadCLIState opens the SQLite-backed state store at the canonical path.
// Callers are responsible for Close(). The store is shared by ePA and PKI
// caches; key prefixes (epa:, pki:) keep their domains apart.
func loadCLIState() (*state.SQLiteStore, error) {
	s, err := state.OpenSQLite(epaStateFile())
	if err != nil {
		return nil, fmt.Errorf("opening state file: %w", err)
	}
	return s, nil
}

// cachedCertPool is the JSON shape stored at certPoolKey(env). The pool itself
// can't be serialized, so we cache the DER bytes of each cert and rebuild the
// pool on read. encoding/json renders []byte as base64, so the on-disk form
// stays human-readable.
type cachedCertPool struct {
	CertsDER [][]byte `json:"certs_der"`
}

// epaCertPool returns a TLS root pool containing the TI roots + currently-valid
// sub-CAs for the given ePA environment. The system CA bundle doesn't trust the
// gematik PKI, so without this pool the TLS handshake to aggregators fails with
// "certificate is not standards compliant" or "unknown authority".
//
// On a cache miss it matches the `ti pki` pattern (`gempki.LoadRoots` +
// `loadTSLCached` + `roots.BuildCertPoolWithSubCAs`) and writes the assembled
// cert DER bytes to the state store with a 24h TTL. Subsequent calls within
// that window rebuild the pool from cached bytes — no network, no XML parse.
func epaCertPool(ctx context.Context, env epa.Env) (*x509.CertPool, error) {
	if pool := cachedEpaCertPool(env); pool != nil {
		return pool, nil
	}

	httpClient := newHTTPClient()
	gpkEnv := gempki.Environment(env)
	roots, err := gempki.LoadRoots(ctx, httpClient, gpkEnv)
	if err != nil {
		return nil, fmt.Errorf("loading gempki roots for %s: %w", env, err)
	}
	def, ok := envDefs[string(env)]
	if !ok {
		return nil, fmt.Errorf("no TSL URL configured for %s", env)
	}
	tsl, err := loadTSLCached(ctx, httpClient, def.TSLURL)
	if err != nil {
		return nil, fmt.Errorf("loading TSL for %s: %w", env, err)
	}

	// Build the cert list ourselves so we can both build the pool and cache
	// the DER bytes. Same order as roots.BuildCertPoolWithSubCAs.
	pool := x509.NewCertPool()
	cached := cachedCertPool{}
	for _, root := range roots.ByCommonName {
		pool.AddCert(root)
		cached.CertsDER = append(cached.CertsDER, root.Raw)
	}
	for _, subCA := range roots.FilterValidSubCAs(tsl) {
		pool.AddCert(subCA)
		cached.CertsDER = append(cached.CertsDER, subCA.Raw)
	}
	storeCachedEpaCertPool(env, cached)
	return pool, nil
}

// cachedEpaCertPool returns the cached pool for env, or nil on miss/error.
// Errors are logged (Debug) and swallowed so callers fall through to the
// network path — a cache is an optimization, never a hard dependency.
func cachedEpaCertPool(env epa.Env) *x509.CertPool {
	st, err := loadCLIState()
	if err != nil {
		slog.Debug("cert pool cache: open state failed", "err", err)
		return nil
	}
	defer st.Close()
	cached, hit, err := getJSON[cachedCertPool](st, certPoolKey(env))
	if err != nil {
		slog.Debug("cert pool cache: read failed", "err", err)
		return nil
	}
	if !hit || len(cached.CertsDER) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, der := range cached.CertsDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			slog.Debug("cert pool cache: parse failed, discarding cache", "err", err)
			_ = st.Delete(certPoolKey(env))
			return nil
		}
		pool.AddCert(cert)
	}
	return pool
}

func storeCachedEpaCertPool(env epa.Env, cached cachedCertPool) {
	st, err := loadCLIState()
	if err != nil {
		slog.Debug("cert pool cache: open state failed", "err", err)
		return
	}
	defer st.Close()
	if err := setJSON(st, certPoolKey(env), cached, state.Expire(certPoolTTL)); err != nil {
		slog.Debug("cert pool cache: write failed", "err", err)
	}
}

// newEpaClient builds an epa.Client with the gempki-backed cert pool. Wraps
// epa.NewClient so every caller in this package gets the right TLS trust
// store without thinking about it.
func newEpaClient(ctx context.Context, env epa.Env, provider epa.ProviderNumber, sf *epa.SecurityFunctions) (*epa.Client, error) {
	pool, err := epaCertPool(ctx, env)
	if err != nil {
		return nil, err
	}
	return epa.NewClient(env, provider, sf, epa.WithCertPool(pool))
}
