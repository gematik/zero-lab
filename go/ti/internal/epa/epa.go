package epa

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/gematik/zero-lab/go/ti/state"
	"github.com/spf13/cobra"
)

// certPoolTTL is how long an assembled gempki-backed TLS root pool stays warm
// in our state store before we refetch roots and the TSL. The TSL itself is
// cached for 5 minutes under the `pki:` prefix in the same SQLite store; this
// longer outer TTL avoids the XML re-parse and pool re-assembly on every CLI
// invocation.
const certPoolTTL = 24 * time.Hour

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "epa",
		Short: "ePA (electronic patient record) commands",
		Long: "Commands for working with the ePA aggregators.\n\n" +
			"Select an environment with --epa-env, " + epaEnvEnv + " env var, or `ti epa use <env>`.\n" +
			"Available environments: dev, test, ref (default), prod.\n\n" +
			"Auth (for commands that need it) is selected with --auth-method connector|p12.",
	}
	cmd.PersistentFlags().StringVarP(&common.OutputFlag, "output", "o", "text", "output format: text, json")

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
// On a cache miss it loads the TI trust store via gempki's NetworkLoader,
// fetches the TSL via common.LoadTSLCached, assembles a pool of roots + TSL-listed
// intermediates, and writes the DER bytes to the state store with a 24h TTL.
// Subsequent calls within that window rebuild the pool from cached bytes —
// no network, no XML parse.
func epaCertPool(ctx context.Context, env epa.Env) (*x509.CertPool, error) {
	if pool := cachedEpaCertPool(env); pool != nil {
		return pool, nil
	}

	httpClient := common.NewHTTPClient()
	gpkEnv := gempki.Environment(env)
	ts, err := gempki.NetworkLoader{Env: gpkEnv, HTTPClient: httpClient}.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading gempki trust store for %s: %w", env, err)
	}
	def, ok := common.EnvDefs[string(env)]
	if !ok {
		return nil, fmt.Errorf("no TSL URL configured for %s", env)
	}
	tsl, err := common.LoadTSLCached(ctx, httpClient, def.TSLURL)
	if err != nil {
		return nil, fmt.Errorf("loading TSL for %s: %w", env, err)
	}

	// Roots first, then every CA/PKC intermediate from the TSL. The TLS
	// handshake performs path validation, so an unused intermediate in the
	// pool is harmless; a missing one breaks the handshake.
	pool := x509.NewCertPool()
	cached := cachedCertPool{}
	for _, root := range ts.Roots() {
		pool.AddCert(root)
		cached.CertsDER = append(cached.CertsDER, root.Raw)
	}
	for _, sub := range gempki.IntermediateCAsFromTSL(tsl) {
		pool.AddCert(sub.Cert)
		cached.CertsDER = append(cached.CertsDER, sub.Cert.Raw)
	}
	storeCachedEpaCertPool(env, cached)
	return pool, nil
}

// cachedEpaCertPool returns the cached pool for env, or nil on miss/error.
// Errors are logged (Debug) and swallowed so callers fall through to the
// network path — a cache is an optimization, never a hard dependency.
func cachedEpaCertPool(env epa.Env) *x509.CertPool {
	st, err := common.LoadCLIState()
	if err != nil {
		slog.Debug("cert pool cache: open state failed", "err", err)
		return nil
	}
	defer st.Close()
	cached, hit, err := common.GetJSON[cachedCertPool](st, certPoolKey(env))
	if err != nil {
		slog.Debug("cert pool cache: read failed", "err", err)
		return nil
	}
	if !hit || len(cached.CertsDER) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	for _, der := range cached.CertsDER {
		// TI roots are brainpool-curve certs, which stdlib x509 can't parse.
		// brainpool.ParseCertificate falls back to x509 for RSA/standard-ECC
		// intermediates, so it handles every cert kind we cache.
		cert, err := brainpool.ParseCertificate(der)
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
	st, err := common.LoadCLIState()
	if err != nil {
		slog.Debug("cert pool cache: open state failed", "err", err)
		return
	}
	defer st.Close()
	if err := common.SetJSON(st, certPoolKey(env), cached, state.Expire(certPoolTTL)); err != nil {
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
