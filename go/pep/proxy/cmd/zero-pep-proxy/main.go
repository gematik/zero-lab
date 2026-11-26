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

// Command zero-pep-proxy is a standalone oauth2-proxy-style authentication gateway built on pep/proxy. It
// serves the /oauth2/* endpoints on :4180 and is meant to sit behind Caddy in forward_auth mode (see the
// Caddyfile alongside this file) or to be reverse-proxied directly.
//
// Providers run in parallel. They come from an openid-providers.yaml file (oidc[]/idpd[]/oidf — see
// openid-providers.example.yaml); when that file is absent, the single-provider PEP_* env vars below are used
// instead. Everything else (server, session, secrets) is env-only — see CONFIG.md.
//
//	PEP_LISTEN_URL           the listener, the scheme its mode (servers.md rule 29): http://0.0.0.0:4180 with
//	                         PEP_LISTEN_PLAINTEXT_ACCEPTED=true, https://… with PEP_LISTEN_TLS_CERT_PATH and _KEY_PATH
//	                         (and _CA_PATH with _PEER_NAME for mutual TLS), or http://127.0.0.1:4180 in the pod; required
//	PEP_PUBLIC_URL           public origin the browser reaches the proxy at (default http://127.0.0.1:4180)
//	PEP_HOSTS                more names requests may be sent to, comma-separated; the host of PEP_PUBLIC_URL always is one
//	PEP_OPENID_PROVIDERS_PATH  providers YAML (default ./openid-providers.yaml); the multi-provider source
//	PEP_OIDC_ISSUER          direct OIDC provider issuer (enables single-OIDC login)
//	PEP_OIDC_CLIENT_ID / _CLIENT_SECRET / _SCOPES / _NAME / _LOGO_URI / _ACCEPTABLE_SKEW  OIDC options
//	PEP_OIDF_RP_CONFIG_PATH  gematik OIDF relying-party config (YAML); enables federation login
//	PEP_IDPD_CLIENT_ID     gematik IDP-Dienst client_id (enables idpd login)
//	PEP_IDPD_ENV           test|ref|prod (default prod); or PEP_IDPD_BASE_URL to override
//	PEP_IDPD_TRUST_FETCH   "true" → download the trust material from gematik's hosts; or
//	PEP_IDPD_TRUST_BUNDLE_PATH  the file `ti pki trust export` writes; idpd requires one of the two
//	PEP_IDPD_REDIRECT_URI  redirect_uri the idpd client sends (default <public>/oauth2/callback)
//	PEP_IDPD_REDIRECT_SCOPES / _NAME / _LOGO_URI / _USER_AGENT  idpd options (always Authenticator flow)
//	PEP_COOKIE_NAME          session cookie name (default ZERO-PEP-SID)
//	PEP_INSECURE_COOKIE      "true" → drop __Host-/Secure for dev; refused unless PEP_PUBLIC_URL is http on localhost
//	                         or 127.0.0.1; default is secure
//	PEP_TEMPLATE_DIR         replace the embedded UI templates from this directory
//	PEP_SESSION_KEY_PATH     file with a base64 256-bit key → enables local /oauth2/auth validation (decrypt
//	                         an encrypted session token, no kv per request). PEP_SESSION_PREVIOUS_KEY_PATH rotates it.
//	PEP_SESSION_TTL          session lifetime when local validation is on (Go duration, default 8h)
//	PEP_SESSION_STORE_KEY_PATH  key file (`<id> <base64 of 32 bytes>` per line) → seals everything in the kv store,
//	                         read at start; a changed file takes effect with a rollout. Required with
//	                         PEP_DATABASE_URL. See docs/at-rest-encryption.md.
//	PEP_DATABASE_URL         Postgres URL of the session store (postgres://user:password@host:port/database);
//	                         durable + shared across replicas. When unset, an in-memory store is used (dev only —
//	                         sessions are lost on restart, not shared). The connection is TLS with the server's
//	                         certificate verified, under the system's roots or the CA bundle of
//	                         PEP_DATABASE_TLS_CA_PATH; plaintext only with PEP_DATABASE_PLAINTEXT_ACCEPTED=true
//	                         (servers.md rule 29). The URL names no sslmode.
//
// Usage: zero-pep-proxy [-w workdir]
//
//	-w chdir's to workdir. openid-providers.yaml is found there (or set
//	PEP_OPENID_PROVIDERS_PATH); the OIDF config's own relative key paths always resolve against the providers
//	file's directory, not -w. ${VAR} placeholders in the providers file expand from the environment.
//
// Configure providers via openid-providers.yaml, or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_IDPD_CLIENT_ID.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gematik/zero-lab/go/egress"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/openid/providers"
	"github.com/gematik/zero-lab/go/pep"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// maxHeaderBytes bounds the request line and header of a request (server rule 28, limits before work). The
// largest things a request carries here are an access token (16 KiB at most) or two cookies of this server and
// those of an application behind the gateway (4 KiB each); 64 KiB holds them, where Go's default is 1 MiB.
const maxHeaderBytes = 64 << 10

// newHTTPServer returns the server that serves handler. Proxied uploads and downloads may legitimately
// take long, so there is no whole-request read or write deadline; slow headers, large headers and idle
// connections are bounded here, and upstream calls by the proxy's transport.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
		IdleTimeout:       120 * time.Second,
	}
}

// servedHosts returns the names requests may be sent to: the host of publicURL, port included as the URL has
// it, and the comma-separated names of more, for a deployment in which a proxy in front sends another Host.
func servedHosts(publicURL, more string) ([]string, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("PEP_PUBLIC_URL has no host")
	}
	hosts := []string{u.Host}
	for name := range strings.SplitSeq(more, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if strings.ContainsAny(name, "/@? ") {
			return nil, errors.New("PEP_HOSTS holds something that is no host name")
		}
		if !slices.Contains(hosts, name) {
			hosts = append(hosts, name)
		}
	}
	return hosts, nil
}

// sessionStoreKeyPathEnv names the key file of the session store. All replicas share it.
const sessionStoreKeyPathEnv = "PEP_SESSION_STORE_KEY_PATH"

// sessionStorePurpose names the proxy's records in the key derivation.
const sessionStorePurpose = "pep/session"

// reapEvery is how often expired rows leave the store.
const reapEvery = 10 * time.Minute

// outboundHTTPTimeout bounds each request to the PDP or an OpenID provider.
const outboundHTTPTimeout = 30 * time.Second

// checkInsecureCookie refuses PEP_INSECURE_COOKIE outside local development (server rule 17): a cookie without Secure
// and __Host- goes out over plain http, and any host of the domain can set it.
func checkInsecureCookie(publicURL string) error {
	if proxy.IsLocalHTTP(publicURL) {
		return nil
	}
	return fmt.Errorf("PEP_INSECURE_COOKIE=true is for http on localhost or 127.0.0.1, and PEP_PUBLIC_URL is %q: unset PEP_INSECURE_COOKIE", publicURL)
}

// databaseURLEnv names the Postgres peer of the session store and the revocations; retiredDatabaseURLEnv is the
// name it had before it carried the component's prefix (naming-and-config.md).
const (
	databaseURLEnv        = "PEP_DATABASE_URL"
	retiredDatabaseURLEnv = "DATABASE_URL"
)

// databaseURL reads the store's Postgres DSN; the retired DATABASE_URL stops the start with the new name rather
// than leave a deployment on an in-memory store it did not choose.
func databaseURL(getenv func(string) string) (string, error) {
	if getenv(retiredDatabaseURLEnv) != "" {
		return "", fmt.Errorf("%s is replaced by %s", retiredDatabaseURLEnv, databaseURLEnv)
	}
	return getenv(databaseURLEnv), nil
}

// storeKeys loads the session store's key file. A persistent store without one refuses to start (server rules
// 5, 17), before any connection, so an unreachable database cannot hide it. Nil means no key and no need for one.
func storeKeys(dsn, keyPath string) (*kv.Keyring, error) {
	if keyPath == "" {
		if dsn != "" {
			return nil, fmt.Errorf("PEP_DATABASE_URL is set but %s is not: a persistent store must hold ciphertext only; make a key file with: printf 'k1 %%s\\n' \"$(openssl rand -base64 32)\"", sessionStoreKeyPathEnv)
		}
		return nil, nil
	}
	ring, err := kv.LoadKeyring(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sessionStoreKeyPathEnv, err)
	}
	return ring, nil
}

// openStore returns the session store. Postgres when PEP_DATABASE_URL is set — durable across restarts and shared
// across replicas (required for production / horizontal scale). Otherwise an in-memory store for dev/tests,
// where sessions are lost on restart and not shared. Sealed whenever a key file is given.
func openStore() kv.Store {
	dsn, err := databaseURL(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	ring, err := storeKeys(dsn, os.Getenv(sessionStoreKeyPathEnv))
	if err != nil {
		log.Fatal(err)
	}
	var store kv.Store
	if dsn == "" {
		slog.Warn("PEP_DATABASE_URL not set — using in-memory kv store, for a single replica only (sessions are lost on restart and not shared across replicas)")
		store = kv.NewMemory()
	} else {
		db, err := databaseOf(dsn, os.Getenv, readOperatorFile)
		if err != nil {
			log.Fatalf("open postgres kv store: %v", err)
		}
		opts := append([]postgres.Option{postgres.WithMigrate()}, db.transport...)
		if store, err = postgres.Open(context.Background(), db.address, db.user, db.password, opts...); err != nil {
			log.Fatalf("open postgres kv store: %v", err)
		}
		slog.Info("using postgres kv store for sessions")
	}
	if ring == nil {
		return store
	}
	slog.Info("kv store sealed", "keys", ring.String())
	return kv.NewSealed(store, ring, sessionStorePurpose)
}

// openRevocations returns the session revocations: published over Postgres LISTEN/NOTIFY and stored in the
// store when PEP_DATABASE_URL is set, so logout and lockout hold at every replica; otherwise in memory, for a single
// replica. ttl is the snapshot lifetime, how long a revocation learned from another replica holds.
func openRevocations(store kv.Store, ttl time.Duration) proxy.Revocations {
	dsn, err := databaseURL(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if dsn == "" {
		slog.Warn("PEP_DATABASE_URL not set — revocations held in memory, for a single replica only")
		return proxy.NewMemoryRevocations(nil)
	}
	db, err := databaseOf(dsn, os.Getenv, readOperatorFile)
	if err != nil {
		log.Fatalf("open revocation bus: %v", err)
	}
	bus, err := postgres.OpenBus(context.Background(), db.address, db.user, db.password, db.transport...)
	if err != nil {
		log.Fatalf("open revocation bus: %v", err)
	}
	slog.Info("using postgres revocation bus (LISTEN/NOTIFY)")
	if ttl <= 0 {
		ttl = proxy.DefaultSnapshotTTL
	}
	revocations, err := newKVRevocations(bus, store, ttl, slog.Default())
	if err != nil {
		log.Fatalf("revocations: %v", err)
	}
	return revocations
}

func main() {
	workdir := flag.String("w", "", "working directory: chdir here")
	flag.Parse()

	// Resolve an explicitly-set PEP_OPENID_PROVIDERS_PATH against the invocation directory now, before -w
	// changes the cwd, so the providers file's own relative paths (OIDF keys/secrets) stay anchored to its
	// directory regardless of -w. providersExplicit ("operator set it") must exist; the default is optional —
	// fall back to the single-provider PEP_* env vars.
	providersPath := os.Getenv("PEP_OPENID_PROVIDERS_PATH")
	providersExplicit := providersPath != ""
	if providersExplicit {
		if abs, err := filepath.Abs(providersPath); err == nil {
			providersPath = abs
		}
	}

	if *workdir != "" {
		if err := os.Chdir(*workdir); err != nil {
			log.Fatalf("chdir %q: %v", *workdir, err)
		}
	}
	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	listener, err := listenFromEnv(os.Getenv, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	publicURL := strings.TrimRight(env("PEP_PUBLIC_URL", "http://127.0.0.1:4180"), "/")
	hosts, err := servedHosts(publicURL, os.Getenv("PEP_HOSTS"))
	if err != nil {
		log.Fatal(err)
	}
	insecureCookie := os.Getenv("PEP_INSECURE_COOKIE") == "true"
	if insecureCookie {
		if err := checkInsecureCookie(publicURL); err != nil {
			log.Fatal(err)
		}
	}

	// Default providers file: openid-providers.yaml in the workdir, absolute (its directory anchors the OIDF
	// config's relative key paths).
	if !providersExplicit {
		if abs, err := filepath.Abs("openid-providers.yaml"); err == nil {
			providersPath = abs
		}
	}

	// The OpenID providers, the IDP-Dienst and the federation master among them, are on the internet: their
	// requests go through the egress client, under the web profile of spec/pki-validation and over https, plain http
	// only for OCSP, CRLs and the TSL (servers.md rule 30).
	// A forward proxy, when the operator sets one, carries the egress client's requests and the revocation fetches
	// (servers.md rule 30); it is reported at start.
	forwardProxy, err := egress.ProxyFromHost(os.Getenv, os.ReadFile, "PEP_EGRESS_PROXY_CREDENTIALS_PATH")
	if err != nil {
		log.Fatal(err)
	}
	slog.Info("egress forward proxy", "proxy", forwardProxy.String())
	webClient, err := egress.NewClient(outboundHTTPTimeout, egress.Options{Proxy: forwardProxy})
	if err != nil {
		log.Fatalf("outbound TLS: %v", err)
	}
	// An upstream behind the gateway and the PDP are peers the deployment configured, which may be plain http; an
	// https one gets the web profile too.
	upstreamTransport, err := egress.NewTransport(egress.Options{Proxy: forwardProxy})
	if err != nil {
		log.Fatalf("upstream TLS: %v", err)
	}

	// One store for the sessions, the revocations and oidf's federation documents. The documents are public
	// signed data, but they go through the same sealed store: splitting it would need a second backing store and
	// key handling for no gain, and oidf verifies them again on every read.
	store := openStore()
	documents := newKVDocuments(store)

	// Backend selection: PEP_BACKEND=pdp makes pep a confidential client of the PDP (DPoP-bound tokens + the
	// gated /api proxy); otherwise pep drives the configured OIDC/OIDF/idpd providers directly.
	var backend proxy.Backend
	if os.Getenv("PEP_BACKEND") == "pdp" {
		backend = pdpBackendFromEnv(publicURL, &http.Client{Transport: upstreamTransport, Timeout: outboundHTTPTimeout})
	} else {
		// Providers run in parallel. When the providers file exists it is the source; otherwise a single
		// provider of each type comes from the PEP_OIDC_* / PEP_OIDF_RP_CONFIG_PATH / PEP_IDPD_* env vars.
		var set *providers.Set
		if _, statErr := os.Stat(providersPath); statErr == nil { //nolint:gosec // the path comes from PEP_OPENID_PROVIDERS_PATH or the fixed default in the working directory, not a request
			var err error
			if set, err = loadProviders(providersPath, publicURL, webClient, documents); err != nil {
				log.Fatalf("load providers from %s: %v", providersPath, err) //nolint:gosec // start-up log of a path from the operator's environment, no request data
			}
			slog.Info("providers loaded", "path", providersPath)
		} else if providersExplicit {
			log.Fatalf("PEP_OPENID_PROVIDERS_PATH %q does not exist: %v", providersPath, statErr) //nolint:gosec // %q escapes a value from the operator's environment; start-up log, no request data
		} else {
			set = providersFromEnv(publicURL, webClient, documents)
		}
		if set.Empty() {
			log.Fatal("configure providers via openid-providers.yaml (PEP_OPENID_PROVIDERS_PATH), or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_IDPD_CLIENT_ID")
		}
		backend = proxy.NewProviderBackend(set)
	}

	var snapshotTTL time.Duration
	if v := os.Getenv("PEP_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("invalid PEP_SESSION_TTL %q: %v", v, err) //nolint:gosec // %q escapes a value from the operator's environment; start-up log, no request data
		}
		snapshotTTL = d
	}

	routes, err := proxy.RoutesFromConfig(proxy.RouteSources{
		RoutesPath:     os.Getenv("PEP_ROUTES_PATH"),
		APIUpstream:    os.Getenv("PEP_API_UPSTREAM"),
		WebappUpstream: os.Getenv("PEP_WEBAPP_UPSTREAM"),
	})
	if err != nil {
		log.Fatalf("gateway routes: %v", err)
	}

	revocations := openRevocations(store, snapshotTTL)
	server, err := proxy.New(proxy.Config{
		Backend:                 backend,
		Sessions:                newKVSessions(store),
		Revocations:             revocations,
		CookieName:              env("PEP_COOKIE_NAME", "ZERO-PEP-SID"),
		InsecureCookie:          insecureCookie,
		TemplateDir:             os.Getenv("PEP_TEMPLATE_DIR"),
		SnapshotKeyPath:         os.Getenv("PEP_SESSION_KEY_PATH"),
		SnapshotPreviousKeyPath: os.Getenv("PEP_SESSION_PREVIOUS_KEY_PATH"),
		SnapshotTTL:             snapshotTTL,
		Routes:                  routes,
		Hosts:                   hosts,
		// The transport alone, as a client's timeout would cut off long uploads and downloads.
		UpstreamTransport: upstreamTransport,
		Logger:            slog.Default(),
	})
	if err != nil {
		log.Fatalf("create proxy: %v", err)
	}

	srv := newHTTPServer(server.Handler())
	ln, err := listen(listener)
	if err != nil {
		log.Fatalf("listen on %s: %v", listener.address, err)
	}

	slog.Info("zero-pep-proxy listening", "version", pep.Version, "addr", listener.address, "mode", listener.mode, "public_url", publicURL)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// Fail closed (server rule 17): a replica that cannot learn the revocations of the others would admit
	// snapshots they ended.
	if err := revocations.Follow(ctx); err != nil {
		stop()
		log.Fatalf("follow revocations: %v", err)
	}
	go kv.Reap(ctx, store, reapEvery)
	err = serve(ctx, srv, ln)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}

// serve runs srv until ctx ends, then drains in-flight requests within the Kubernetes
// termination grace period (30 s by default).
func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

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
