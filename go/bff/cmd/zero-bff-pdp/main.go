// Command pdp-bff runs the pdp authorization server and the bff (with its embedded webui) as a single
// process on one port — a lightweight relying-party demo. It is meant to be exposed publicly via a tunnel
// (e.g. rathole) so it can authenticate against directory-ref (OIDF) and external OPs like Google; ingress
// and TLS are handled upstream, so this binary speaks plain HTTP on one port.
//
// Routing on the single mux: the pdp config must keep operational endpoints under /as (well-knowns at root),
// so /.well-known/* and /as/* go to the authorization server and everything else to the bff and webui. Each
// side keeps its own middleware chain.
//
// The bff authenticates to the AS with private_key_jwt (RFC 7523). Because the AS lives in this same
// process, the demo generates the bff's keys at startup and registers it as a client of a demo product
// directly in the AS config, so it runs without any manual key generation or client registration.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/bff/gateway"
	"github.com/gematik/zero-lab/go/bff/webui"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const demoProductID = "bff-demo"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if env("DEBUG", "") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	pdpConfigPath := flag.String("pdp-config", env("PDP_CONFIG_PATH", "pdp.yaml"), "path to the pdp config file")
	flag.Parse()

	// Load a .env next to the config (best-effort) so the BFF_* vars and the config's ${...} placeholders
	// are sourced from one place. Existing environment variables take precedence.
	_ = godotenv.Load(filepath.Join(filepath.Dir(*pdpConfigPath), ".env"))

	pdpCfg, err := pdp.LoadConfigFile(*pdpConfigPath)
	if err != nil {
		log.Fatalf("load pdp config %q: %v", *pdpConfigPath, err)
	}

	// One kv store (Postgres when DATABASE_URL is set, else in-memory) backs both halves: the AS sessions
	// + nonces and the bff sessions. The command owns the driver dependency (kv/postgres); the libraries
	// only see the kv.Store interface.
	store := openStore()
	pdpCfg.AuthzServerConfig.Store = store

	// One origin: the issuer, the public URL and the bff's redirect base are the same public tunnel URL. The
	// AS itself is discovered locally (it's in this process); the metadata it returns carries the public,
	// issuer-based endpoint URLs that the browser and the bff's server-side calls use.
	bindAddress := pdpCfg.BindAddress
	if bindAddress == "" {
		bindAddress = ":8011"
	}
	publicURL := env("PUBLIC_URL", "http://127.0.0.1"+bindAddress)
	localIssuer := "http://127.0.0.1" + bindAddress

	clientID := env("BFF_CLIENT_ID", "bff-demo")
	scopes := strings.Fields(env("BFF_SCOPE", ""))

	// Generate the bff's signing + DPoP keys and register the bff as a client of a demo product directly in
	// the in-process AS config — no manual keygen or client registration needed.
	signingKey, dpopKey, err := newBffKeys()
	if err != nil {
		log.Fatalf("generate bff keys: %v", err)
	}
	publicJWK, err := publicJWKMap(signingKey)
	if err != nil {
		log.Fatalf("encode bff public jwk: %v", err)
	}
	pdpCfg.AuthzServerConfig.Products = append(pdpCfg.AuthzServerConfig.Products, authzserver.Product{
		ProductID:    demoProductID,
		ProductName:  "Zero BFF demo",
		RedirectURIs: []string{publicURL + "/bff/auth/callback"},
		Scopes:       scopes,
	})
	pdpCfg.AuthzServerConfig.Clients = append(pdpCfg.AuthzServerConfig.Clients, authzserver.Client{
		ClientID:  clientID,
		ProductID: demoProductID,
		PublicJWK: publicJWK,
	})

	// Authorization server: its own OAuth-error/logging/recover chain. The pdp listen address (bind_address)
	// is the single port the whole demo serves on.
	p, err := pdp.New(*pdpCfg)
	if err != nil {
		log.Fatalf("create pdp: %v", err)
	}
	pdpMux := http.NewServeMux()
	p.AuthzServer.MountRoutes(pdpMux)
	pdpHandler := authzserver.OAuthErrors(authzserver.Logger(authzserver.Recover(pdpMux)))

	// The bff is constructed only after the AS is reachable (bff.New discovers the AS over HTTP, and the AS
	// lives in this same process). Until then this slot serves 503; the pdp routes are live immediately.
	var bffHandler atomic.Pointer[http.Handler]
	bffSlot := func(w http.ResponseWriter, r *http.Request) {
		if h := bffHandler.Load(); h != nil {
			(*h).ServeHTTP(w, r)
			return
		}
		http.Error(w, "bff initializing", http.StatusServiceUnavailable)
	}

	// One mux, one port. Longest-prefix match sends the pdp paths to the AS and everything else to the bff.
	top := http.NewServeMux()
	top.Handle("/.well-known/oauth-authorization-server", pdpHandler)
	top.Handle("/.well-known/openid-federation", pdpHandler)
	top.Handle("/as/", pdpHandler)
	top.HandleFunc("/bff/", bffSlot)
	top.HandleFunc("/", bffSlot)

	// Serve now so the bff can discover the local AS in this process.
	go func() {
		slog.Info("pdp-bff listening", "addr", p.BindAddress)
		if err := http.ListenAndServe(p.BindAddress, top); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	h := bff.RecoverMiddleware(buildBFF(bffParams{
		discoveryIssuer: localIssuer,
		publicURL:       publicURL,
		clientID:        clientID,
		scopes:          scopes,
		signingKey:      signingKey,
		dpopKey:         dpopKey,
		store:           store,
	}))
	bffHandler.Store(&h)

	slog.Info("pdp-bff ready", "public_url", publicURL)
	select {}
}

type bffParams struct {
	discoveryIssuer string
	publicURL       string
	clientID        string
	scopes          []string
	signingKey      jwk.Key
	dpopKey         jwk.Key
	store           kv.Store
}

// buildBFF constructs the bff, retrying until the in-process AS answers discovery, and returns its handler.
// When WEBAPP_UPSTREAM/API_UPSTREAM are set it runs as an auth gateway (gating + proxying those upstreams,
// login UI under /bff/); otherwise it serves the bff API + the static login UI at /.
func buildBFF(p bffParams) http.Handler {
	routes := gateway.RoutesFromEnv()
	frontendRedirect := p.publicURL + "/"
	if len(routes) > 0 {
		frontendRedirect = p.publicURL + "/bff/"
	}

	cfg := bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:      p.discoveryIssuer,
			ClientID:    p.clientID,
			RedirectURI: p.publicURL + "/bff/auth/callback",
			Scopes:      p.scopes,
			SigningKey:  p.signingKey,
			DPoPKey:     p.dpopKey,
		},
		CookieName:          env("BFF_COOKIE_NAME", "ZETA-BFF-SID"),
		FrontendRedirectURI: frontendRedirect,
		SessionManager:      bff.NewSessionManager(p.store, 0),
	}

	var b *bff.BackendForFrontend
	for attempt := 1; ; attempt++ {
		var err error
		if b, err = bff.New(cfg); err == nil {
			break
		} else if attempt >= 50 {
			log.Fatalf("create bff (AS unreachable after %d attempts): %v", attempt, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	handler, err := gateway.Handler(b, webui.FS, gateway.Config{Routes: routes})
	if err != nil {
		log.Fatalf("build gateway: %v", err)
	}
	return handler
}

// openStore returns the kv backend: Postgres when DATABASE_URL is set, otherwise an in-memory store
// (sessions + nonces are not durable across restarts).
func openStore() kv.Store {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Warn("DATABASE_URL not set — using in-memory kv store (sessions + nonces are not durable)")
		return kv.NewMemory()
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		log.Fatalf("open postgres kv store: %v", err)
	}
	slog.Info("using postgres kv store")
	return store
}

// newBffKeys generates the bff's ES256 signing key (for the client_assertion) and DPoP key (its thumbprint
// becomes the assertion's cnf.jkt).
func newBffKeys() (signing, dpop jwk.Key, err error) {
	if signing, err = authzserver.GenerateRandomJwk(); err != nil {
		return nil, nil, err
	}
	dpop, err = authzserver.GenerateRandomJwk()
	return signing, dpop, err
}

// publicJWKMap returns the public half of key as a JWK object suitable for the AS client registry.
func publicJWKMap(key jwk.Key) (map[string]any, error) {
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(pub)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
