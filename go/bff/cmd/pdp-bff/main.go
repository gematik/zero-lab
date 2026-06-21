// Command pdp-bff runs the pdp authorization server and the bff (with its embedded webui) as a single
// process on one port — a lightweight relying-party demo. It is meant to be exposed publicly via a tunnel
// (e.g. rathole) so it can authenticate against directory-ref (OIDF) and external OPs like Google; ingress
// and TLS are handled upstream, so this binary speaks plain HTTP on one port.
//
// Routing on the single mux: the pdp config must keep operational endpoints under /as (well-knowns at root),
// so /.well-known/* and /as/* go to the authorization server and everything else to the bff and webui. Each
// side keeps its own middleware chain.
package main

import (
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
	"github.com/gematik/zero-lab/go/bff/webui"
	"github.com/gematik/zero-lab/go/pdp"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
	"github.com/joho/godotenv"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	pdpConfigPath := flag.String("pdp-config", env("PDP_BFF_CONFIG", "pdp.yaml"), "path to the pdp config file")
	flag.Parse()

	// Load a .env next to the config (best-effort) so the BFF_* vars and the config's ${...} placeholders
	// are sourced from one place. Existing environment variables take precedence.
	_ = godotenv.Load(filepath.Join(filepath.Dir(*pdpConfigPath), ".env"))

	// Authorization server: its own OAuth-error/logging/recover chain. The pdp listen address (bind_address)
	// is the single port the whole demo serves on.
	pdpCfg, err := pdp.LoadConfigFile(*pdpConfigPath)
	if err != nil {
		log.Fatalf("load pdp config %q: %v", *pdpConfigPath, err)
	}
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

	// One origin: the issuer, the public URL and the bff's redirect base are the same public tunnel URL. The
	// AS itself is discovered locally (it's in this process); the metadata it returns carries the public,
	// issuer-based endpoint URLs that the browser and the bff's server-side calls use.
	publicURL := env("BFF_PUBLIC_URL", "http://127.0.0.1"+p.BindAddress)
	localIssuer := "http://127.0.0.1" + p.BindAddress
	h := bff.RecoverMiddleware(buildBFF(localIssuer, publicURL))
	bffHandler.Store(&h)

	slog.Info("pdp-bff ready", "public_url", publicURL)
	select {}
}

// buildBFF constructs the bff, retrying until the in-process AS answers discovery, and returns the mux with
// the bff API + the static webui.
func buildBFF(discoveryIssuer, publicURL string) *http.ServeMux {
	cfg := bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:       discoveryIssuer,
			ClientId:     env("BFF_CLIENT_ID", "bff-demo"),
			ClientSecret: env("BFF_CLIENT_SECRET", "bff-demo"),
			RedirectUri:  publicURL + "/bff/auth/callback",
			Scopes:       strings.Fields(env("BFF_SCOPE", "")),
		},
		CookieName:          env("BFF_COOKIE_NAME", "ZETA-BFF-SID"),
		FrontendRedirectUri: publicURL + "/",
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

	mux := http.NewServeMux()
	b.Mount(mux)
	mux.Handle("/", http.FileServerFS(webui.FS))
	return mux
}
