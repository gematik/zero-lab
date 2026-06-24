// Command zero-pep-proxy is a standalone oauth2-proxy-style authentication gateway built on pep/proxy. It
// serves the /oauth2/* endpoints on :4180 and is meant to sit behind Caddy in forward_auth mode (see the
// Caddyfile alongside this file) or to be reverse-proxied directly.
//
// Direct providers (OIDC, OIDF) with sessions in memory. Config from env:
//
//	PEP_ADDR                 listen address (default :4180)
//	PEP_PUBLIC_URL           public origin the browser reaches the proxy at (default http://127.0.0.1:4180)
//	PEP_OIDC_ISSUER          direct OIDC provider issuer (enables OIDC login)
//	PEP_OIDC_CLIENT_ID       the proxy's client_id at the provider
//	PEP_OIDC_CLIENT_SECRET   the client secret
//	PEP_OIDC_SCOPES          space-separated (default "openid email profile")
//	PEP_OIDC_NAME            display name in the chooser (default "OpenID Connect")
//	PEP_OIDC_ACCEPTABLE_SKEW id_token clock-skew tolerance, a Go duration (e.g. 60s, 2m); default 1m
//	PEP_OIDF_RP_CONFIG_PATH  gematik OIDF relying-party config (YAML); enables federation login
//	PEP_COOKIE_NAME          session cookie name (default ZERO-PEP-SID)
//	PEP_PRODUCTION_COOKIE    "true" → __Host- + Secure (set behind HTTPS)
//	PEP_TEMPLATE_DIR         replace the embedded UI templates from this directory
//
// Configure at least one of PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH.
package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/pep/proxy"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	addr := env("PEP_ADDR", ":4180")
	publicURL := strings.TrimRight(env("PEP_PUBLIC_URL", "http://127.0.0.1:4180"), "/")

	var opts []proxy.ProviderOption

	// Direct OIDC provider (optional).
	if issuer := os.Getenv("PEP_OIDC_ISSUER"); issuer != "" {
		var skew time.Duration // id_token clock-skew tolerance; 0 → the oidc client's 1m default.
		if v := os.Getenv("PEP_OIDC_ACCEPTABLE_SKEW"); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				log.Fatalf("invalid PEP_OIDC_ACCEPTABLE_SKEW %q: %v", v, err)
			}
			skew = d
		}
		client, err := oidc.NewClient(oidc.Config{
			Issuer:         issuer,
			ClientID:       os.Getenv("PEP_OIDC_CLIENT_ID"),
			ClientSecret:   oidc.NewSecretString(os.Getenv("PEP_OIDC_CLIENT_SECRET")),
			RedirectURI:    publicURL + "/oauth2/callback",
			Scopes:         strings.Fields(env("PEP_OIDC_SCOPES", "openid email profile")),
			Name:           env("PEP_OIDC_NAME", "OpenID Connect"),
			AcceptableSkew: skew,
		})
		if err != nil {
			log.Fatalf("create oidc client: %v", err)
		}
		opts = append(opts, proxy.WithOIDCClients(client))
		slog.Info("oidc provider configured", "issuer", issuer)
	}

	// OIDF (gematik federation) relying party (optional). The config's redirect_uris[0] must be
	// <public>/oauth2/callback, and its `sub` must be reachable at <public> and registered with the
	// federation master.
	if rpPath := os.Getenv("PEP_OIDF_RP_CONFIG_PATH"); rpPath != "" {
		rp, err := oidf.NewRelyingPartyFromConfigFile(rpPath)
		if err != nil {
			log.Fatalf("load oidf relying party: %v", err)
		}
		opts = append(opts, proxy.WithRelyingParty(rp))
		slog.Info("oidf relying party configured", "config", rpPath)
	}

	if len(opts) == 0 {
		log.Fatal("configure at least one provider: PEP_OIDC_ISSUER and/or PEP_OIDF_RP_CONFIG_PATH")
	}

	server, err := proxy.New(proxy.Config{
		Backend:          proxy.NewProviderBackend(opts...),
		Store:            kv.NewMemory(),
		CookieName:       env("PEP_COOKIE_NAME", "ZERO-PEP-SID"),
		ProductionCookie: os.Getenv("PEP_PRODUCTION_COOKIE") == "true",
		TemplateDir:      os.Getenv("PEP_TEMPLATE_DIR"),
	})
	if err != nil {
		log.Fatalf("create proxy: %v", err)
	}

	slog.Info("zero-pep-proxy listening", "addr", addr, "public_url", publicURL)
	log.Fatal(http.ListenAndServe(addr, server.Handler()))
}
