// Command zero-pep-proxy is a standalone oauth2-proxy-style authentication gateway built on pep/proxy. It
// serves the /oauth2/* endpoints on :4180 and is meant to sit behind Caddy in forward_auth mode (see the
// Caddyfile alongside this file) or to be reverse-proxied directly.
//
// Providers run in parallel. For several providers (multiple OIDC, gemidp, an OIDF RP), point
// PEP_CONFIG_PATH at a YAML file (see config.example.yaml). For a single provider of each type, the PEP_*
// env vars below work without a config file. Sessions are in memory.
//
//	PEP_ADDR                 listen address (default :4180)
//	PEP_PUBLIC_URL           public origin the browser reaches the proxy at (default http://127.0.0.1:4180)
//	PEP_CONFIG_PATH          YAML listing several providers (oidc[], gemidp[], oidf) — the multi-provider path
//	PEP_OIDC_ISSUER          direct OIDC provider issuer (enables single-OIDC login)
//	PEP_OIDC_CLIENT_ID / _CLIENT_SECRET / _SCOPES / _NAME / _LOGO_URI / _ACCEPTABLE_SKEW  OIDC options
//	PEP_OIDF_RP_CONFIG_PATH  gematik OIDF relying-party config (YAML); enables federation login
//	PEP_GEMIDP_CLIENT_ID     gematik IDP-Dienst client_id (enables gemidp login)
//	PEP_GEMIDP_ENV           test|ref|prod (default prod); or PEP_GEMIDP_BASE_URL to override
//	PEP_GEMIDP_REDIRECT_URI  redirect_uri the gemidp client sends (default <public>/oauth2/callback)
//	PEP_GEMIDP_REDIRECT_SCOPES / _NAME / _LOGO_URI / _USER_AGENT  gemidp options (always Authenticator flow)
//	PEP_COOKIE_NAME          session cookie name (default ZERO-PEP-SID)
//	PEP_PRODUCTION_COOKIE    "true" → __Host- + Secure (set behind HTTPS)
//	PEP_TEMPLATE_DIR         replace the embedded UI templates from this directory
//	DATABASE_URL             Postgres DSN for the session store; durable + shared across replicas. When unset,
//	                         an in-memory store is used (dev only — sessions are lost on restart, not shared).
//
// Usage: zero-pep-proxy [-w workdir] [-f config.yaml]
//
//	-w chdir's to workdir and loads a .env from it; the config (default pep.yaml) is found there too, but a
//	config's own relative paths (keys, secrets) always resolve against the config file's directory, not -w.
//	${VAR} placeholders in the config expand from the environment. -f overrides the default / PEP_CONFIG_PATH.
//
// Configure providers via the config file, or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_GEMIDP_CLIENT_ID.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pep/proxy"
	"github.com/joho/godotenv"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// openStore returns the session store. Postgres when DATABASE_URL is set — durable across restarts and shared
// across replicas (required for production / horizontal scale). Otherwise an in-memory store for dev/tests,
// where sessions are lost on restart and not shared.
func openStore() kv.Store {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Warn("DATABASE_URL not set — using in-memory kv store (sessions are lost on restart and not shared across replicas)")
		return kv.NewMemory()
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		log.Fatalf("open postgres kv store: %v", err)
	}
	slog.Info("using postgres kv store for sessions")
	return store
}

func main() {
	configPath := flag.String("f", "", "providers config YAML (default pep.yaml in the workdir); overrides PEP_CONFIG_PATH")
	workdir := flag.String("w", "", "working directory: chdir here and load .env from it (does not move the config's base path)")
	flag.Parse()

	// Resolve an explicit -f / PEP_CONFIG_PATH against the invocation directory now, before -w changes the
	// cwd, and make it absolute — so the config's own relative paths (keys, secrets) stay anchored to the
	// config file's directory regardless of -w.
	cfgPath := *configPath
	if cfgPath == "" {
		cfgPath = os.Getenv("PEP_CONFIG_PATH")
	}
	if cfgPath != "" {
		if abs, err := filepath.Abs(cfgPath); err == nil {
			cfgPath = abs
		}
	}

	if *workdir != "" {
		if err := os.Chdir(*workdir); err != nil {
			log.Fatalf("chdir %q: %v", *workdir, err)
		}
	}
	// Load .env from the (work)dir so PEP_* and the config's ${VAR} placeholders come from one place;
	// existing environment variables take precedence.
	_ = godotenv.Load()

	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	addr := env("PEP_ADDR", ":4180")
	publicURL := strings.TrimRight(env("PEP_PUBLIC_URL", "http://127.0.0.1:4180"), "/")

	// Default config filename, looked up in the workdir; absolute so its directory is the config's base path.
	if cfgPath == "" {
		if abs, err := filepath.Abs("pep.yaml"); err == nil {
			if _, statErr := os.Stat(abs); statErr == nil {
				cfgPath = abs
			}
		}
	}

	// Providers run in parallel. A config file (-f / PEP_CONFIG_PATH, a YAML listing several oidc/gemidp +
	// one oidf RP) is the multi-provider path; otherwise a single provider of each type comes from PEP_* env.
	var opts []proxy.ProviderOption
	if cfgPath != "" {
		var err error
		if opts, err = loadProviders(cfgPath, publicURL); err != nil {
			log.Fatalf("load providers from %s: %v", cfgPath, err)
		}
		slog.Info("providers loaded from config", "path", cfgPath)
	} else {
		opts = providersFromEnv(publicURL)
	}

	if len(opts) == 0 {
		log.Fatal("configure providers via PEP_CONFIG_PATH, or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_GEMIDP_CLIENT_ID")
	}

	server, err := proxy.New(proxy.Config{
		Backend:          proxy.NewProviderBackend(opts...),
		Store:            openStore(),
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
