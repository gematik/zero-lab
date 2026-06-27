// Command zero-pep-proxy is a standalone oauth2-proxy-style authentication gateway built on pep/proxy. It
// serves the /oauth2/* endpoints on :4180 and is meant to sit behind Caddy in forward_auth mode (see the
// Caddyfile alongside this file) or to be reverse-proxied directly.
//
// Providers run in parallel. They come from an openid-providers.yaml file (oidc[]/gemidp[]/oidf — see
// openid-providers.example.yaml); when that file is absent, the single-provider PEP_* env vars below are used
// instead. Everything else (server, session, secrets) is env-only — see CONFIG.md.
//
//	PEP_ADDR                 listen address (default :4180)
//	PEP_PUBLIC_URL           public origin the browser reaches the proxy at (default http://127.0.0.1:4180)
//	PEP_OPENID_PROVIDERS_PATH  providers YAML (default ./openid-providers.yaml); the multi-provider source
//	PEP_OIDC_ISSUER          direct OIDC provider issuer (enables single-OIDC login)
//	PEP_OIDC_CLIENT_ID / _CLIENT_SECRET / _SCOPES / _NAME / _LOGO_URI / _ACCEPTABLE_SKEW  OIDC options
//	PEP_OIDF_RP_CONFIG_PATH  gematik OIDF relying-party config (YAML); enables federation login
//	PEP_GEMIDP_CLIENT_ID     gematik IDP-Dienst client_id (enables gemidp login)
//	PEP_GEMIDP_ENV           test|ref|prod (default prod); or PEP_GEMIDP_BASE_URL to override
//	PEP_GEMIDP_REDIRECT_URI  redirect_uri the gemidp client sends (default <public>/oauth2/callback)
//	PEP_GEMIDP_REDIRECT_SCOPES / _NAME / _LOGO_URI / _USER_AGENT  gemidp options (always Authenticator flow)
//	PEP_COOKIE_NAME          session cookie name (default ZERO-PEP-SID)
//	PEP_INSECURE_COOKIE      "true" → drop __Host-/Secure for http://localhost dev; default is secure
//	PEP_TEMPLATE_DIR         replace the embedded UI templates from this directory
//	PEP_SESSION_KEY_PATH     file with a base64 256-bit key → enables local /oauth2/auth validation (decrypt
//	                         an encrypted session token, no kv per request). PEP_SESSION_PREVIOUS_KEY_PATH rotates it.
//	PEP_SESSION_TTL          session lifetime when local validation is on (Go duration, default 8h)
//	DATABASE_URL             Postgres DSN for the session store; durable + shared across replicas. When unset,
//	                         an in-memory store is used (dev only — sessions are lost on restart, not shared).
//
// Usage: zero-pep-proxy [-w workdir]
//
//	-w chdir's to workdir and loads a .env from it. openid-providers.yaml is found there (or set
//	PEP_OPENID_PROVIDERS_PATH); the OIDF config's own relative key paths always resolve against the providers
//	file's directory, not -w. ${VAR} placeholders in the providers file expand from the environment.
//
// Configure providers via openid-providers.yaml, or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_GEMIDP_CLIENT_ID.
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
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pep"
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

// openBus returns the revocation bus: Postgres LISTEN/NOTIFY when DATABASE_URL is set (so logout/lockout is
// fleet-wide), otherwise nil — a single-instance in-memory revoker.
func openBus() kv.Bus {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil
	}
	bus, err := postgres.OpenBus(context.Background(), dsn)
	if err != nil {
		log.Fatalf("open revocation bus: %v", err)
	}
	slog.Info("using postgres revocation bus (LISTEN/NOTIFY)")
	return bus
}

func main() {
	workdir := flag.String("w", "", "working directory: chdir here and load .env from it")
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
	// Load .env from the (work)dir so PEP_* and the config's ${VAR} placeholders come from one place;
	// existing environment variables take precedence.
	_ = godotenv.Load()

	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
	addr := env("PEP_ADDR", ":4180")
	publicURL := strings.TrimRight(env("PEP_PUBLIC_URL", "http://127.0.0.1:4180"), "/")

	// Default providers file: openid-providers.yaml in the workdir, absolute (its directory anchors the OIDF
	// config's relative key paths).
	if !providersExplicit {
		if abs, err := filepath.Abs("openid-providers.yaml"); err == nil {
			providersPath = abs
		}
	}

	// Providers run in parallel. When the providers file exists it is the source; otherwise a single provider
	// of each type comes from the PEP_OIDC_* / PEP_OIDF_RP_CONFIG_PATH / PEP_GEMIDP_* env vars.
	var opts []proxy.ProviderOption
	if _, statErr := os.Stat(providersPath); statErr == nil {
		var err error
		if opts, err = loadProviders(providersPath, publicURL); err != nil {
			log.Fatalf("load providers from %s: %v", providersPath, err)
		}
		slog.Info("providers loaded", "path", providersPath)
	} else if providersExplicit {
		log.Fatalf("PEP_OPENID_PROVIDERS_PATH %q does not exist: %v", providersPath, statErr)
	} else {
		opts = providersFromEnv(publicURL)
	}

	if len(opts) == 0 {
		log.Fatal("configure providers via openid-providers.yaml (PEP_OPENID_PROVIDERS_PATH), or PEP_OIDC_ISSUER / PEP_OIDF_RP_CONFIG_PATH / PEP_GEMIDP_CLIENT_ID")
	}

	var snapshotTTL time.Duration
	if v := os.Getenv("PEP_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("invalid PEP_SESSION_TTL %q: %v", v, err)
		}
		snapshotTTL = d
	}

	server, err := proxy.New(proxy.Config{
		Backend:                 proxy.NewProviderBackend(opts...),
		Store:                   openStore(),
		CookieName:              env("PEP_COOKIE_NAME", "ZERO-PEP-SID"),
		InsecureCookie:          os.Getenv("PEP_INSECURE_COOKIE") == "true",
		TemplateDir:             os.Getenv("PEP_TEMPLATE_DIR"),
		SnapshotKeyPath:         os.Getenv("PEP_SESSION_KEY_PATH"),
		SnapshotPreviousKeyPath: os.Getenv("PEP_SESSION_PREVIOUS_KEY_PATH"),
		SnapshotTTL:             snapshotTTL,
		Bus:                     openBus(),
	})
	if err != nil {
		log.Fatalf("create proxy: %v", err)
	}

	slog.Info("zero-pep-proxy listening", "version", pep.Version, "addr", addr, "public_url", publicURL)
	log.Fatal(http.ListenAndServe(addr, server.Handler()))
}
