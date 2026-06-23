package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/bff/webui"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("BFF_ADDR", ":8080")
	// Public origin the browser reaches the BFF at; the AS must have <public>/bff/auth/callback
	// registered as the client's redirect_uri.
	publicURL := env("BFF_PUBLIC_URL", "http://127.0.0.1:8080")
	clientID := env("BFF_CLIENT_ID", "e2e-client")

	// The bff authenticates to the AS with private_key_jwt (RFC 7523). Generate an ephemeral signing key
	// (for the client_assertion) and DPoP key (its thumbprint is the assertion's cnf.jkt), and log the
	// public signing JWK so it can be registered as this client's public_jwk at the AS.
	signingKey, err := authzserver.GenerateRandomJwk()
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	dpopKey, err := authzserver.GenerateRandomJwk()
	if err != nil {
		log.Fatalf("generate dpop key: %v", err)
	}
	if pub, err := signingKey.PublicKey(); err == nil {
		if pubJSON, err := json.Marshal(pub); err == nil {
			slog.Info("register this public JWK as the client's public_jwk at the AS", "client_id", clientID, "public_jwk", string(pubJSON))
		}
	}

	b, err := bff.New(bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:      env("BFF_AS_ISSUER", "http://127.0.0.1:8011"),
			ClientID:    clientID,
			RedirectURI: publicURL + "/bff/auth/callback",
			SigningKey:  signingKey,
			DPoPKey:     dpopKey,
		},
		CookieName:          env("BFF_COOKIE_NAME", "ZETA-BFF-SID"),
		FrontendRedirectURI: publicURL + "/",
		SessionManager:      bff.NewSessionManager(openStore(), 0),
	})
	if err != nil {
		log.Fatalf("create bff: %v", err)
	}

	mux := http.NewServeMux()
	b.Mount(mux)
	// Static SPA at /. Swappable for a React/Svelte build without touching the API.
	mux.Handle("/", http.FileServerFS(webui.FS))

	slog.Info("bff listening", "addr", addr, "public_url", publicURL)
	log.Fatal(http.ListenAndServe(addr, bff.RecoverMiddleware(mux)))
}

// openStore returns the kv backend: Postgres when DATABASE_URL is set, otherwise an in-memory store
// (sessions are not durable across restarts).
func openStore() kv.Store {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		slog.Warn("DATABASE_URL not set — using in-memory kv store (sessions are not durable)")
		return kv.NewMemory()
	}
	store, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		log.Fatalf("open postgres kv store: %v", err)
	}
	slog.Info("using postgres kv store")
	return store
}
