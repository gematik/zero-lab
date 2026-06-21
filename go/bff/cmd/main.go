package main

import (
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/bff/webui"
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
	publicUrl := env("BFF_PUBLIC_URL", "http://127.0.0.1:8080")

	b, err := bff.New(bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:       env("BFF_AS_ISSUER", "http://127.0.0.1:8011"),
			ClientId:     env("BFF_CLIENT_ID", "e2e-client"),
			ClientSecret: env("BFF_CLIENT_SECRET", "e2e-client"),
			RedirectUri:  publicUrl + "/bff/auth/callback",
		},
		CookieName:          env("BFF_COOKIE_NAME", "ZETA-BFF-SID"),
		FrontendRedirectUri: publicUrl + "/",
	})
	if err != nil {
		log.Fatalf("create bff: %v", err)
	}

	mux := http.NewServeMux()
	b.Mount(mux)
	// Static SPA at /. Swappable for a React/Svelte build without touching the API.
	mux.Handle("/", http.FileServerFS(webui.FS))

	slog.Info("bff listening", "addr", addr, "public_url", publicUrl)
	log.Fatal(http.ListenAndServe(addr, bff.RecoverMiddleware(mux)))
}
