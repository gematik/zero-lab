package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gematik/zero-lab/go/pep/proxy"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// pdpBackendFromEnv builds the PDP backend (PEP_BACKEND=pdp): pep as a confidential client of the PDP. The
// private_key_jwt signing key is read from a file (PEP_CLIENT_SIGNING_KEY_PATH), never from an env value.
func pdpBackendFromEnv(publicURL string) proxy.Backend {
	asIssuer := os.Getenv("PEP_AS_ISSUER")
	clientID := os.Getenv("PEP_CLIENT_ID")
	if asIssuer == "" || clientID == "" {
		log.Fatal("PEP_BACKEND=pdp requires PEP_AS_ISSUER and PEP_CLIENT_ID")
	}
	signingKey, err := loadJWKFile(os.Getenv("PEP_CLIENT_SIGNING_KEY_PATH"))
	if err != nil {
		log.Fatalf("PEP_CLIENT_SIGNING_KEY_PATH: %v", err)
	}
	redirect := os.Getenv("PEP_REDIRECT_URI")
	if redirect == "" {
		redirect = publicURL + "/oauth2/callback"
	}
	cfg := proxy.PDPConfig{
		ASIssuer:    asIssuer,
		ClientID:    clientID,
		SigningKey:  signingKey,
		RedirectURI: redirect,
		APIUpstream: os.Getenv("PEP_API_UPSTREAM"),
		APIPrefix:   env("PEP_API_PREFIX", "/api"),
	}
	if s := os.Getenv("PEP_SCOPES"); s != "" {
		cfg.Scopes = strings.Fields(s)
	}
	b, err := proxy.NewPDPBackend(cfg)
	if err != nil {
		log.Fatalf("pdp backend: %v", err)
	}
	return b
}

// loadJWKFile reads a single JWK (the client signing key) from a file.
func loadJWKFile(path string) (jwk.Key, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(data)
}
