package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSmoke_Metadata(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	if md.Issuer == "" {
		t.Fatal("metadata: empty issuer")
	}
	if md.TokenEndpoint == "" || md.JwksURI == "" || md.AuthorizationEndpoint == "" {
		t.Fatalf("metadata: missing core endpoints: %+v", md)
	}
}

func TestSmoke_JWKS(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	if set := getJWKS(t, md); set.Len() == 0 {
		t.Fatal("jwks: no keys")
	}
}

func TestSmoke_Nonce(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	resp := mustGet(t, httpClient(), md.NonceEndpoint)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nonce GET: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("nonce GET: content-type %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) == "" {
		t.Fatal("nonce GET: empty body")
	}
}

func TestSmoke_OpenidProviders(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	_ = getOpenidProviders(t, md) // 200 + JSON array (may be empty when no OP configured)
}

func TestSmoke_OIDFEntityStatement(t *testing.T) {
	base := baseURL(t)
	resp := mustGet(t, httpClient(), base+"/.well-known/openid-federation")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("OIDF entity statement not configured")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entity statement: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(strings.Split(strings.TrimSpace(string(body)), ".")) != 3 {
		t.Fatalf("entity statement: not a JWT (got %d bytes)", len(body))
	}
}
