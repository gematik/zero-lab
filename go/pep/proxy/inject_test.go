package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
)

func TestAPIProxyInjectsDPoP(t *testing.T) {
	var gotAuth, gotDPoP string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get(dpop.DPoPHeaderName)
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	_, jwkJSON, _ := newSessionDPoPKey()
	sess := &Session{
		ID:         "s1",
		Identity:   map[string]any{"sub": "u1"},
		DPoPKeyJWK: jwkJSON,
		Tokens:     map[string]*TokenEntry{"https://as": {AccessToken: "the-token", ExpiresAt: time.Now().Add(time.Hour)}},
	}
	b := &pdpBackend{
		cfg:    PDPConfig{ASIssuer: "https://as", APIPrefix: "/api", APIUpstream: up.URL},
		http:   up.Client(),
		signer: bffSigner{},
	}
	handler := b.apiProxy(func(r *http.Request) (*Session, bool) { return sess, true })

	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer evil")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if gotAuth != "DPoP the-token" {
		t.Fatalf("Authorization = %q, want DPoP the-token (client Bearer stripped)", gotAuth)
	}
	proof, err := dpop.Parse(gotDPoP)
	if err != nil {
		t.Fatalf("DPoP proof: %v", err)
	}
	if proof.HttpMethod != "GET" || !strings.HasSuffix(proof.HttpURI, "/protected") {
		t.Errorf("proof htm/htu = %s %s (want GET …/protected, prefix stripped)", proof.HttpMethod, proof.HttpURI)
	}
	ath, _ := dpop.CalculateAccessTokenHash("the-token")
	if proof.AccessTokenHash != ath {
		t.Errorf("ath = %q, want %q", proof.AccessTokenHash, ath)
	}
}

func TestAPIProxyRejectsUnauthenticated(t *testing.T) {
	b := &pdpBackend{cfg: PDPConfig{APIPrefix: "/api", APIUpstream: "http://unused"}, signer: bffSigner{}}
	handler := b.apiProxy(func(r *http.Request) (*Session, bool) { return nil, false })
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
