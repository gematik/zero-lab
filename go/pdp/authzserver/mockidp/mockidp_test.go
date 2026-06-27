//go:build mockidp

package mockidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"golang.org/x/oauth2"
)

type hostFunc struct {
	issuer, opCallback string
	add                func(oidc.Client)
}

func (h hostFunc) IssuerBaseURL() string     { return h.issuer }
func (h hostFunc) OPCallbackURL() string     { return h.opCallback }
func (h hostFunc) AddProvider(c oidc.Client) { h.add(c) }

func TestMockOPRunsAuthCodeFlow(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var captured oidc.Client
	host := hostFunc{issuer: srv.URL, opCallback: srv.URL + "/op-callback", add: func(c oidc.Client) { captured = c }}
	if err := Register(host, mux, Identity{Subject: "X110000001", Claims: map[string]any{"name": "Test User"}}); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("provider was not registered")
	}
	if captured.Issuer() != srv.URL+"/mock-idp" {
		t.Fatalf("issuer = %q", captured.Issuer())
	}

	verifier := oauth2.GenerateVerifier()
	authURL, err := captured.AuthenticationURL("st-1", "nonce-1", verifier)
	if err != nil {
		t.Fatal(err)
	}

	// The login page renders the auth params as a form; submit them (POST /mock-idp/auth).
	au, _ := url.Parse(authURL)
	form := url.Values{}
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge"} {
		form.Set(k, au.Query().Get(k))
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pr, err := noRedirect.PostForm(srv.URL+"/mock-idp/auth", form)
	if err != nil {
		t.Fatal(err)
	}
	if pr.StatusCode != http.StatusFound {
		t.Fatalf("auth submit status = %d, want 302", pr.StatusCode)
	}
	cu, _ := url.Parse(pr.Header.Get("Location"))
	if cu.Path != "/op-callback" || cu.Query().Get("state") != "st-1" {
		t.Fatalf("redirected to %q, want the op-callback with state", pr.Header.Get("Location"))
	}
	code := cu.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code in op-callback redirect")
	}

	// This is exactly what OPCallbackEndpoint does: real /token round-trip + id_token validation.
	tr, err := captured.ExchangeForIdentity(code, verifier)
	if err != nil {
		t.Fatalf("ExchangeForIdentity: %v", err)
	}
	claims := map[string]any{}
	if err := tr.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "X110000001" {
		t.Errorf("sub = %v, want X110000001", claims["sub"])
	}
	if claims["name"] != "Test User" {
		t.Errorf("name = %v, want Test User", claims["name"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v, want nonce-1", claims["nonce"])
	}
}
