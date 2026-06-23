package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// TestFlow_FederationPAR drives an OpenID Federation IdP (type "oidf") via /authorization and
// asserts the pdp (relying party) successfully performed a Pushed Authorization Request against
// it — the checkpoint is the redirect to the IdP carrying request_uri. No human login. Picks the
// gematik sectoral IDP if present, else the first oidf provider; override with
// ZERO_PDP_E2E_FED_ISSUER. Requires the pdp reachable at its public federation entity URL.
func TestFlow_FederationPAR(t *testing.T) {
	base := baseURL(t)
	md := getMetadata(t, base)

	hasOIDF := false
	for _, p := range getOpenidProviders(t, md) {
		if p.Type == "oidf" {
			hasOIDF = true
			break
		}
	}
	if !hasOIDF {
		t.Skip("no OIDF federation providers configured")
	}

	opIssuer := env("ZERO_PDP_E2E_FED_ISSUER", defaultFedIssuer)
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	redirectURI := env("ZERO_PDP_E2E_REDIRECT_URI", defaultRedirectURI)
	scope := env("ZERO_PDP_E2E_SCOPE", defaultScope)
	_, challenge := pkce()
	state := randString()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"scope":                 {scope},
		"op_issuer":             {opIssuer},
	}

	// Federation discovery + automatic registration + PAR involve several upstream fetches.
	c := &http.Client{
		Timeout:       90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Logf("driving federation IdP %s", opIssuer)
	resp, err := c.Get(md.AuthorizationEndpoint + "?" + q.Encode())
	if err != nil {
		t.Fatalf("GET authorization: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorization: status %d, want 302: %s", resp.StatusCode, body)
	}
	locURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if hostOf(t, redirectURI) == locURL.Host && locURL.Query().Get("error") != "" {
		t.Skipf("pdp could not drive the federation IdP (error=%s: %s) — check rathole/federation reachability",
			locURL.Query().Get("error"), locURL.Query().Get("error_description"))
	}
	if locURL.Query().Get("request_uri") == "" {
		t.Fatalf("federation IdP redirect lacks request_uri (PAR expected): %s", locURL.String())
	}
	t.Logf("OK: pdp→federation-IdP PAR succeeded — request_uri present, IdP host=%s", locURL.Host)
}

// TestFlow_ClientCredentials is a complete, non-interactive token flow: it issues an access
// token via client_credentials and verifies it against the server JWKS.
func TestFlow_ClientCredentials(t *testing.T) {
	base := baseURL(t)
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	scope := env("ZERO_PDP_E2E_SCOPE", defaultScope)
	md := getMetadata(t, base)

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	addClientAuth(form, clientAssertion(t, md, clientID, clientKey(t)))
	req, _ := http.NewRequest(http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token: status %d: %s", resp.StatusCode, body)
	}
	var tr authzserver.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		t.Fatalf("token decode: %v", err)
	}
	if tr.AccessToken == "" {
		t.Fatal("token: empty access_token")
	}
	tok := verifyAccessToken(t, tr.AccessToken, getJWKS(t, md))
	if sub, _ := tok.Subject(); sub != clientID {
		t.Errorf("access token sub = %q, want %q", sub, clientID)
	}
	t.Logf("OK: client_credentials issued a verifiable %s token (expires_in=%d)", tr.TokenType, tr.ExpiresIn)
}
