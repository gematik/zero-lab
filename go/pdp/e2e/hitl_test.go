package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// TestHITL_AuthorizationCode runs the full authorization-code flow through a real OpenID
// Provider, requiring a human to complete the browser login. Gated by ZERO_PDP_E2E_HITL.
func TestHITL_AuthorizationCode(t *testing.T) {
	if os.Getenv("ZERO_PDP_E2E_HITL") == "" {
		t.Skip("ZERO_PDP_E2E_HITL not set — skipping human-in-the-loop flow")
	}
	base := baseURL(t)
	md := getMetadata(t, base)
	providers := getOpenidProviders(t, md)
	if len(providers) == 0 {
		t.Skip("no OpenID Provider configured — see docs/e2e.md")
	}

	opIssuer := env("ZERO_PDP_E2E_OP_ISSUER", defaultOPIssuer)
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	clientSecret := env("ZERO_PDP_E2E_CLIENT_SECRET", defaultClientSecret)
	scope := env("ZERO_PDP_E2E_SCOPE", defaultScope)
	addr := env("ZERO_PDP_E2E_CALLBACK_ADDR", defaultCallbackAddr)

	cb := startCallbackServer(t, addr)
	redirectURI := env("ZERO_PDP_E2E_REDIRECT_URI", cb.redirectURI)

	verifier, challenge := pkce()
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
	authURL := md.AuthorizationEndpoint + "?" + q.Encode()

	t.Logf("\n\n=== HUMAN ACTION REQUIRED ===\nComplete the login in the browser:\n%s\n\n(waiting up to 3 minutes for the callback to %s)\n", authURL, cb.redirectURI)
	_ = openBrowser(authURL)

	res := cb.wait(t, 3*time.Minute)
	if res.Error != "" {
		t.Fatalf("authorization failed: %s: %s", res.Error, res.Desc)
	}
	if res.State != state {
		t.Fatalf("state mismatch: got %q, want %q", res.State, state)
	}
	if res.Code == "" {
		t.Fatal("no authorization code in callback")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {res.Code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	// Confidential clients authenticate via HTTP Basic (client_secret_basic, per the AS
	// metadata); public clients send client_id in the form instead.
	if clientSecret == "" {
		form.Set("client_id", clientID)
	}
	req, _ := http.NewRequest(http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
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
	verifyAccessToken(t, tr.AccessToken, getJWKS(t, md))
	t.Logf("OK: full authorization-code flow completed; access token verifies (%s, expires_in=%d)", tr.TokenType, tr.ExpiresIn)

	// Introspect the issued token: as the issuing client it is active and carries the upstream
	// OIDC identity captured during the login.
	_, ir := introspect(t, md, clientID, clientSecret, tr.AccessToken)
	if !ir.Active {
		t.Fatal("introspect: active=false, want true")
	}
	if ir.Sub == "" {
		t.Error("introspect: empty sub")
	}
	if len(ir.Identity) == 0 {
		t.Error("introspect: empty identity for an authorization-code session")
	}
	t.Logf("OK: introspection returned the upstream identity (sub=%s, %d id_token claims)", ir.Sub, len(ir.Identity))
}

// openBrowser best-effort opens a URL in the default browser.
func openBrowser(rawURL string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, rawURL)...).Start()
}
