package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// introspect posts a token to the introspection endpoint, optionally authenticating as a client.
func introspect(t *testing.T, md authzserver.ExtendedMetadata, clientID, secret, token string) (*http.Response, authzserver.IntrospectionResponse) {
	t.Helper()
	form := url.Values{"token": {token}}
	// Confidential clients authenticate via HTTP Basic; public clients send client_id in the form.
	if clientID != "" && secret == "" {
		form.Set("client_id", clientID)
	}
	req, _ := http.NewRequest(http.MethodPost, md.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(clientID, secret)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	var ir authzserver.IntrospectionResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
			t.Fatalf("introspect decode: %v", err)
		}
	}
	resp.Body.Close()
	return resp, ir
}

// mintClientCredentialsToken obtains an access token via the client_credentials grant.
func mintClientCredentialsToken(t *testing.T, md authzserver.ExtendedMetadata, clientID, secret, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
	req, _ := http.NewRequest(http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
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
	return tr.AccessToken
}

func TestSmoke_Introspection(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	if md.IntrospectionEndpoint == "" {
		t.Fatal("metadata: empty introspection_endpoint")
	}
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	secret := env("ZERO_PDP_E2E_CLIENT_SECRET", defaultClientSecret)

	// No client authentication → 401 (RFC 7662 §2.1).
	resp, _ := introspect(t, md, "", "", "anything")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("introspect without client auth: status %d, want 401", resp.StatusCode)
	}

	// Authenticated client, bogus token → {"active": false}.
	resp, ir := introspect(t, md, clientID, secret, "not-a-jwt")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect bogus token: status %d, want 200", resp.StatusCode)
	}
	if ir.Active {
		t.Fatal("introspect bogus token: active=true, want false")
	}
	t.Log("OK: introspection requires client auth and reports bogus tokens inactive")
}

func TestFlow_Introspection_ClientCredentials(t *testing.T) {
	base := baseURL(t)
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	secret := env("ZERO_PDP_E2E_CLIENT_SECRET", defaultClientSecret)
	scope := env("ZERO_PDP_E2E_SCOPE", defaultScope)
	md := getMetadata(t, base)

	token := mintClientCredentialsToken(t, md, clientID, secret, scope)

	_, ir := introspect(t, md, clientID, secret, token)
	if !ir.Active {
		t.Fatal("introspect own token: active=false, want true")
	}
	if ir.ClientID != clientID {
		t.Errorf("introspect: client_id=%q, want %q", ir.ClientID, clientID)
	}
	if ir.Jti == "" {
		t.Error("introspect: empty jti")
	}
	if ir.Identity != nil {
		t.Error("introspect: a client_credentials token must carry no identity")
	}
	t.Logf("OK: client introspected its own token (active, scope=%q, jti=%s)", ir.Scope, ir.Jti)
}

// TestFlow_Introspection_CrossClient verifies the ownership rule: a different authenticated client
// must not learn anything about a token it did not receive. Needs a second registered client.
func TestFlow_Introspection_CrossClient(t *testing.T) {
	base := baseURL(t)
	client2 := os.Getenv("ZERO_PDP_E2E_CLIENT2_ID")
	if client2 == "" {
		t.Skip("ZERO_PDP_E2E_CLIENT2_ID not set — skipping cross-client ownership check")
	}
	secret2 := os.Getenv("ZERO_PDP_E2E_CLIENT2_SECRET")
	clientID := env("ZERO_PDP_E2E_CLIENT_ID", defaultClientID)
	secret := env("ZERO_PDP_E2E_CLIENT_SECRET", defaultClientSecret)
	scope := env("ZERO_PDP_E2E_SCOPE", defaultScope)
	md := getMetadata(t, base)

	token := mintClientCredentialsToken(t, md, clientID, secret, scope)

	_, ir := introspect(t, md, client2, secret2, token)
	if ir.Active {
		t.Fatal("cross-client introspect: active=true, want false (ownership rule)")
	}
	t.Log("OK: a different client cannot introspect another client's token")
}
