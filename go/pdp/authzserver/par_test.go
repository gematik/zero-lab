package authzserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// a valid RFC 7636 S256 challenge (43-char base64url)
const testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

func parRequest(assertion string) *http.Request {
	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", testClientID)
	form.Set("redirect_uri", "https://rp.example.com/callback")
	form.Set("code_challenge", testCodeChallenge)
	form.Set("code_challenge_method", "S256")
	form.Set("state", "st-123")
	form.Set("scope", testScope)
	if assertion != "" {
		form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
		form.Set("client_assertion", assertion)
	}
	req := httptest.NewRequest(http.MethodPost, testIssuer+"/par", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestPAREndpointStoresSingleUseRequest(t *testing.T) {
	server, signKey := newTestServer(t)
	rec := httptest.NewRecorder()
	if err := server.PAREndpoint(rec, parRequest(signClientAssertion(t, server, signKey, nil))); err != nil {
		t.Fatalf("PAREndpoint: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.RequestURI, "urn:ietf:params:oauth:request_uri:") || resp.ExpiresIn <= 0 {
		t.Fatalf("bad PAR response: %+v", resp)
	}

	// Resolving consumes it (what /authorize does) and yields the pushed params.
	sess, err := server.sessionStore.GetAutzhServerSessionByRequestURI(resp.RequestURI)
	if err != nil {
		t.Fatalf("request_uri did not resolve: %v", err)
	}
	if sess.ClientID != testClientID || sess.State != "st-123" {
		t.Errorf("pushed params not stored: %+v", sess)
	}
	// Single-use: a replay resolves to not-found.
	if _, err := server.sessionStore.GetAutzhServerSessionByRequestURI(resp.RequestURI); err == nil {
		t.Error("request_uri resolved twice (not single-use)")
	}
}

func TestPAREndpointRequiresClientAuth(t *testing.T) {
	server, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	if err := server.PAREndpoint(rec, parRequest("")); err == nil {
		t.Fatal("PAR accepted an unauthenticated push (no client_assertion)")
	}
}
