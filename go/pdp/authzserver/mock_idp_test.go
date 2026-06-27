package authzserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestMockIDPCompletesAuthCodeFlow(t *testing.T) {
	server, _ := newTestServer(t)
	server.nonProdMode = true
	server.mockIDP = &MockIDPConfig{Subject: "X110000001", Claims: map[string]any{"name": "Test User"}}

	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {"https://rp.example.com/callback"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
		"state":                 {"st-123"},
		"scope":                 {testScope},
	}
	req := httptest.NewRequest(http.MethodGet, "/auth?"+form.Encode(), nil)
	rec := httptest.NewRecorder()
	if err := server.AuthorizationEndpoint(rec, req); err != nil {
		t.Fatalf("AuthorizationEndpoint: %v", err)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.example.com/callback?") {
		t.Fatalf("redirected to %q, want the client callback (no real OP)", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" || u.Query().Get("state") != "st-123" {
		t.Errorf("missing code or wrong state: %q", loc)
	}
}

func TestIntrospectionSurfacesMockIdentity(t *testing.T) {
	server, signKey := newTestServer(t)
	server.nonProdMode = true
	server.mockIDP = &MockIDPConfig{Subject: "X110000001", Claims: map[string]any{"name": "Test User"}}

	sess := &AuthzServerSession{
		ClientID:            testClientID,
		Audience:            []string{testClientID},
		Scopes:              []string{testScope},
		AccessTokenDuration: 5 * time.Minute,
		ExpiresAt:           time.Now().Add(time.Hour),
		MockClaims:          map[string]any{"sub": "X110000001", "name": "Test User"},
	}
	if err := server.NonProdStartSession(sess); err != nil {
		t.Fatalf("NonProdStartSession: %v", err)
	}
	tr, err := server.NonProdIssueTokens(sess.ID)
	if err != nil {
		t.Fatalf("NonProdIssueTokens: %v", err)
	}

	form := url.Values{}
	form.Set("token", tr.AccessToken)
	form.Set("client_assertion_type", ClientAssertionTypeJWTBearer)
	form.Set("client_assertion", signClientAssertion(t, server, signKey, nil))
	req := httptest.NewRequest(http.MethodPost, testIssuer+"/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	if err := server.IntrospectionEndpoint(rec, req); err != nil {
		t.Fatalf("IntrospectionEndpoint: %v", err)
	}
	var resp IntrospectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active {
		t.Fatalf("token not active: %s", rec.Body.String())
	}
	if resp.Sub != "X110000001" {
		t.Errorf("sub = %q, want X110000001", resp.Sub)
	}
	if resp.Identity["name"] != "Test User" {
		t.Errorf("identity = %v, want name=Test User", resp.Identity)
	}
}
