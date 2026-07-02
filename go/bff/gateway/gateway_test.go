package gateway_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/bff/gateway"
	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func testKey(t *testing.T) jwk.Key {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := jwk.Import(prk)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func thumbprint(t *testing.T, k jwk.Key) string {
	t.Helper()
	b, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// mockAS serves just enough for bff.New to discover the AS and for a refresh to succeed.
func mockAS(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                    base,
			"authorization_endpoint":    base + "/auth",
			"token_endpoint":            base + "/token",
			"introspection_endpoint":    base + "/introspect",
			"openid_providers_endpoint": base + "/openid-providers",
			"nonce_endpoint":            base + "/nonce",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "refreshed-token", "token_type": "Bearer", "expires_in": 3600,
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// upstream records the last request it received so a test can assert what the gateway forwarded.
type upstream struct {
	*httptest.Server
	last *http.Request
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.last = r.Clone(context.Background())
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(u.Close)
	return u
}

var testIdentity = map[string]any{"identity": map[string]any{"sub": "user-123", "name": "Test User"}}

func newBFF(t *testing.T, dpopKey jwk.Key) (*bff.BackendForFrontend, bff.SessionManager) {
	t.Helper()
	as := mockAS(t)
	sm := bff.NewSessionManager(kv.NewMemory(), 0)
	b, err := bff.New(bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:      as.URL,
			ClientID:    "bff-client",
			RedirectURI: "http://bff.example/bff/auth/callback",
			SigningKey:  testKey(t),
			DPoPKey:     dpopKey,
		},
		CookieName:          "test-cookie",
		FrontendRedirectURI: "http://bff.example/bff/",
		SessionManager:      sm,
	})
	if err != nil {
		t.Fatalf("bff.New: %v", err)
	}
	return b, sm
}

func seedSession(t *testing.T, sm bff.SessionManager, accessToken string, expiry time.Time) *http.Cookie {
	t.Helper()
	s, err := sm.CreateSession("state", "verifier", "S256")
	if err != nil {
		t.Fatal(err)
	}
	s.AccessToken = accessToken
	s.AccessTokenExpiresAt = expiry
	s.RefreshToken = "refresh-token"
	s.Identity = testIdentity
	if err := sm.UpdateSession(s); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "test-cookie", Value: s.ID}
}

func TestIdentityInjection(t *testing.T) {
	up := newUpstream(t)
	b, sm := newBFF(t, testKey(t))
	gw, err := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectIdentity},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := seedSession(t, sm, "access-token", time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/app/home", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body)
	}
	raw := up.last.Header.Get("X-Auth-Request-Identity")
	if raw == "" {
		t.Fatal("upstream did not receive identity header")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("identity header not base64url: %v", err)
	}
	var id map[string]any
	if err := json.Unmarshal(decoded, &id); err != nil {
		t.Fatalf("identity header not JSON: %v", err)
	}
	if id["sub"] != "user-123" {
		t.Errorf("identity sub = %v, want user-123", id["sub"])
	}
	if up.last.Header.Get("Authorization") != "" {
		t.Error("identity route must not forward an Authorization header")
	}
}

func TestDPoPInjection(t *testing.T) {
	up := newUpstream(t)
	dpopKey := testKey(t)
	b, sm := newBFF(t, dpopKey)
	gw, err := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/api/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectDPoP},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := seedSession(t, sm, "access-token", time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/api/resource", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if got := up.last.Header.Get("Authorization"); got != "DPoP access-token" {
		t.Fatalf("Authorization = %q, want %q", got, "DPoP access-token")
	}
	// The proof must validate as a resource-server DPoP proof bound to the forwarded token.
	binding, derr := dpop.ParseRequest(up.last, dpop.ParseOptions{AuthorizationRequired: true})
	if derr != nil {
		t.Fatalf("DPoP proof invalid: %v", derr)
	}
	if binding.DPoP.KeyThumbprint != thumbprint(t, dpopKey) {
		t.Errorf("proof signed with wrong key: thumbprint %q != %q", binding.DPoP.KeyThumbprint, thumbprint(t, dpopKey))
	}
}

func TestSpoofingHygiene(t *testing.T) {
	up := newUpstream(t)
	b, sm := newBFF(t, testKey(t))
	gw, err := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectIdentity},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := seedSession(t, sm, "access-token", time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/app", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-Auth-Request-Identity", "spoofed")
	req.Header.Set("Authorization", "Bearer evil")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if got := up.last.Header.Get("Authorization"); got != "" {
		t.Errorf("client Authorization leaked upstream: %q", got)
	}
	raw := up.last.Header.Get("X-Auth-Request-Identity")
	if raw == "spoofed" {
		t.Fatal("client-spoofed identity header reached upstream")
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(raw)
	var id map[string]any
	_ = json.Unmarshal(decoded, &id)
	if id["sub"] != "user-123" {
		t.Errorf("identity = %v, want the gateway's value", id)
	}
}

func TestUnauthenticatedHTMLRedirects(t *testing.T) {
	b, _ := newBFF(t, testKey(t))
	up := newUpstream(t)
	gw, _ := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectIdentity},
	}})

	req := httptest.NewRequest("GET", "/dashboard?tab=1", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if want := "/bff/?rd=%2Fdashboard%3Ftab%3D1"; loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestUnauthenticatedXHRGets401(t *testing.T) {
	b, _ := newBFF(t, testKey(t))
	up := newUpstream(t)
	gw, _ := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/api/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectDPoP},
	}})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

func TestUnprotectedPassthrough(t *testing.T) {
	up := newUpstream(t)
	b, _ := newBFF(t, testKey(t))
	gw, _ := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/public/", UpstreamURL: up.URL, Protected: false},
	}})

	req := httptest.NewRequest("GET", "/public/asset.js", nil) // no cookie
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (unprotected)", rec.Code)
	}
	if up.last == nil {
		t.Fatal("unprotected request did not reach the upstream")
	}
}

func TestHandlerGatewayRouting(t *testing.T) {
	up := newUpstream(t)
	b, _ := newBFF(t, testKey(t))
	uiFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>login ui</html>")},
		"style.css":  {Data: []byte("body{}")},
	}
	h, err := gateway.Handler(b, uiFS, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectIdentity},
	}})
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string, html bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if html {
			req.Header.Set("Accept", "text/html")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/bff/", false); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "login ui") {
		t.Errorf("/bff/ = %d %q, want the login UI", rec.Code, rec.Body)
	}
	if rec := get("/bff/style.css", false); rec.Code != http.StatusOK {
		t.Errorf("/bff/style.css = %d, want 200", rec.Code)
	}
	if rec := get("/bff/auth/session", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("/bff/auth/session = %d, want 401 (auth endpoint reachable)", rec.Code)
	}
	if rec := get("/dashboard", true); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/bff/?rd=%2Fdashboard" {
		t.Errorf("/dashboard = %d loc=%q, want 302 → /bff/?rd=%%2Fdashboard", rec.Code, rec.Header().Get("Location"))
	}
}

func TestStripPrefix(t *testing.T) {
	up := newUpstream(t)
	dpopKey := testKey(t)
	b, sm := newBFF(t, dpopKey)
	gw, err := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/api/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectDPoP, StripPrefix: true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cookie := seedSession(t, sm, "access-token", time.Now().Add(time.Hour))

	req := httptest.NewRequest("GET", "/api/resource", nil)
	req.AddCookie(cookie)
	gw.ServeHTTP(httptest.NewRecorder(), req)

	if up.last.URL.Path != "/resource" {
		t.Fatalf("upstream path = %q, want /resource (prefix stripped)", up.last.URL.Path)
	}
	// The DPoP proof's htu must match the stripped URL the resource server actually sees.
	if _, derr := dpop.ParseRequest(up.last, dpop.ParseOptions{AuthorizationRequired: true}); derr != nil {
		t.Fatalf("DPoP proof invalid after strip: %v", derr)
	}
}

func TestRefreshRotationRepersists(t *testing.T) {
	up := newUpstream(t)
	dpopKey := testKey(t)
	b, sm := newBFF(t, dpopKey)
	gw, _ := gateway.New(b, gateway.Config{Routes: []gateway.Route{
		{PathPrefix: "/api/", UpstreamURL: up.URL, Protected: true, Inject: gateway.InjectDPoP},
	}})
	// Expired access token → the gateway refreshes via the mock AS (which returns "refreshed-token").
	cookie := seedSession(t, sm, "stale-token", time.Now().Add(-time.Hour))

	req := httptest.NewRequest("GET", "/api/resource", nil)
	req.AddCookie(cookie)
	gw.ServeHTTP(httptest.NewRecorder(), req)

	if got := up.last.Header.Get("Authorization"); got != "DPoP refreshed-token" {
		t.Fatalf("Authorization = %q, want refreshed token", got)
	}
	stored, err := sm.GetSessionByID(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessToken != "refreshed-token" {
		t.Errorf("session not re-persisted: access token = %q", stored.AccessToken)
	}
}
