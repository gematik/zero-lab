package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func staticSession(sess *Session) func(*http.Request) (*Session, bool) {
	return func(*http.Request) (*Session, bool) { return sess, sess != nil }
}

func TestRoutesFromEnv(t *testing.T) {
	t.Setenv("PEP_API_UPSTREAM", "http://rs:8080")
	t.Setenv("PEP_WEBAPP_UPSTREAM", "http://app:8080")
	got := routesFromEnv()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (%+v)", len(got), got)
	}
	api, web := got[0], got[1]
	if api.PathPrefix != "/api" || api.Inject != InjectDPoP || !api.StripPrefix || !api.Protected {
		t.Errorf("api route = %+v", api)
	}
	if web.PathPrefix != "/" || web.Inject != InjectIdentity || !web.Protected {
		t.Errorf("webapp route = %+v", web)
	}
}

func TestValidateRoutesSortsLongestPrefixFirst(t *testing.T) {
	in := []Route{{PathPrefix: "/", Upstream: "http://a"}, {PathPrefix: "/api", Upstream: "http://b"}}
	out, err := validateRoutes(in)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].PathPrefix != "/api" {
		t.Errorf("first prefix = %q, want /api", out[0].PathPrefix)
	}
}

func TestValidateRoutesRejectsBadUpstreamAndDupes(t *testing.T) {
	if _, err := validateRoutes([]Route{{PathPrefix: "/a", Upstream: "://nope"}}); err == nil {
		t.Error("accepted invalid upstream")
	}
	dup := []Route{{PathPrefix: "/a", Upstream: "http://x"}, {PathPrefix: "/a", Upstream: "http://y"}}
	if _, err := validateRoutes(dup); err == nil {
		t.Error("accepted duplicate prefix")
	}
}

func TestValidateRoutesRejectsBadInject(t *testing.T) {
	if _, err := validateRoutes([]Route{{PathPrefix: "/a", Upstream: "http://x", Inject: "bogus"}}); err == nil {
		t.Error("accepted invalid inject mode")
	}
}

func TestLoadRoutesYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.yaml")
	if err := os.WriteFile(p, []byte("routes:\n  - path_prefix: /api\n    upstream: http://rs:8080\n    inject: dpop\n    strip_prefix: true\n  - path_prefix: /open\n    upstream: http://x:8080\n    protected: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRoutes(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Inject != InjectDPoP || !got[0].StripPrefix || !got[0].Protected {
		t.Errorf("api route = %+v", got[0])
	}
	if got[1].Protected {
		t.Error("protected:false should be honored")
	}
}

func TestGatewayLongestPrefixMatch(t *testing.T) {
	gw, err := newGateway(staticSession(nil), &fakeBackend{}, []Route{
		{PathPrefix: "/", Upstream: "http://app"},
		{PathPrefix: "/api", Upstream: "http://rs"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rt := gw.match("/api/x"); rt == nil || rt.PathPrefix != "/api" {
		t.Errorf("match(/api/x) = %v, want /api", rt)
	}
	if rt := gw.match("/home"); rt == nil || rt.PathPrefix != "/" {
		t.Errorf("match(/home) = %v, want /", rt)
	}
}

func TestGatewayUnauthenticatedBranch(t *testing.T) {
	gw, err := newGateway(staticSession(nil), &fakeBackend{}, []Route{
		{PathPrefix: "/", Upstream: "http://app:8080", Protected: true, Inject: InjectIdentity},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("html unauth: status %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/oauth2/sign_in") {
		t.Errorf("redirect = %q, want /oauth2/sign_in…", loc)
	}

	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/api/data", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("api unauth: status %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want json", ct)
	}
}

func TestGatewayIdentityInjection(t *testing.T) {
	var gotPath, gotIdentity, gotForgedUser string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotIdentity = r.Header.Get("X-Auth-Request-Identity")
		gotForgedUser = r.Header.Get("X-Auth-Request-User")
	}))
	defer upstream.Close()

	sess := &Session{Identity: map[string]any{"sub": "u-1", "preferred_username": "alice"}}
	gw, err := newGateway(staticSession(sess), &fakeBackend{}, []Route{
		{PathPrefix: "/app", Upstream: upstream.URL, Protected: true, Inject: InjectIdentity, StripPrefix: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/app/page", nil)
	req.Header.Set("X-Auth-Request-User", "attacker")
	gw.ServeHTTP(rec, req)

	if gotPath != "/page" {
		t.Errorf("upstream path = %q, want /page (strip)", gotPath)
	}
	if gotForgedUser == "attacker" {
		t.Error("client-forged X-Auth-Request-User reached upstream")
	}
	if gotIdentity == "" {
		t.Fatal("X-Auth-Request-Identity not injected")
	}
	raw, err := base64.RawURLEncoding.DecodeString(gotIdentity)
	if err != nil {
		t.Fatalf("identity not base64url: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "u-1" {
		t.Errorf("identity claims = %v", claims)
	}
}

func TestGatewayUnprotectedPassthrough(t *testing.T) {
	hit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer upstream.Close()

	gw, err := newGateway(staticSession(nil), &fakeBackend{}, []Route{
		{PathPrefix: "/public", Upstream: upstream.URL, Protected: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/public/x", nil))
	if !hit {
		t.Error("unprotected route did not reach the upstream")
	}
}
