package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// dpopTestBackend is a Backend that yields a token and forwards DPoP via the real pdpBackend minting.
type dpopTestBackend struct {
	fakeBackend
	pdp *pdpBackend
}

func (d *dpopTestBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	return "test-token", nil
}

func (d *dpopTestBackend) injectDPoP(out *http.Request, sess *Session, token string) error {
	return d.pdp.injectDPoP(out, sess, token)
}

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
	if api.PathPrefix != "/api" || api.Inject != InjectDPoP || !api.StripPrefix || api.Gate != GateSession {
		t.Errorf("api route = %+v", api)
	}
	if web.PathPrefix != "/" || web.Inject != InjectIdentity || web.Gate != GateSnapshot {
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

func TestValidateRoutesDPoPRequiresSessionGate(t *testing.T) {
	if _, err := validateRoutes([]Route{{PathPrefix: "/api", Upstream: "http://rs", Inject: InjectDPoP, Gate: GateSnapshot}}); err == nil {
		t.Error("dpop route accepted with gate: snapshot")
	}
	// dpop defaults to gate: session and is accepted.
	out, err := validateRoutes([]Route{{PathPrefix: "/api", Upstream: "http://rs", Inject: InjectDPoP}})
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Gate != GateSession {
		t.Errorf("dpop gate defaulted to %q, want session", out[0].Gate)
	}
}

func TestLoadRoutesYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.yaml")
	if err := os.WriteFile(p, []byte("routes:\n  - path_prefix: /api\n    upstream: http://rs:8080\n    inject: dpop\n    gate: session\n    strip_prefix: true\n  - path_prefix: /open\n    upstream: http://x:8080\n    gate: none\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadRoutes(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Inject != InjectDPoP || !got[0].StripPrefix || got[0].Gate != GateSession {
		t.Errorf("api route = %+v", got[0])
	}
	if got[1].Gate != GateNone {
		t.Errorf("open route gate = %q, want none", got[1].Gate)
	}
}

func TestGatewayLongestPrefixMatch(t *testing.T) {
	gw, err := newGateway([]Route{
		{PathPrefix: "/", Upstream: "http://app"},
		{PathPrefix: "/api", Upstream: "http://rs"},
	}, gatewayDeps{currentSession: staticSession(nil), backend: &fakeBackend{}})
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
	gw, err := newGateway([]Route{
		{PathPrefix: "/", Upstream: "http://app:8080", Inject: InjectIdentity, Gate: GateSession},
	}, gatewayDeps{currentSession: staticSession(nil), backend: &fakeBackend{}})
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
	gw, err := newGateway([]Route{
		{PathPrefix: "/app", Upstream: upstream.URL, Inject: InjectIdentity, Gate: GateSession, StripPrefix: true},
	}, gatewayDeps{currentSession: staticSession(sess), backend: &fakeBackend{}})
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

	gw, err := newGateway([]Route{
		{PathPrefix: "/public", Upstream: upstream.URL, Gate: GateNone},
	}, gatewayDeps{currentSession: staticSession(nil), backend: &fakeBackend{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/public/x", nil))
	if !hit {
		t.Error("unprotected route did not reach the upstream")
	}
}

func TestServerMountsOAuthBeforeGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(299) // sentinel: the gateway proxied to the upstream
	}))
	defer upstream.Close()

	s, err := New(Config{
		Backend:    &fakeBackend{identity: map[string]any{"sub": "u1"}},
		Store:      kv.NewMemory(),
		CookieName: "TEST-SID",
		Routes:     []Route{{PathPrefix: "/", Upstream: upstream.URL, Gate: GateNone}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/sign_in", nil))
	if rec.Code == 299 {
		t.Fatal("/oauth2/* was proxied to the upstream — pep must serve it")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/anything", nil))
	if rec.Code != 299 {
		t.Fatalf("gateway route not reached: status %d", rec.Code)
	}
}

func TestGatewayScopeGate(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer upstream.Close()
	routes := []Route{{PathPrefix: "/", Upstream: upstream.URL, Inject: InjectIdentity, Gate: GateSession, Scope: "admin"}}

	allowed := &Session{Identity: map[string]any{"sub": "u1", "scope": "read admin"}}
	gw, err := newGateway(routes, gatewayDeps{currentSession: staticSession(allowed), backend: &fakeBackend{}})
	if err != nil {
		t.Fatal(err)
	}
	gw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if !reached {
		t.Error("required scope present but upstream not reached")
	}

	reached = false
	denied := &Session{Identity: map[string]any{"sub": "u1", "scope": "read"}}
	gw2, _ := newGateway(routes, gatewayDeps{currentSession: staticSession(denied), backend: &fakeBackend{}})
	rec := httptest.NewRecorder()
	gw2.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if reached {
		t.Error("upstream reached without the required scope")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestGatewayDPoPInjection(t *testing.T) {
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	sess := &Session{Identity: map[string]any{"sub": "u1"}, DPoPKeyJWK: jwkJSON}

	var gotAuth, gotProof string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProof = r.Header.Get("DPoP")
	}))
	defer upstream.Close()

	backend := &dpopTestBackend{pdp: &pdpBackend{signer: bffSigner{}}}
	gw, err := newGateway([]Route{
		{PathPrefix: "/api", Upstream: upstream.URL, Inject: InjectDPoP, Gate: GateSession, StripPrefix: true},
	}, gatewayDeps{currentSession: staticSession(sess), backend: backend})
	if err != nil {
		t.Fatal(err)
	}
	gw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/orders", nil))

	if !strings.HasPrefix(gotAuth, "DPoP ") {
		t.Errorf("Authorization = %q, want DPoP <token>", gotAuth)
	}
	if gotProof == "" {
		t.Error("DPoP proof header not set")
	}
}

func TestGatewaySnapshotGate(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	snap := &snapshotter{encKey: key, decKeys: [][]byte{key}, ttl: time.Hour}
	cookie, err := snap.mint("sid-1", map[string]any{"sub": "u9"})
	if err != nil {
		t.Fatal(err)
	}

	var gotIdentity string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = r.Header.Get("X-Auth-Request-Identity")
	}))
	defer upstream.Close()

	gw, err := newGateway([]Route{
		{PathPrefix: "/", Upstream: upstream.URL, Inject: InjectIdentity, Gate: GateSnapshot},
	}, gatewayDeps{currentSession: staticSession(nil), backend: &fakeBackend{}, cookieName: "SID", snapshotKeys: [][]byte{key}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/page", nil)
	req.AddCookie(&http.Cookie{Name: "SID", Value: cookie})
	gw.ServeHTTP(httptest.NewRecorder(), req)

	if gotIdentity == "" {
		t.Fatal("snapshot gate: identity not injected")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(gotIdentity)
	var claims map[string]any
	json.Unmarshal(raw, &claims)
	if claims["sub"] != "u9" {
		t.Errorf("identity = %v", claims)
	}
}
