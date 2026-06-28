# pep gateway (S5) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Generalize pep's single `/api` DPoP proxy into a flexible multi-route reverse-proxy gateway that
gates and proxies a set of upstreams standalone, injecting identity or a DPoP-bound token per route.

**Architecture:** A Server-level `Gateway` `http.Handler` built from a validated route table, mounted after
`/oauth2/*`. Routing/gating/identity injection are backend-agnostic (reuse `headers.go`); DPoP injection is
delegated to a token-bearing backend (the PDP backend) via a small optional interface, generalizing the
existing per-session proof minting. The current `apiBackend.mountAPI` path is subsumed.

**Tech Stack:** Go, `net/http/httputil.ReverseProxy`, `gopkg.in/yaml.v3` (already used by pep config),
`github.com/gematik/zero-lab/go/dpop`.

**Spec:** [`gateway.md`](gateway.md).

## Global Constraints

- Branch `feat/pep-gateway` off `main` (prefix `feat`). Ask before commit. Never push.
- `/oauth2/*` is always mounted first and must win the mux; a `/` webapp route must never shadow it.
- The gateway is active only when routes are configured; with none, pep is forward_auth-only — `handleAuth`
  is unchanged (bare 401, Caddy redirects).
- `dpop` routes require a backend implementing the DPoP injector (the PDP backend) — a `dpop` route with the
  provider backend is a startup error.
- DPoP is per-session (`Session.DPoPKeyJWK`), not a backend-wide key.
- Module-graph guard must stay 0: `go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|pep/proxy\)'` → `0`.
- Naming: Go-idiomatic initialisms (DPoP, URL, JWK). Env vars holding a path end in `_PATH`.
- No narration comments; comments explain *why*. Match surrounding style.

## File Structure

| File | Responsibility |
| --- | --- |
| `pep/proxy/gateway.go` (new) | `Route`, `InjectMode`, `Gateway` engine: longest-prefix match, gating, per-route reverse proxy + injection (Rewrite), `handleUnauthenticated`. |
| `pep/proxy/gateway_config.go` (new) | Route loading: `routesFromEnv()` + `loadRoutes(path)` (YAML) + `validateRoutes()`. |
| `pep/proxy/gateway_test.go` (new) | Unit tests for the engine + config. |
| `pep/proxy/backend.go` (modify) | Add the `dpopForwarder` optional interface. |
| `pep/proxy/backend_pdp.go` (modify) | Add `injectDPoP(out, sess, token)` (refactor from `apiProxy`); drop `mountAPI`/`apiProxy` + `PDPConfig.APIPrefix`/`APIUpstream`. |
| `pep/proxy/inject.go` (delete) | Subsumed by `gateway.go`. |
| `pep/proxy/proxy.go` (modify) | `Config.Routes`; `Handler()` builds + mounts the `Gateway` (replacing the `apiBackend` block); drop the `apiBackend` interface. |
| `pep/cmd/zero-pep-proxy/main.go` (modify) | Read `PEP_ROUTES_PATH` / `PEP_API_UPSTREAM` / `PEP_WEBAPP_UPSTREAM` → `Config.Routes`. |
| `pep/cmd/zero-pep-proxy/CONFIG.md`, `pep/proxy/e2e/README.md` (modify) | Document the gateway vars + the standalone shape. |

---

### Task 1: Route type + config loading + validation

**Files:**
- Create: `pep/proxy/gateway_config.go`
- Test: `pep/proxy/gateway_test.go`

**Interfaces:**
- Produces: `type InjectMode string` (`InjectNone`/`InjectIdentity`/`InjectDPoP`); `type Route struct{PathPrefix, Upstream string; Protected bool; Inject InjectMode; StripPrefix bool}`; `routesFromEnv() []Route`; `loadRoutes(path string) ([]Route, error)`; `validateRoutes(routes []Route) ([]Route, error)` (returns longest-prefix-sorted routes or an error).

- [ ] **Step 1: Write the failing test**

```go
// pep/proxy/gateway_test.go
package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

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
	if _, err := validateRoutes([]Route{{PathPrefix: "/a", Upstream: "::nope"}}); err == nil {
		t.Error("accepted invalid upstream")
	}
	dup := []Route{{PathPrefix: "/a", Upstream: "http://x"}, {PathPrefix: "/a", Upstream: "http://y"}}
	if _, err := validateRoutes(dup); err == nil {
		t.Error("accepted duplicate prefix")
	}
}

func TestLoadRoutesYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "routes.yaml")
	os.WriteFile(p, []byte("routes:\n  - path_prefix: /api\n    upstream: http://rs:8080\n    inject: dpop\n    strip_prefix: true\n"), 0o600)
	got, err := loadRoutes(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Inject != InjectDPoP || !got[0].StripPrefix {
		t.Fatalf("loaded = %+v", got)
	}
	if !got[0].Protected {
		t.Error("Protected should default true")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run 'TestRoutes|TestValidateRoutes|TestLoadRoutes' -v`
Expected: FAIL (undefined: Route, routesFromEnv, …).

- [ ] **Step 3: Implement**

```go
// pep/proxy/gateway_config.go
package proxy

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type InjectMode string

const (
	InjectNone     InjectMode = ""
	InjectIdentity InjectMode = "identity"
	InjectDPoP     InjectMode = "dpop"
)

// Route maps a path prefix to an upstream. Protected routes require an authenticated session; Inject (only
// meaningful when Protected) selects what is forwarded to identify/authorize the user.
type Route struct {
	PathPrefix  string     `yaml:"path_prefix"`
	Upstream    string     `yaml:"upstream"`
	Protected   bool       `yaml:"protected"`
	Inject      InjectMode `yaml:"inject"`
	StripPrefix bool       `yaml:"strip_prefix"`

	upstream *url.URL
}

// routesFromEnv builds the two common routes from env shortcuts: PEP_API_UPSTREAM (/api, DPoP, strip) and
// PEP_WEBAPP_UPSTREAM (/, identity). Empty when neither is set.
func routesFromEnv() []Route {
	var routes []Route
	if u := os.Getenv("PEP_API_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/api", Upstream: u, Protected: true, Inject: InjectDPoP, StripPrefix: true})
	}
	if u := os.Getenv("PEP_WEBAPP_UPSTREAM"); u != "" {
		routes = append(routes, Route{PathPrefix: "/", Upstream: u, Protected: true, Inject: InjectIdentity})
	}
	return routes
}

type routesFile struct {
	Routes []Route `yaml:"routes"`
}

// loadRoutes reads a routes YAML. Routes default to Protected unless the file sets protected:false — yaml
// zero-values bool to false, so we re-read with a presence-aware decode.
func loadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routes %q: %w", path, err)
	}
	// Default Protected=true: decode into a map first to see which keys were set.
	var probe struct {
		Routes []map[string]any `yaml:"routes"`
	}
	if err := yaml.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("parse routes %q: %w", path, err)
	}
	var f routesFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse routes %q: %w", path, err)
	}
	for i := range f.Routes {
		if _, set := probe.Routes[i]["protected"]; !set {
			f.Routes[i].Protected = true
		}
	}
	return f.Routes, nil
}

// validateRoutes parses each upstream, rejects duplicate prefixes, and returns the routes sorted
// longest-prefix-first (so "/api" wins over "/").
func validateRoutes(routes []Route) ([]Route, error) {
	seen := map[string]bool{}
	out := make([]Route, len(routes))
	copy(out, routes)
	for i := range out {
		rt := &out[i]
		if rt.PathPrefix == "" {
			return nil, fmt.Errorf("route %d: empty path_prefix", i)
		}
		if seen[rt.PathPrefix] {
			return nil, fmt.Errorf("duplicate route prefix %q", rt.PathPrefix)
		}
		seen[rt.PathPrefix] = true
		u, err := url.Parse(rt.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("route %q: invalid upstream %q", rt.PathPrefix, rt.Upstream)
		}
		rt.upstream = u
		switch rt.Inject {
		case InjectNone, InjectIdentity, InjectDPoP:
		default:
			return nil, fmt.Errorf("route %q: invalid inject %q", rt.PathPrefix, rt.Inject)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out, nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/proxy/ -run 'TestRoutes|TestValidateRoutes|TestLoadRoutes' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/gateway_config.go pep/proxy/gateway_test.go
git commit -m "feat(pep): gateway route config (env shortcuts + YAML) + validation"
```

---

### Task 2: Gateway engine — match, gate, unauthenticated branch

**Files:**
- Create: `pep/proxy/gateway.go`
- Test: `pep/proxy/gateway_test.go` (append)

**Interfaces:**
- Consumes: `Route`, `InjectMode`, `validateRoutes` (Task 1); `*Server`, `s.currentSession(r) (*Session, bool)`, `sess.Authenticated()`, `sanitizeReturnTo` (existing in proxy.go), `s.backend` (`Backend`).
- Produces: `type Gateway struct{…}`; `newGateway(s *Server, routes []Route) (*Gateway, error)`; `(*Gateway) ServeHTTP`; `(*Gateway) handleUnauthenticated`; `wantsHTML(r) bool`.

- [ ] **Step 1: Write the failing test**

```go
// append to pep/proxy/gateway_test.go
import (
	"net/http"
	"net/http/httptest"
	// (keep existing imports)
)

// newGatewayTestServer builds a Server whose backend is a stub and whose currentSession returns the given
// session. (Reuse the package's existing test helpers where present.)
func TestGatewayUnauthenticatedBranch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	s := newGatewayTestServer(t, nil /* no session */)
	gw, err := newGateway(s, []Route{{PathPrefix: "/", Upstream: upstream.URL, Protected: true, Inject: InjectIdentity}})
	if err != nil {
		t.Fatal(err)
	}

	// Browser navigation → 302 to the login UI.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.Header.Set("Accept", "text/html")
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("html unauth: status %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/oauth2/sign_in?rd=%2Fdashboard" {
		t.Errorf("redirect = %q", loc)
	}

	// API request → 401 JSON.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/data", nil)
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("api unauth: status %d, want 401", rec.Code)
	}
}

func TestGatewayLongestPrefixMatch(t *testing.T) {
	s := newGatewayTestServer(t, nil)
	gw, _ := newGateway(s, []Route{
		{PathPrefix: "/", Upstream: "http://app"},
		{PathPrefix: "/api", Upstream: "http://rs"},
	})
	if rt := gw.match("/api/x"); rt == nil || rt.PathPrefix != "/api" {
		t.Errorf("match(/api/x) = %v, want /api", rt)
	}
	if rt := gw.match("/home"); rt == nil || rt.PathPrefix != "/" {
		t.Errorf("match(/home) = %v, want /", rt)
	}
}
```

Add a `newGatewayTestServer(t, sess)` helper to the test file that constructs a minimal `*Server` whose
`currentSession` returns `(sess, sess != nil)` and whose `backend` is a stub implementing `Backend`
(`FreshAccessToken` returns `("tok", nil)`). Model it on the existing `newTestServer`/`fakeBackend` in
`proxy_test.go`.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestGateway -v`
Expected: FAIL (undefined: newGateway, newGatewayTestServer).

- [ ] **Step 3: Implement the engine**

```go
// pep/proxy/gateway.go
package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Gateway gates and reverse-proxies the configured routes. It is mounted on the Server mux after /oauth2/*,
// so it only ever sees paths the auth endpoints didn't claim.
type Gateway struct {
	s      *Server
	routes []Route
}

// newGateway validates the routes and builds the gateway. dpop routes require a backend that can attach a
// DPoP-bound token (the PDP backend); see Task 5 for the capability check.
func newGateway(s *Server, routes []Route) (*Gateway, error) {
	validated, err := validateRoutes(routes)
	if err != nil {
		return nil, err
	}
	if err := requireDPoPCapability(s.backend, validated); err != nil { // Task 5
		return nil, err
	}
	return &Gateway{s: s, routes: validated}, nil
}

func (g *Gateway) match(path string) *Route {
	for i := range g.routes {
		if strings.HasPrefix(path, g.routes[i].PathPrefix) {
			return &g.routes[i]
		}
	}
	return nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt := g.match(r.URL.Path)
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	if !rt.Protected {
		g.proxy(rt).ServeHTTP(w, r)
		return
	}
	sess, ok := g.s.currentSession(r)
	if !ok || !sess.Authenticated() {
		g.handleUnauthenticated(w, r)
		return
	}
	if rt.Inject != InjectNone {
		var token string
		if rt.Inject == InjectDPoP {
			t, err := g.s.backend.FreshAccessToken(r.Context(), sess)
			if err != nil || t == "" {
				g.handleUnauthenticated(w, r)
				return
			}
			token = t
		}
		r = r.WithContext(withInjection(r.Context(), &injection{mode: rt.Inject, token: token, sess: sess}))
	}
	g.proxy(rt).ServeHTTP(w, r)
}

// handleUnauthenticated sends a browser navigation to the login UI (with a guarded return-to) and any other
// request a JSON 401 — the oauth2-proxy behavior, so APIs get a clean 401 and humans get the login page.
func (g *Gateway) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		loginURL := "/oauth2/sign_in"
		if rd := sanitizeReturnTo(r.URL.RequestURI()); rd != "" {
			loginURL += "?rd=" + url.QueryEscape(rd)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "error_description": "authentication required"})
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

type injectionCtxKey struct{}

type injection struct {
	mode  InjectMode
	token string
	sess  *Session
}

func withInjection(ctx context.Context, inj *injection) context.Context {
	return context.WithValue(ctx, injectionCtxKey{}, inj)
}

func injectionFrom(ctx context.Context) *injection {
	inj, _ := ctx.Value(injectionCtxKey{}).(*injection)
	return inj
}

// proxy builds the reverse proxy for a route. Implemented in Task 3 (identity) and extended in Task 4 (DPoP).
func (g *Gateway) proxy(rt *Route) http.Handler { // placeholder replaced in Task 3
	return &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(rt.upstream) }}
}
```

Verify `sanitizeReturnTo` exists in `proxy.go` and returns `""` for non-local paths (it does — it guards the
`rd` param on `/oauth2/start`). If its empty-on-invalid behavior differs, adjust the redirect accordingly.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/proxy/ -run TestGateway -v`
Expected: PASS (`TestGatewayUnauthenticatedBranch`, `TestGatewayLongestPrefixMatch`).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/gateway.go pep/proxy/gateway_test.go
git commit -m "feat(pep): gateway engine — match, gate, HTML/API unauthenticated branch"
```

---

### Task 3: Identity injection + prefix strip + header hygiene

**Files:**
- Modify: `pep/proxy/gateway.go` (replace the `proxy` placeholder)
- Test: `pep/proxy/gateway_test.go` (append)

**Interfaces:**
- Consumes: `setIdentityHeaders(h http.Header, identity map[string]any)` (headers.go), `injectionFrom`.
- Produces: real `(*Gateway) proxy(rt *Route) http.Handler` with a Rewrite that strips the prefix, sets
  X-Forwarded, clears client `Authorization`/`X-Auth-Request-*`, and injects identity.

- [ ] **Step 1: Write the failing test**

```go
// append to pep/proxy/gateway_test.go
func TestGatewayIdentityInjection(t *testing.T) {
	var gotPath, gotIdentity, gotForgedUser string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotIdentity = r.Header.Get("X-Auth-Request-Identity")
		gotForgedUser = r.Header.Get("X-Auth-Request-User")
	}))
	defer upstream.Close()

	sess := &Session{Identity: map[string]any{"sub": "u-1", "preferred_username": "alice"}}
	s := newGatewayTestServer(t, sess)
	gw, _ := newGateway(s, []Route{{PathPrefix: "/app", Upstream: upstream.URL, Protected: true, Inject: InjectIdentity, StripPrefix: true}})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/app/page", nil)
	req.Header.Set("X-Auth-Request-User", "attacker") // must be stripped
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
	json.Unmarshal(raw, &claims)
	if claims["sub"] != "u-1" {
		t.Errorf("identity claims = %v", claims)
	}
}
```

Add `"encoding/base64"` to the test imports.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestGatewayIdentityInjection -v`
Expected: FAIL (strip not applied / identity not set — the placeholder proxy does neither).

- [ ] **Step 3: Implement the real proxy**

```go
// pep/proxy/gateway.go — replace the placeholder proxy method, add imports "log/slog"
func (g *Gateway) proxy(rt *Route) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(rt.upstream)
			if rt.StripPrefix {
				trimmed := strings.TrimPrefix(pr.Out.URL.Path, strings.TrimSuffix(rt.PathPrefix, "/"))
				if trimmed == "" {
					trimmed = "/"
				}
				pr.Out.URL.Path = trimmed
				pr.Out.URL.RawPath = ""
			}
			pr.SetXForwarded()

			// Never let a client forge identity or authorization to the upstream.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(headerUser)
			pr.Out.Header.Del(headerEmail)
			pr.Out.Header.Del(headerGroups)
			pr.Out.Header.Del(headerIdentity)

			inj := injectionFrom(pr.In.Context())
			if inj == nil {
				return
			}
			switch inj.mode {
			case InjectIdentity:
				setIdentityHeaders(pr.Out.Header, inj.sess.Identity)
			case InjectDPoP:
				if err := g.injectDPoP(pr.Out, inj.sess, inj.token); err != nil { // Task 4
					slog.Error("gateway DPoP injection", "route", rt.PathPrefix, "error", err)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("gateway upstream unreachable", "upstream", rt.upstream.String(), "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad_gateway", "error_description": "upstream unavailable"})
		},
	}
}
```

For now stub `injectDPoP` on the Gateway so it compiles; Task 4 fills it:

```go
func (g *Gateway) injectDPoP(out *http.Request, sess *Session, token string) error { return nil }
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/proxy/ -run TestGateway -v`
Expected: PASS (identity injection, strip, hygiene all green).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/gateway.go pep/proxy/gateway_test.go
git commit -m "feat(pep): gateway identity injection, prefix strip, header hygiene"
```

---

### Task 4: DPoP injection via the backend seam

**Files:**
- Modify: `pep/proxy/backend.go` (add interface), `pep/proxy/backend_pdp.go` (add method), `pep/proxy/gateway.go` (real `injectDPoP`)
- Test: `pep/proxy/gateway_test.go` (append)

**Interfaces:**
- Produces: `type dpopForwarder interface { injectDPoP(out *http.Request, sess *Session, token string) error }`; `(*pdpBackend) injectDPoP(...)`; `(*Gateway) injectDPoP` delegating to the backend when it implements `dpopForwarder`.
- Consumes: `parseSessionDPoPKey`, `b.signer.dpopProof(out, token, key)`, `dpop.DPoPHeaderName` (from inject.go / signer.go).

- [ ] **Step 1: Write the failing test**

```go
// append to pep/proxy/gateway_test.go — requires the PDP backend stub to implement dpopForwarder.
func TestGatewayDPoPInjection(t *testing.T) {
	var gotAuth, gotProof string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProof = r.Header.Get("DPoP")
	}))
	defer upstream.Close()

	// A session with a real DPoP key + identity, and a backend that returns a token + injects DPoP.
	sess := newDPoPTestSession(t) // helper: generates an ES256 JWK into Session.DPoPKeyJWK, sets Identity
	s := newGatewayTestServerWithDPoP(t, sess) // backend implements dpopForwarder via the real pdpBackend signer
	gw, err := newGateway(s, []Route{{PathPrefix: "/api", Upstream: upstream.URL, Protected: true, Inject: InjectDPoP, StripPrefix: true}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, httptest.NewRequest("GET", "/api/orders", nil))

	if !strings.HasPrefix(gotAuth, "DPoP ") {
		t.Errorf("Authorization = %q, want DPoP <token>", gotAuth)
	}
	if gotProof == "" {
		t.Error("DPoP proof header not set")
	}
}
```

Add helpers `newDPoPTestSession` and `newGatewayTestServerWithDPoP` whose backend is a real `*pdpBackend`
(constructed via `NewPDPBackend` with a stub HTTP client, or a thin struct embedding `bffSigner{}` that
implements both `FreshAccessToken` and `injectDPoP`). Reuse `bffSigner{}.dpopProof` directly.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestGatewayDPoP -v`
Expected: FAIL (Gateway.injectDPoP is a no-op stub → no headers).

- [ ] **Step 3: Implement the seam + the PDP method + the gateway delegation**

```go
// pep/proxy/backend.go — add near apiBackend/routeProvider optional interfaces
// dpopForwarder is implemented by a backend that can attach a DPoP-bound access token to an upstream
// request (the PDP backend). dpop routes require it.
type dpopForwarder interface {
	injectDPoP(out *http.Request, sess *Session, token string) error
}
```

```go
// pep/proxy/backend_pdp.go — refactor the apiProxy minting into a reusable method (delete mountAPI/apiProxy)
import "github.com/gematik/zero-lab/go/dpop"

var _ dpopForwarder = (*pdpBackend)(nil)

// injectDPoP mints a fresh proof bound to the outbound request and attaches the DPoP-bound token, replacing
// any client Authorization. The proof is signed with the session's DPoP key (the token's cnf.jkt).
func (b *pdpBackend) injectDPoP(out *http.Request, sess *Session, token string) error {
	key, err := parseSessionDPoPKey(sess.DPoPKeyJWK)
	if err != nil {
		return err
	}
	proof, err := b.signer.dpopProof(out, token, key)
	if err != nil {
		return err
	}
	out.Header.Set("Authorization", "DPoP "+token)
	out.Header.Set(dpop.DPoPHeaderName, proof)
	return nil
}
```

```go
// pep/proxy/gateway.go — replace the injectDPoP stub
func (g *Gateway) injectDPoP(out *http.Request, sess *Session, token string) error {
	fwd, ok := g.s.backend.(dpopForwarder)
	if !ok {
		return fmt.Errorf("backend does not support DPoP injection")
	}
	return fwd.injectDPoP(out, sess, token)
}
```

Add `"fmt"` to `gateway.go` imports. Delete `pep/proxy/inject.go` (its `mountAPI`/`apiProxy` are now gone;
`injectDPoP` carries the minting). Keep `PDPConfig.APIPrefix`/`APIUpstream` for now — removed in Task 6.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/proxy/ -run TestGateway -v && go build ./pep/...`
Expected: PASS; build clean (no more references to the deleted apiProxy).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/backend.go pep/proxy/backend_pdp.go pep/proxy/gateway.go pep/proxy/inject.go pep/proxy/gateway_test.go
git commit -m "feat(pep): gateway DPoP injection via backend seam; subsume the /api proxy"
```

---

### Task 5: Load-time capability validation (dpop requires PDP backend)

**Files:**
- Modify: `pep/proxy/gateway.go` (implement `requireDPoPCapability`, referenced in Task 2)
- Test: `pep/proxy/gateway_test.go` (append)

**Interfaces:**
- Produces: `requireDPoPCapability(backend Backend, routes []Route) error`.

- [ ] **Step 1: Write the failing test**

```go
// append to pep/proxy/gateway_test.go
func TestGatewayDPoPRouteRequiresCapableBackend(t *testing.T) {
	// providerBackend stub: no dpopForwarder.
	s := newGatewayTestServer(t, nil) // its backend is the plain stub (not a dpopForwarder)
	_, err := newGateway(s, []Route{{PathPrefix: "/api", Upstream: "http://rs:8080", Protected: true, Inject: InjectDPoP}})
	if err == nil {
		t.Fatal("dpop route accepted with a non-DPoP backend")
	}
}
```

Ensure the plain `newGatewayTestServer` backend stub does NOT implement `dpopForwarder` (only
`newGatewayTestServerWithDPoP` does).

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestGatewayDPoPRouteRequires -v`
Expected: FAIL (`requireDPoPCapability` is a stub that returns nil).

- [ ] **Step 3: Implement**

```go
// pep/proxy/gateway.go
func requireDPoPCapability(backend Backend, routes []Route) error {
	for _, rt := range routes {
		if rt.Inject == InjectDPoP {
			if _, ok := backend.(dpopForwarder); !ok {
				return fmt.Errorf("route %q uses inject: dpop, but the backend cannot forward DPoP tokens (needs the PDP backend)", rt.PathPrefix)
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/proxy/ -run TestGateway -v`
Expected: PASS (all gateway tests).

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/gateway.go pep/proxy/gateway_test.go
git commit -m "feat(pep): reject dpop routes without a DPoP-capable backend at load"
```

---

### Task 6: Wire the gateway into the Server; drop the old apiBackend path

**Files:**
- Modify: `pep/proxy/proxy.go` (add `Config.Routes`; build+mount Gateway in `Handler()`; remove `apiBackend` interface + the `mountAPI` block), `pep/proxy/backend_pdp.go` (drop `PDPConfig.APIPrefix`/`APIUpstream`)
- Test: `pep/proxy/gateway_test.go` (append) + ensure existing `proxy_test.go` still passes.

**Interfaces:**
- Consumes: `newGateway`. Produces: `Config.Routes []Route`; `Handler()` mounts the Gateway at `/` when routes are set.

- [ ] **Step 1: Write the failing test**

```go
// append to pep/proxy/gateway_test.go — /oauth2/* must win over a "/" gateway route.
func TestServerMountsOAuthBeforeGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(299) // sentinel: upstream was hit
	}))
	defer upstream.Close()

	s := newTestServer(t) // existing helper; provider backend, no session
	s.cfg.Routes = []Route{{PathPrefix: "/", Upstream: upstream.URL, Protected: false}}
	h := s.Handler()

	// /oauth2/sign_in is served by pep, not proxied.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/sign_in", nil))
	if rec.Code == 299 {
		t.Fatal("/oauth2/* was proxied to the upstream — must be served by pep")
	}
	// A non-oauth path is proxied (unprotected route → 299).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/anything", nil))
	if rec.Code != 299 {
		t.Fatalf("gateway route not reached: status %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pep/proxy/ -run TestServerMountsOAuthBeforeGateway -v`
Expected: FAIL (Config has no Routes field; gateway not mounted).

- [ ] **Step 3: Implement**

```go
// pep/proxy/proxy.go — add to Config struct
// Routes, when non-empty, turn on standalone gateway mode: pep gates + reverse-proxies these upstreams.
// Empty → forward_auth-only (behind Caddy), unchanged.
Routes []Route
```

```go
// pep/proxy/proxy.go — in Handler(), REPLACE the apiBackend block:
//   if ab, ok := s.backend.(apiBackend); ok { ab.mountAPI(s, mux) }
// with the gateway mount (kept LAST so /oauth2/* and proxyRoutes win):
if len(s.cfg.Routes) > 0 {
	gw, err := newGateway(s, s.cfg.Routes)
	if err != nil {
		// Handler() has no error return; fail loudly at construction. If Handler can't return an error,
		// build the gateway in the Server constructor (NewServer) and store it, surfacing the error there.
		panic(fmt.Sprintf("gateway config: %v", err))
	}
	mux.Handle("/", gw)
}
```

Prefer surfacing the error: build the gateway in `NewServer` (where errors propagate) and store `s.gateway`;
`Handler()` then just does `if s.gateway != nil { mux.Handle("/", s.gateway) }`. Check `NewServer`'s
signature in `proxy.go` and follow whichever pattern it already uses for fallible setup. Remove the now-unused
`apiBackend` interface and the `mountAPI` block. Delete `PDPConfig.APIPrefix` and `PDPConfig.APIUpstream` and
the `cfg.APIPrefix` default in `NewPDPBackend`.

- [ ] **Step 4: Run to verify pass**

Run: `go test ./pep/... -v 2>&1 | grep -E 'FAIL|ok' && go vet ./pep/...`
Expected: PASS for all pep tests; vet clean.

- [ ] **Step 5: Guard + commit**

Run: `go list -deps ./zaddy/cmd/zero-caddy | grep -c 'gematik/zero-lab/go/\(oidf\|gemidp\|pep/proxy\)'`
Expected: `0`.

```bash
git add pep/proxy/proxy.go pep/proxy/backend_pdp.go pep/proxy/gateway_test.go
git commit -m "feat(pep): mount the gateway in standalone mode; remove the single-/api path"
```

---

### Task 7: Command wiring + docs

**Files:**
- Modify: `pep/cmd/zero-pep-proxy/main.go`, `pep/cmd/zero-pep-proxy/CONFIG.md`, `pep/proxy/e2e/README.md`

**Interfaces:**
- Consumes: `proxy.Config.Routes`, `proxy.loadRoutes` (export as needed) / `proxy.routesFromEnv`.

- [ ] **Step 1: Decide the export surface**

`main.go` is in a different package, so it needs exported builders. Add to `gateway_config.go`:

```go
// RoutesFromConfig returns the gateway routes from PEP_ROUTES_PATH (a YAML file, authoritative) or the
// PEP_API_UPSTREAM / PEP_WEBAPP_UPSTREAM env shortcuts. Empty when none are set (forward_auth-only).
func RoutesFromConfig() ([]Route, error) {
	if p := os.Getenv("PEP_ROUTES_PATH"); p != "" {
		return loadRoutes(p)
	}
	return routesFromEnv(), nil
}
```

- [ ] **Step 2: Wire it in main.go**

Find where `proxy.Config` is assembled in `main.go` and set `cfg.Routes`:

```go
routes, err := proxy.RoutesFromConfig()
if err != nil {
	log.Fatalf("gateway routes: %v", err)
}
cfg.Routes = routes
```

Remove any prior wiring that set `PEP_API_UPSTREAM` into the PDP backend config (it now feeds the gateway).

- [ ] **Step 3: Build + run the existing PDP HITL harness smoke**

Run: `go build ./pep/... && go vet ./pep/...`
Expected: clean. (Functional proof is Task 8.)

- [ ] **Step 4: Docs**

Update `pep/cmd/zero-pep-proxy/CONFIG.md` and `pep/proxy/e2e/README.md`: document `PEP_ROUTES_PATH`,
`PEP_WEBAPP_UPSTREAM` (and that `PEP_API_UPSTREAM` now feeds a gateway route), with a `routes.yaml` example
and the standalone (no-Caddy) shape that replaces `zero-bff-pdp`.

- [ ] **Step 5: Commit**

```bash
git add pep/proxy/gateway_config.go pep/cmd/zero-pep-proxy/main.go pep/cmd/zero-pep-proxy/CONFIG.md pep/proxy/e2e/README.md
git commit -m "feat(pep): wire gateway routes from env/PEP_ROUTES_PATH; document the standalone gateway"
```

---

### Task 8: HITL — standalone gateway end to end (the bff-pdp replacement shape)

**Files:** none (verification). Per the stage-HITL rule, the human drives this before the stage is done.

- [ ] **Step 1: Bring up the PDP backend harness** (PDP `:8011` + zaddy `:8010`, built with mockidp) per
  `pep/proxy/e2e/README.md` § PDP backend.

- [ ] **Step 2: Run pep standalone with TWO routes** (no Caddy in front): a `/` identity webapp
  (`PEP_WEBAPP_UPSTREAM` → metsubushi) and an `/api` DPoP route (`PEP_API_UPSTREAM` → zaddy `:8010`), on the
  PDP backend. Example:

```sh
PEP_BACKEND=pdp PEP_AS_ISSUER=http://localhost:8011 PEP_CLIENT_ID=pep-client \
PEP_CLIENT_SIGNING_KEY_PATH=pdp-config/pep-client.jwk \
PEP_PUBLIC_URL=http://localhost:8080 PEP_ADDR=:8080 PEP_INSECURE_COOKIE=true PEP_SCOPES=protected \
PEP_WEBAPP_UPSTREAM=http://localhost:8082 PEP_API_UPSTREAM=http://localhost:8010 \
  go run ../../cmd/zero-pep-proxy
```

- [ ] **Step 3: Verify in a browser:**
  - Unauthenticated `GET /` (browser) → 302 to `/oauth2/sign_in` → mock-IdP login → back to `/`, the webapp
    renders with the injected `X-Auth-Request-*` identity.
  - `GET /api/protected-dpop` → 200, zaddy-verified DPoP-bound token.
  - Unauthenticated `curl /api/...` (no `Accept: text/html`) → 401 JSON.

- [ ] **Step 4:** Report results; only then mark S5 done and proceed to the cut-over backlog item.

---

## Self-Review

- **Spec coverage:** Route/config (T1), engine + unauth branch (T2), identity inject + hygiene + strip (T3),
  DPoP inject + backend seam + subsume /api (T4), capability validation (T5), mux precedence + standalone
  mount + remove old path (T6), config/env/docs (T7), HITL (T8). All spec sections map to a task.
- **Type consistency:** `Route`/`InjectMode`/`injection`/`dpopForwarder`/`Gateway`/`newGateway`/
  `requireDPoPCapability`/`injectDPoP` names are used identically across T1–T6.
- **Watch-outs flagged inline:** `sanitizeReturnTo` empty-on-invalid semantics (T2); `Handler()` has no error
  return → build the gateway in `NewServer` and surface the error there (T6); test helpers
  (`newGatewayTestServer`, `newGatewayTestServerWithDPoP`, `newDPoPTestSession`) modeled on the existing
  `proxy_test.go` fakes (T2/T4).
