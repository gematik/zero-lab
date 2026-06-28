package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gematik/zero-lab/go/pep"
)

// gatewayDeps are what the gateway needs from the Server: session resolution, the backend (token + DPoP
// injection), and the snapshot cookie name + keys for the stateless gate.
type gatewayDeps struct {
	currentSession func(*http.Request) (*Session, bool)
	backend        Backend
	cookieName     string
	snapshotKeys   [][]byte
}

// Gateway gates and reverse-proxies the configured routes. Gating runs as a pep.Enforcer chain (the gate,
// optionally AllOf with EnforcerScope) over a gatewayContext; the inject is the terminal next. Mounted on the
// Server mux after /oauth2/*, active only when routes are configured.
type Gateway struct {
	deps   gatewayDeps
	routes []Route
}

func newGateway(routes []Route, deps gatewayDeps) (*Gateway, error) {
	validated, err := validateRoutes(routes)
	if err != nil {
		return nil, err
	}
	if err := requireDPoPCapability(deps.backend, validated); err != nil {
		return nil, err
	}
	for _, rt := range validated {
		if rt.Gate == GateSnapshot && len(deps.snapshotKeys) == 0 {
			return nil, fmt.Errorf("route %q uses gate: snapshot, but the snapshot fast path is not configured (set the session key)", rt.PathPrefix)
		}
	}
	g := &Gateway{deps: deps, routes: validated}
	for i := range g.routes {
		g.routes[i].proxy = g.newProxy(&g.routes[i])
	}
	return g, nil
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
	if rt.Gate == GateNone {
		rt.proxy.ServeHTTP(w, r)
		return
	}
	gctx := newGatewayContext(w, r)
	served := false
	g.policyFor(rt).Apply(gctx, func(pep.Context) {
		served = true
		g.injectAndProxy(rt, gctx)
	})
	if gctx.state.denied {
		g.handleDenied(w, r, gctx.state.denyErr)
		return
	}
	if !served {
		g.handleUnauthenticated(w, r)
	}
}

// policyFor builds the route's enforcer: the gate (stateless snapshot or stateful kv), optionally wrapped in
// AllOf with an EnforcerScope.
func (g *Gateway) policyFor(rt *Route) pep.Enforcer {
	var gate pep.Enforcer
	switch rt.Gate {
	case GateSnapshot:
		gate = pep.NewEnforcerSessionCookie(g.deps.cookieName, g.deps.snapshotKeys)
	default: // GateSession
		gate = &statefulGate{currentSession: g.deps.currentSession}
	}
	if rt.Scope == "" {
		return gate
	}
	allOf := &pep.EnforcerAllOf{TypeVal: pep.EnforcerTypeAllOf}
	allOf.Append(gate)
	allOf.Append(&pep.EnforcerScope{TypeVal: pep.EnforcerTypeScope, Scope: rt.Scope})
	return allOf
}

// injectAndProxy is the policy's terminal next: build the injection from the resolved identity/session and
// reverse-proxy the upstream.
func (g *Gateway) injectAndProxy(rt *Route, gctx *gatewayContext) {
	inj := &injection{mode: rt.Inject, sess: gctx.state.session}
	_ = gctx.UnmarshalClaims(&inj.identity)
	if rt.Inject == InjectDPoP {
		token, err := g.deps.backend.FreshAccessToken(gctx.r.Context(), gctx.state.session)
		if err != nil || token == "" {
			slog.Warn("gateway upstream token unavailable", "route", rt.PathPrefix, "error", err)
			g.handleUnauthenticated(gctx.w, gctx.r)
			return
		}
		inj.token = token
	}
	r2 := gctx.r.WithContext(withInjection(gctx.r.Context(), inj))
	rt.proxy.ServeHTTP(gctx.w, r2)
}

func (g *Gateway) handleDenied(w http.ResponseWriter, r *http.Request, err pep.Error) {
	if err.HttpStatus == http.StatusUnauthorized {
		g.handleUnauthenticated(w, r)
		return
	}
	respondGatewayJSON(w, err.HttpStatus, err.Code, err.Description)
}

func (g *Gateway) newProxy(rt *Route) *httputil.ReverseProxy {
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
				setIdentityHeaders(pr.Out.Header, inj.identity)
			case InjectDPoP:
				if err := g.injectDPoP(pr.Out, inj.sess, inj.token); err != nil {
					slog.Error("gateway DPoP injection", "route", rt.PathPrefix, "error", err)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("gateway upstream unreachable", "upstream", rt.upstream.String(), "error", err)
			respondGatewayJSON(w, http.StatusBadGateway, "bad_gateway", "upstream unavailable")
		},
	}
}

func (g *Gateway) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		loginURL := "/oauth2/sign_in"
		if rd := sanitizeReturnTo(r.URL.RequestURI()); rd != "" {
			loginURL += "?rd=" + url.QueryEscape(rd)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	respondGatewayJSON(w, http.StatusUnauthorized, "unauthorized", "authentication required")
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func respondGatewayJSON(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

type injectionCtxKey struct{}

type injection struct {
	mode     InjectMode
	identity map[string]any
	sess     *Session
	token    string
}

func withInjection(ctx context.Context, inj *injection) context.Context {
	return context.WithValue(ctx, injectionCtxKey{}, inj)
}

func injectionFrom(ctx context.Context) *injection {
	inj, _ := ctx.Value(injectionCtxKey{}).(*injection)
	return inj
}

// injectDPoP delegates to the backend when it can forward DPoP-bound tokens. dpop routes are rejected at
// construction (requireDPoPCapability) when the backend can't, so the assertion should always hold here.
func (g *Gateway) injectDPoP(out *http.Request, sess *Session, token string) error {
	fwd, ok := g.deps.backend.(dpopForwarder)
	if !ok {
		return fmt.Errorf("backend does not support DPoP injection")
	}
	return fwd.injectDPoP(out, sess, token)
}

// requireDPoPCapability rejects dpop routes when the backend cannot forward DPoP-bound tokens (only the PDP
// backend can), turning a runtime surprise into a startup error.
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
