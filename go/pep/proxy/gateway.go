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
)

// Gateway gates and reverse-proxies the configured routes. It is mounted on the Server mux after /oauth2/*,
// so it only ever sees paths the auth endpoints didn't claim. It is backend-agnostic for routing, gating and
// identity injection; DPoP injection is delegated to a dpopForwarder backend.
type Gateway struct {
	currentSession func(*http.Request) (*Session, bool)
	backend        Backend
	routes         []Route
}

// newGateway validates the routes (rejecting dpop routes the backend can't honor) and builds one reverse
// proxy per route.
func newGateway(currentSession func(*http.Request) (*Session, bool), backend Backend, routes []Route) (*Gateway, error) {
	validated, err := validateRoutes(routes)
	if err != nil {
		return nil, err
	}
	if err := requireDPoPCapability(backend, validated); err != nil {
		return nil, err
	}
	g := &Gateway{currentSession: currentSession, backend: backend, routes: validated}
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
	if !rt.Protected {
		rt.proxy.ServeHTTP(w, r)
		return
	}
	sess, ok := g.currentSession(r)
	if !ok || !sess.Authenticated() {
		g.handleUnauthenticated(w, r)
		return
	}
	if rt.Inject != InjectNone {
		var token string
		if rt.Inject == InjectDPoP {
			t, err := g.backend.FreshAccessToken(r.Context(), sess)
			if err != nil || t == "" {
				slog.Warn("gateway token refresh failed", "route", rt.PathPrefix, "error", err)
				g.handleUnauthenticated(w, r)
				return
			}
			token = t
		}
		r = r.WithContext(withInjection(r.Context(), &injection{mode: rt.Inject, token: token, sess: sess}))
	}
	rt.proxy.ServeHTTP(w, r)
}

// newProxy builds the reverse proxy for one route. The Rewrite hook runs on the cloned outbound request: it
// retargets the upstream, strips the prefix, refreshes X-Forwarded-*, drops any client-supplied auth/identity
// headers, then injects our own identity header or DPoP-bound token from the request context.
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
				setIdentityHeaders(pr.Out.Header, inj.sess.Identity)
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

// handleUnauthenticated sends a browser navigation to the login UI (with a guarded return-to) and any other
// request a JSON 401 — so APIs get a clean 401 and humans get the login page.
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

// injectDPoP delegates to the backend when it can forward DPoP-bound tokens. dpop routes are rejected at
// construction (requireDPoPCapability) when the backend can't, so the assertion should always hold here.
func (g *Gateway) injectDPoP(out *http.Request, sess *Session, token string) error {
	fwd, ok := g.backend.(dpopForwarder)
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
