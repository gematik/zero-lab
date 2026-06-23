// Package gateway turns the BFF into an oauth2-proxy-style auth gateway: it gates and reverse-proxies a
// set of upstreams (a business webapp, an API resource server) that run as separate processes behind the
// BFF. Unauthenticated browser navigations are sent to the BFF login UI; authenticated requests are
// proxied to the upstream with the user identity (a base64url-JSON header) or the access token
// (DPoP-bound) attached. Tokens never reach the browser.
package gateway

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/dpop"
)

// InjectMode selects what a protected route forwards upstream to identify/authorize the user.
type InjectMode string

const (
	// InjectNone gates the route but forwards nothing extra.
	InjectNone InjectMode = ""
	// InjectIdentity forwards the user's identity claims as a single base64url-JSON header.
	InjectIdentity InjectMode = "identity"
	// InjectDPoP attaches the access token as `Authorization: DPoP` plus a freshly minted DPoP proof.
	InjectDPoP InjectMode = "dpop"
)

// Route maps a path prefix to an upstream. Protected routes require an authenticated session; Inject (only
// meaningful when Protected) selects what is forwarded to identify the user.
type Route struct {
	PathPrefix  string
	UpstreamURL string
	Protected   bool
	Inject      InjectMode
	// StripPrefix removes PathPrefix from the request path before proxying (so /api/x → upstream /x).
	StripPrefix bool

	upstream *url.URL
	proxy    *httputil.ReverseProxy
}

// Config configures the gateway. Routes are matched longest-prefix-first.
type Config struct {
	Routes []Route
	// LoginUIPrefix is the BFF login UI path unauthenticated navigations are redirected to (default /bff/).
	LoginUIPrefix string
	// ReturnParam carries the originally requested path on the login redirect (default "rd").
	ReturnParam string
	// IdentityHeader carries base64url(JSON(identity)) for InjectIdentity (default X-Auth-Request-Identity).
	IdentityHeader string
}

// Gateway is an http.Handler that gates and reverse-proxies the configured upstreams.
type Gateway struct {
	bff    *bff.BackendForFrontend
	cfg    Config
	routes []*Route
	dpopPK *dpop.PrivateKey
}

// New builds the gateway: it parses each upstream, builds a reverse proxy per route, and — when any route
// injects DPoP — wraps the BFF's DPoP key for minting proofs.
func New(b *bff.BackendForFrontend, cfg Config) (*Gateway, error) {
	if cfg.LoginUIPrefix == "" {
		cfg.LoginUIPrefix = "/bff/"
	}
	if cfg.ReturnParam == "" {
		cfg.ReturnParam = "rd"
	}
	if cfg.IdentityHeader == "" {
		cfg.IdentityHeader = "X-Auth-Request-Identity"
	}

	g := &Gateway{bff: b, cfg: cfg}
	for i := range cfg.Routes {
		rt := new(Route)
		*rt = cfg.Routes[i]
		u, err := url.Parse(rt.UpstreamURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("route %q: invalid upstream %q", rt.PathPrefix, rt.UpstreamURL)
		}
		rt.upstream = u
		if rt.Protected && rt.Inject == InjectDPoP && g.dpopPK == nil {
			key := b.DPoPKey()
			if key == nil {
				return nil, fmt.Errorf("route %q wants DPoP injection but the BFF has no DPoP key", rt.PathPrefix)
			}
			pk, err := dpop.FromJWK(key)
			if err != nil {
				return nil, fmt.Errorf("wrap DPoP key: %w", err)
			}
			g.dpopPK = pk
		}
		rt.proxy = g.newProxy(rt)
		g.routes = append(g.routes, rt)
	}
	// Longest prefix first so "/api/" wins over "/".
	sort.SliceStable(g.routes, func(i, j int) bool {
		return len(g.routes[i].PathPrefix) > len(g.routes[j].PathPrefix)
	})
	return g, nil
}

// Handler returns the gateway as an http.Handler.
func (g *Gateway) Handler() http.Handler { return g }

func (g *Gateway) match(path string) *Route {
	for _, rt := range g.routes {
		if strings.HasPrefix(path, rt.PathPrefix) {
			return rt
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

	session, err := g.bff.RetrieveSession(r)
	if err != nil {
		g.handleUnauthenticated(w, r)
		return
	}

	if rt.Inject != InjectNone {
		token, err := g.bff.FreshAccessToken(r.Context(), session)
		if err != nil {
			slog.Warn("gateway token refresh failed", "error", err)
			_ = g.bff.DeleteSession(session)
			g.bff.ExpireCookie(w)
			g.handleUnauthenticated(w, r)
			return
		}
		r = r.WithContext(withInjection(r.Context(), &injection{mode: rt.Inject, token: token, session: session}))
	}
	rt.proxy.ServeHTTP(w, r)
}

// handleUnauthenticated sends an HTML navigation to the login UI (with a return-to) and any other request
// (XHR/fetch/API) a JSON 401 — the oauth2-proxy behavior.
func (g *Gateway) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		loginURL := g.cfg.LoginUIPrefix
		if rd := r.URL.RequestURI(); isLocalPath(rd) {
			loginURL += "?" + g.cfg.ReturnParam + "=" + url.QueryEscape(rd)
		}
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	respondJSON(w, http.StatusUnauthorized, map[string]string{
		"error":             "unauthorized",
		"error_description": "authentication required",
	})
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isLocalPath guards the return-to against open redirects: a local absolute path only ("/…", never "//host"
// or a backslash-smuggled host).
func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
