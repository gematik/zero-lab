// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/httpguard"
	"github.com/gematik/zero-lab/go/pep"
)

// gatewayDeps are what the gateway needs from the Server: session resolution, the backend (token + DPoP
// injection), and the snapshot cookie name + keys for the stateless gate.
type gatewayDeps struct {
	currentSession func(*http.Request) (*Session, bool)
	backend        Backend
	cookieName     string
	snapshotKeys   [][]byte
	// ownCookies are the names of the cookies this server sets; none of them is forwarded to an upstream.
	ownCookies []string
	// revocations end a snapshot before its expiry; a snapshot route needs them.
	revocations Revocations
	// now is the time requests are judged at; nil means the system clock.
	now func() time.Time
	// transport reaches the upstreams; nil is only allowed when none is https.
	transport http.RoundTripper
	// log receives the gateway's events and is the enforcers' logger; nil logs nothing.
	log *slog.Logger
}

// Gateway gates and reverse-proxies the configured routes. Gating runs as a pep.Enforcer chain (the gate,
// optionally AllOf with EnforcerScope) over a gatewayContext; the inject is the terminal next. Mounted on the
// Server mux after /oauth2/*, active only when routes are configured.
type Gateway struct {
	deps   gatewayDeps
	routes []Route
}

func newGateway(routes []Route, deps gatewayDeps) (*Gateway, error) {
	if deps.now == nil {
		deps.now = time.Now
	}
	validated, err := validateRoutes(routes)
	if err != nil {
		return nil, err
	}
	if err := requireDPoPCapability(deps.backend, validated); err != nil {
		return nil, err
	}
	for _, rt := range validated {
		if rt.upstream.Scheme == "https" && deps.transport == nil {
			return nil, fmt.Errorf("route %q: https upstream without an upstream transport: its TLS would be verified by no profile", rt.PathPrefix)
		}
		if rt.Gate == GateSnapshot && len(deps.snapshotKeys) == 0 {
			return nil, fmt.Errorf("route %q uses gate: snapshot, but the snapshot fast path is not configured (set the session key)", rt.PathPrefix)
		}
		if rt.Gate == GateSnapshot && deps.revocations == nil {
			return nil, fmt.Errorf("route %q uses gate: snapshot without revocations: a signed-out session would pass until its snapshot expires", rt.PathPrefix)
		}
	}
	g := &Gateway{deps: deps, routes: validated}
	for i := range g.routes {
		g.routes[i].proxy = g.newProxy(&g.routes[i])
	}
	return g, nil
}

// match finds the route of an escaped path that httpguard.CheckPath accepted: the longest prefix that holds it
// on a segment boundary, compared as received.
func (g *Gateway) match(escaped string) *Route {
	for i := range g.routes {
		if httpguard.HasPrefix(escaped, g.routes[i].PathPrefix) {
			return &g.routes[i]
		}
	}
	return nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Server rule 28, "Method and path": a path is matched as received. An encoded separator or dot segment
	// that an upstream would resolve could otherwise reach a gated route through an open one.
	if err := httpguard.Path(r); err != nil {
		respondGatewayJSON(w, http.StatusBadRequest, "invalid_request", "the path is not canonical")
		return
	}
	rt := g.match(r.URL.EscapedPath())
	if rt == nil {
		http.NotFound(w, r)
		return
	}
	if rt.Gate == GateNone {
		rt.proxy.ServeHTTP(w, r)
		return
	}
	gctx := newGatewayContext(w, r, g.deps.now, g.deps.log)
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

// policyFor builds the route's enforcer: the gate (snapshot or stored session), optionally wrapped in
// AllOf with an EnforcerScope.
func (g *Gateway) policyFor(rt *Route) pep.Enforcer {
	var gate pep.Enforcer
	switch rt.Gate {
	case GateSnapshot:
		gate = &snapshotGate{cookieName: g.deps.cookieName, keys: g.deps.snapshotKeys, revocations: g.deps.revocations}
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
			g.deps.log.Warn("gateway upstream token unavailable", "route", rt.PathPrefix, "error", err)
			g.handleUnauthenticated(gctx.w, gctx.r)
			return
		}
		inj.token = token
	}
	r2 := gctx.r.WithContext(withInjection(gctx.r.Context(), inj))
	rt.proxy.ServeHTTP(gctx.w, r2)
}

func (g *Gateway) handleDenied(w http.ResponseWriter, r *http.Request, err pep.Error) {
	if err.HTTPStatus == http.StatusUnauthorized {
		g.handleUnauthenticated(w, r)
		return
	}
	respondGatewayJSON(w, err.HTTPStatus, err.Code, err.Description)
}

func (g *Gateway) newProxy(rt *Route) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: g.deps.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			if rt.StripPrefix {
				// The prefix comes off the path as received, before SetURL joins it to the upstream's path, so
				// what is forwarded is the upstream's path and the rest of a canonical path, nothing decoded
				// again.
				rest := strings.TrimPrefix(pr.In.URL.EscapedPath(), strings.TrimSuffix(rt.PathPrefix, "/"))
				if rest == "" {
					rest = "/"
				}
				path, err := url.PathUnescape(rest)
				if err != nil {
					path = rest
				}
				pr.Out.URL.Path, pr.Out.URL.RawPath = path, rest
			}
			pr.SetURL(rt.upstream)
			pr.SetXForwarded()

			// Never let a client forge identity or authorization to the upstream.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(headerUser)
			pr.Out.Header.Del(headerEmail)
			pr.Out.Header.Del(headerGroups)
			pr.Out.Header.Del(headerIdentity)
			// The session cookie and the snapshot are the credential of a session that holds DPoP-bound tokens
			// and their key. An upstream gets the identity or a token for itself, never what would let it act
			// as the browser towards this server (RFC 9700 Section 4.9, Section 4.13).
			withoutCookies(pr.Out.Header, g.deps.ownCookies)

			inj := injectionFrom(pr.In.Context())
			if inj == nil {
				return
			}
			switch inj.mode {
			case InjectIdentity:
				setIdentityHeaders(pr.Out.Header, inj.identity)
			case InjectDPoP:
				if err := g.injectDPoP(pr.Out, inj.sess, inj.token); err != nil {
					g.deps.log.Error("gateway DPoP injection", "route", rt.PathPrefix, "error", err)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			g.deps.log.Error("gateway upstream unreachable", "upstream", rt.upstream.String(), "error", err)
			respondGatewayJSON(w, http.StatusBadGateway, "bad_gateway", "upstream unavailable")
		},
	}
}

func (g *Gateway) handleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		loginURL := "/oauth2/sign_in"
		// A request URI that is no return-to the login takes (a backslash in it, one of /oauth2) is left
		// out, and the login returns to "/".
		if rd := r.URL.RequestURI(); checkReturnTo(rd) == nil {
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
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
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
		return errors.New("backend does not support DPoP injection")
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

// withoutCookies removes the cookies with one of names from the Cookie fields of h and leaves every other
// cookie-pair as it was received, in order (RFC 6265 Section 4.2.1). A field left without a pair is removed.
func withoutCookies(h http.Header, names []string) {
	fields := h.Values("Cookie")
	if len(fields) == 0 || len(names) == 0 {
		return
	}
	kept := fields[:0:0]
	for _, field := range fields {
		var pairs []string
		for pair := range strings.SplitSeq(field, ";") {
			pair = strings.TrimSpace(pair)
			name, _, _ := strings.Cut(pair, "=")
			if pair == "" || slices.Contains(names, strings.TrimSpace(name)) {
				continue
			}
			pairs = append(pairs, pair)
		}
		if len(pairs) > 0 {
			kept = append(kept, strings.Join(pairs, "; "))
		}
	}
	h.Del("Cookie")
	for _, field := range kept {
		h.Add("Cookie", field)
	}
}
