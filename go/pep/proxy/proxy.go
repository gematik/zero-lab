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

// Package proxy is an oauth2-proxy-style authentication gateway: it runs the login (against direct OIDC/
// OIDF/idpd providers or — later — a PDP), keeps the tokens server-side, and exposes the oauth2-proxy
// endpoint contract (/oauth2/{auth,start,sign_in,callback,sign_out,…}) so it works behind Caddy in
// forward_auth mode and as a standalone gateway. It is a token-mediating backend for frontend
// (draft-ietf-oauth-browser-based-apps); backlog doc-4 holds the history.
package proxy

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Config configures the proxy server.
type Config struct {
	Backend        Backend       // the auth backend (providerBackend today; pdpBackend later)
	SessionTTL     time.Duration // sliding session TTL (0 = 1h); ignored when the snapshot fast path is on
	CookieName     string        // session cookie name (default ZERO-PEP-SID)
	InsecureCookie bool          // drop the __Host- prefix + Secure for http dev; default is secure
	TemplateDir    string        // override the embedded UI templates (os.DirFS); "" = embedded

	// Snapshot fast path (docs/stateless-session-validation.md). When SnapshotKeyPath is set, /oauth2/auth
	// validates an encrypted snapshot cookie locally (no kv) for the whole session. Keys are read from files.
	SnapshotKeyPath         string        // base64 256-bit key file; "" disables the fast path
	SnapshotPreviousKeyPath string        // optional previous key file (rotation overlap)
	SnapshotTTL             time.Duration // = session absolute lifetime (0 = 8h)

	// Sessions and Revocations are the state replicas share. The host picks the backend and builds them; New
	// refuses to start without either rather than keep one in its own memory, which another replica would not
	// see. A sign-out or a rotation at one replica revokes the session ID at every other through Revocations.
	Sessions    SessionStore
	Revocations Revocations

	// Routes, when non-empty, turn on standalone gateway mode: pep gates + reverse-proxies these upstreams
	// itself (no Caddy). Empty = forward_auth-only, unchanged. gate: snapshot routes require the snapshot fast
	// path (SnapshotKeyPath).
	Routes []Route

	// UpstreamTransport carries the gateway's requests to its upstreams. An https upstream needs it, verifying
	// under the profile of spec/pki-validation the host chose for it (titls' web profile for one on the
	// internet), and New refuses an https route without one. A plain http upstream, a service beside pep in the
	// same pod or network, has no TLS to verify and goes through Go's default transport when this is nil.
	UpstreamTransport http.RoundTripper

	// Clock is the time sessions, snapshots, revocations and tokens are judged at; nil means the system
	// clock.
	Clock func() time.Time

	// Logger receives the proxy's operational events; nil logs nothing.
	Logger *slog.Logger
}

// clockSetter is a Backend that keeps the server's clock for the token expiries it records.
type clockSetter interface {
	setClock(now func() time.Time)
}

// DefaultSnapshotTTL is the snapshot lifetime, and — when the fast path is on — the session lifetime: the
// snapshot covers the whole session (forward_auth can't refresh the cookie), with instant revocation via the
// Revocations as the only early termination.
const DefaultSnapshotTTL = 8 * time.Hour

// Server serves the /oauth2/* endpoints over a Backend + session store.
type Server struct {
	sessions    *sessionManager
	cookie      *http.Cookie
	render      *renderer
	backend     Backend
	snap        *snapshotter // nil when the fast path is disabled (no key file)
	snapCookie  *http.Cookie // snapshot cookie template (only when snap != nil)
	snapTTL     time.Duration
	revocations Revocations
	gateway     *Gateway // nil in forward_auth-only mode (no Routes)
	now         func() time.Time
	log         *slog.Logger
}

// New returns a Server for cfg. It fails without a Backend, Sessions or Revocations and on a key file that
// cannot be loaded.
func New(cfg Config) (*Server, error) {
	if cfg.Backend == nil {
		return nil, errors.New("proxy: backend is required")
	}
	if cfg.Sessions == nil || cfg.Revocations == nil {
		return nil, errors.New("proxy: Sessions and Revocations are required: the host supplies the state replicas share")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "ZERO-PEP-SID"
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r, err := newRenderer(cfg.TemplateDir, log)
	if err != nil {
		return nil, err
	}

	snapTTL := cfg.SnapshotTTL
	if snapTTL <= 0 {
		snapTTL = DefaultSnapshotTTL
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	if b, ok := cfg.Backend.(clockSetter); ok {
		b.setClock(now)
	}
	snap, err := newSnapshotter(cfg.SnapshotKeyPath, cfg.SnapshotPreviousKeyPath, snapTTL)
	if err != nil {
		return nil, err
	}
	if snap != nil {
		snap.now = now
	}

	sessions := newSessionManager(cfg.Sessions, cfg.SessionTTL, log)
	sessions.now = now
	s := &Server{
		sessions:    sessions,
		cookie:      newCookieTemplate(cfg.CookieName, cfg.InsecureCookie),
		render:      r,
		backend:     cfg.Backend,
		snap:        snap,
		snapTTL:     snapTTL,
		revocations: cfg.Revocations,
		now:         now,
		log:         log,
	}
	if snap != nil {
		// The snapshot covers the whole session, so the stored session must live as long (it holds the refresh
		// token) and there is no sliding idle: pin both the idle and absolute TTLs to the snapshot lifetime.
		sessions.ttl = snapTTL
		sessions.maxLifetime = snapTTL
		s.snapCookie = newCookieTemplate(cfg.CookieName+"-SNAP", cfg.InsecureCookie)
		s.log.Info("snapshot fast path enabled", "ttl", snapTTL)
	}

	if len(cfg.Routes) > 0 {
		// Both names, whether or not the snapshot is in use: a browser can still hold one from before.
		ownCookies := []string{s.cookie.Name, newCookieTemplate(cfg.CookieName+"-SNAP", cfg.InsecureCookie).Name}
		deps := gatewayDeps{currentSession: s.currentSession, backend: s.backend, now: now, transport: cfg.UpstreamTransport, revocations: s.revocations, log: log, ownCookies: ownCookies}
		if snap != nil {
			deps.cookieName = s.snapCookie.Name // the snapshot gate validates the -SNAP cookie
			deps.snapshotKeys = snap.decKeys
		}
		gw, err := newGateway(cfg.Routes, deps)
		if err != nil {
			return nil, fmt.Errorf("gateway: %w", err)
		}
		s.gateway = gw
		s.log.Info("standalone gateway enabled", "routes", len(cfg.Routes))
	}
	return s, nil
}

// Handler returns the /oauth2/* mux. Mount it at the root; in forward_auth mode Caddy reverse_proxies
// /oauth2/* here and forward_auths every other route to /oauth2/auth.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/auth", s.handleAuth)
	mux.HandleFunc("GET /oauth2/start", s.handleStart)
	mux.HandleFunc("GET /oauth2/sign_in", s.handleSignIn)
	mux.HandleFunc("GET /oauth2/callback", s.handleCallback)
	mux.HandleFunc("GET /oauth2/poll", s.handlePoll)
	mux.HandleFunc("GET /oauth2/userinfo", s.handleUserinfo)
	mux.HandleFunc("GET /oauth2/sign_out", s.handleSignOut)
	mux.HandleFunc("POST /oauth2/sign_out", s.handleSignOut)
	// Backend-provided top-level routes (e.g. the OIDF entity statement at /.well-known/openid-federation).
	if rp, ok := s.backend.(routeProvider); ok {
		for _, rt := range rp.proxyRoutes() {
			mux.Handle(rt.Pattern, rt.Handler)
		}
	}
	// Standalone gateway mode: gate + reverse-proxy the configured upstreams. "/" is least-specific, so
	// /oauth2/* and the backend routes above always win.
	if s.gateway != nil {
		mux.Handle("/", s.gateway)
	}
	return mux
}

type signInData struct {
	Providers []Provider
	ReturnTo  string
}

type errorData struct {
	Code        string
	Description string
	IDPIss      string // when set, "Try again" retries this provider
	ReturnTo    string
}

type qrData struct {
	ProviderName string
	AuthURL      string
	QRImage      template.URL
	PollURL      string
	ReturnTo     string
}

// handleAuth is the forward_auth subrequest: 202 + identity headers when authenticated, bare 401 otherwise
// (Caddy's handle_response then redirects to /oauth2/start?rd=).
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	// Fast path: validate the encrypted snapshot locally — no store — for the whole session lifetime. Revoked
	// sessions are rejected immediately via Revocations.
	if s.snap != nil {
		if c, err := r.Cookie(s.snapCookie.Name); err == nil {
			if claims, ok := s.snap.open(c.Value); ok {
				revoked, err := s.revocations.Revoked(r.Context(), claims.SID)
				if err != nil {
					s.log.Error("revocation check failed, denying", "session_ref", logRef(claims.SID), "error", err)
				}
				if revoked || err != nil {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				setIdentityHeaders(w.Header(), claims.Identity)
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}
		// No valid snapshot → fall through to the store path; the /auth subrequest can't re-mint the cookie
		// (forward_auth), so the snapshot is (re)minted on the browser-direct callback/poll responses.
	}
	sess, ok := s.currentSession(r)
	if !ok || !sess.Authenticated() {
		_, cookieErr := r.Cookie(s.cookie.Name)
		s.log.Debug("forward_auth deny", "uri", withoutQuery(r.Header.Get("X-Forwarded-Uri")),
			"cookie_present", cookieErr == nil, "session_found", ok)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	setIdentityHeaders(w.Header(), sess.Identity)
	w.WriteHeader(http.StatusAccepted)
}

// setSnapshot mints the encrypted snapshot cookie for an authenticated session, on a browser-direct response
// (callback / poll). No-op when the fast path is disabled.
func (s *Server) setSnapshot(w http.ResponseWriter, sess *Session) {
	if s.snap == nil {
		return
	}
	tok, err := s.snap.mint(sess.ID, sess.Identity)
	if err != nil {
		s.log.Warn("mint snapshot failed", "session_ref", logRef(sess.ID), "error", err)
		return
	}
	setCookie(w, s.snapCookie, tok)
}

// sortProviders orders the chooser list: oidc + idpd keep their configured order at the top, and the OIDF
// federation IdPs (typically many) are sorted by label. The browser then pins the last-used provider above
// all (localStorage) and fuzzy-filters.
func sortProviders(providers []Provider) {
	sort.SliceStable(providers, func(i, j int) bool {
		oi, oj := providers[i].Type == "oidf", providers[j].Type == "oidf"
		if oi != oj {
			return !oi
		}
		if oi {
			return strings.ToLower(providers[i].Name) < strings.ToLower(providers[j].Name)
		}
		return false
	})
}

// withoutQuery keeps an authorization URL loggable: its query carries state, nonce and the
// PKCE challenge or a request_uri, which stay out of logs (servers rule 5).
func withoutQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// handleSignIn renders the provider chooser.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeReturnTo(r.URL.Query().Get("rd"))
	providers, err := s.backend.Providers(r.Context())
	if err != nil {
		s.renderFailure(w, "providers_error", "The identity providers are not available.", err, "", rd)
		return
	}
	sortProviders(providers)
	s.render.render(w, http.StatusOK, "sign_in.html", signInData{Providers: providers, ReturnTo: rd})
}

// handleStart begins a login: it creates a pending session, binds the cookie, and either redirects to the
// IdP (Mode "redirect") or renders the decoupled QR (Mode "decoupled", OIDF). With no idp_iss it
// auto-starts a single configured provider or shows the chooser.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rd := sanitizeReturnTo(q.Get("rd"))

	idpIss := q.Get("idp_iss")
	if idpIss == "" {
		if def := s.backend.DefaultIssuer(); def != "" {
			idpIss = def
		} else {
			dest := "/oauth2/sign_in"
			if rd != "" {
				dest += "?rd=" + url.QueryEscape(rd)
			}
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
	}

	sess := s.sessions.create()
	sess.ReturnTo = rd
	start, err := s.backend.StartLogin(r.Context(), sess, idpIss, q.Get("scope"))
	if err != nil {
		s.renderFailure(w, "login_failed", loginNotStarted, err, idpIss, rd)
		return
	}
	sess.LoginMode = start.Mode
	if err := s.sessions.save(r.Context(), sess); err != nil {
		s.renderFailure(w, "server_error", loginNotCompleted, err, idpIss, rd)
		return
	}
	setCookie(w, s.cookie, sess.token)

	s.log.Info("login start", "session_ref", logRef(sess.ID), "idp_iss", idpIss, "mode", start.Mode, "auth_endpoint", withoutQuery(start.AuthURL))

	var name string
	if start.Provider != nil {
		name = start.Provider.Name
	}
	switch start.Mode {
	case "decoupled": // OIDF — QR for a second device + on-device redirect, polled
		img, err := qrImage(start.AuthURL)
		if err != nil {
			s.renderFailure(w, "qr_error", loginNotStarted, err, idpIss, rd)
			return
		}
		s.render.render(w, http.StatusOK, "qr.html", qrData{
			ProviderName: name, AuthURL: start.AuthURL, QRImage: img,
			PollURL: "/oauth2/poll", ReturnTo: sess.ReturnTo,
		})
	case "authenticator": // idpd — open the authenticator:// app on this device + poll
		s.render.render(w, http.StatusOK, "authenticator.html", qrData{
			ProviderName: name, AuthURL: start.AuthURL,
			PollURL: "/oauth2/poll", ReturnTo: sess.ReturnTo,
		})
	default:
		http.Redirect(w, r, start.AuthURL, http.StatusFound)
	}
}

// handlePoll reports decoupled-login progress for the cookie-bound session: 200 once authenticated (with
// the return-to target), 202 while pending, 401 when there is no session. See DESIGN.md §3 — the cookie
// correlates the waiting browser, state correlates the out-of-band callback (cf. RFC 8628 / OIDC CIBA).
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	if sess.Authenticated() {
		dest := sess.ReturnTo
		if dest == "" {
			dest = "/"
		}
		// Decoupled flow: the callback completed on the other device, so the id wasn't rotated there. Rotate
		// now on this cookie-owning device (anti-fixation), revoke the old id, re-bind the cookie, and mint the
		// snapshot before handing back control.
		oldID := sess.ID
		if err := s.sessions.rotate(r.Context(), sess); err != nil {
			s.log.Warn("session rotation failed", "session_ref", logRef(sess.ID), "error", err)
		} else {
			s.revoke(r.Context(), oldID)
			setCookie(w, s.cookie, sess.token)
			s.setSnapshot(w, sess)
		}
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "return_to": dest})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"authenticated": false})
}

// handleUserinfo returns the current session's identity claims (never raw tokens).
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || !sess.Authenticated() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "identity": sess.Identity})
}

// writeJSON sends v with status, or a bare 500 when v cannot be encoded rather than status with an empty body. Map
// members are sorted, so the same value is always the same body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// handleCallback is the redirect_uri: it completes the login (by OAuth state) and returns to rd. A redirect
// login completes only in the browser holding the cookie from /oauth2/start; a cross-device one completes
// without it, and the cookie is not set there (DESIGN.md §3).
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Every answer is served at the URL that carries code and state: it is neither kept by a cache nor named
	// in the Referer of what the page loads or links to (RFC 9700 Section 4.2.4).
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()
	// Resolve the session by state first so error pages know which provider to retry.
	sess, serr := s.sessions.byState(r.Context(), q.Get("state"))
	var idpIss, rd string
	if serr == nil {
		idpIss, rd = sess.IDPIss, sess.ReturnTo
		// The state is used once, by the first callback that names it and whatever becomes of that callback
		// (RFC 9700 Section 4.2.4). The session is saved without it, or a later save would index it again.
		s.sessions.deleteState(r.Context(), sess.State)
		sess.State = ""
		if err := s.sessions.save(r.Context(), sess); err != nil {
			s.renderFailure(w, "server_error", loginNotCompleted, err, idpIss, rd)
			return
		}
	}
	if e := q.Get("error"); e != "" {
		s.log.Warn("identity provider refused the login", "idp_iss", idpIss, "error", oauthErrorCode(e))
		s.renderError(w, "login_failed", "The identity provider refused the login.", idpIss, rd)
		return
	}
	if serr != nil {
		s.renderError(w, "invalid_state", "unknown or expired login state", "", "")
		return
	}
	// RFC 9700 Section 2.1.1: a redirect login is bound to the browser that started it. Without that browser's
	// cookie the callback may be a victim's, lured to an authorization URL another browser started; redeeming
	// its code would sign the starter in as the victim. The session is removed with its state, so the code is
	// never redeemed for it.
	owns := s.requestOwnsSession(r, sess)
	if !owns && !crossDevice(sess.LoginMode) {
		s.sessions.remove(r.Context(), sess)
		s.log.Warn("login callback refused: not from the browser that started it", "idp_iss", idpIss)
		s.renderError(w, "invalid_state", "unknown or expired login state", idpIss, rd)
		return
	}
	if err := s.backend.Complete(r.Context(), sess, q.Get("code")); err != nil {
		s.renderFailure(w, "exchange_failed", loginNotCompleted, err, idpIss, rd, q.Get("code"), q.Get("state"))
		return
	}
	if err := s.sessions.save(r.Context(), sess); err != nil {
		s.renderFailure(w, "server_error", loginNotCompleted, err, idpIss, rd)
		return
	}
	dest := sess.ReturnTo
	if dest == "" {
		dest = "/"
	}

	// Decoupled (OIDF QR) flow: this callback landed on a second device that scanned the QR and never started
	// the login here, so it holds no session cookie — redirecting it to rd is meaningless, and it can't rotate
	// the cookie. Show a success page; the originating device (polling /oauth2/poll) proceeds to rd and rotates
	// the id there.
	if !owns {
		s.log.Info("login complete", "session_ref", logRef(sess.ID), "idp_iss", sess.IDPIss, "decoupled", true)
		s.render.render(w, http.StatusOK, "complete.html", nil)
		return
	}
	// On-device: now that the user is authenticated, rotate the session id (anti-fixation), revoke the old id
	// (kills any old snapshot), re-bind the cookie, and mint a fresh snapshot before returning to rd.
	oldID := sess.ID
	if err := s.sessions.rotate(r.Context(), sess); err != nil {
		s.renderFailure(w, "server_error", loginNotCompleted, err, idpIss, rd)
		return
	}
	s.revoke(r.Context(), oldID)
	setCookie(w, s.cookie, sess.token)
	s.setSnapshot(w, sess)
	s.log.Info("login complete", "session_ref", logRef(sess.ID), "idp_iss", sess.IDPIss, "return_to", dest)
	http.Redirect(w, r, dest, http.StatusFound)
}

// crossDevice says a login of mode may complete in a browser without the session's cookie: the decoupled
// (OIDF QR) login completes on a second device, and the authenticator login in the app the deep link opened. What
// guards them instead is in DESIGN.md (cross-device logins).
func crossDevice(mode string) bool {
	return mode == "decoupled" || mode == "authenticator"
}

// requestOwnsSession reports whether the request carries the session cookie set at /oauth2/start for this
// session — true on the device that began the login, false on a second device in the decoupled flow.
func (s *Server) requestOwnsSession(r *http.Request, sess *Session) bool {
	c, err := r.Cookie(s.cookie.Name)
	return err == nil && hashToken(c.Value) == sess.ID
}

// signOutTimeout bounds the store calls of a sign-out, which no longer end with the request.
const signOutTimeout = 5 * time.Second

// handleSignOut clears the session. POST (XHR) requires the X-Requested-With CSRF header and returns 204;
// GET (a link) renders signed_out.html.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Header.Get("X-Requested-With") == "" {
		http.Error(w, "missing X-Requested-With", http.StatusForbidden)
		return
	}
	// A browser that navigates away right after the request cancels it; a sign-out cut short would leave a
	// session that still authenticates. The bound keeps a stalled store from holding the handler instead.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), signOutTimeout)
	defer cancel()
	if sess, ok := s.currentSession(r.WithContext(ctx)); ok {
		_ = s.sessions.deleteByID(ctx, sess.ID)
		s.revoke(ctx, sess.ID) // instant: any valid snapshot for this sid is rejected on the fast path
	}
	expireCookie(w, s.cookie)
	if s.snapCookie != nil {
		expireCookie(w, s.snapCookie)
	}
	if r.Method == http.MethodGet {
		s.render.render(w, http.StatusOK, "signed_out.html", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) currentSession(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(s.cookie.Name)
	if err != nil {
		return nil, false
	}
	sess, err := s.sessions.byToken(r.Context(), c.Value)
	if err != nil {
		return nil, false
	}
	return sess, true
}

// revoke ends sid at every replica for as long as a snapshot naming it can be valid. It runs to the end when the
// browser goes away mid-request, as the session it ends is gone already.
func (s *Server) revoke(ctx context.Context, sid string) {
	if err := s.revocations.Revoke(context.WithoutCancel(ctx), sid, s.now().Add(s.snapTTL)); err != nil {
		s.log.Warn("revocation did not reach every replica", "session_ref", logRef(sid), "error", err)
	}
}

// renderError renders the error page. idpIss (when non-empty) makes "Try again" retry that provider;
// returnTo is carried through both actions.
func (s *Server) renderError(w http.ResponseWriter, code, description, idpIss, returnTo string) {
	s.render.render(w, http.StatusBadRequest, "error.html", errorData{
		Code: code, Description: description, IDPIss: idpIss, ReturnTo: returnTo,
	})
}

// What a browser reads of a failed login.
const (
	loginNotStarted   = "The login could not be started."
	loginNotCompleted = "The login could not be completed."
)

// renderFailure shows the browser description alone and logs err. secrets are values of this request, redacted should
// an error still echo one.
func (s *Server) renderFailure(w http.ResponseWriter, code, description string, err error, idpIss, returnTo string, secrets ...string) {
	detail := err.Error()
	for _, secret := range secrets {
		if secret != "" {
			detail = strings.ReplaceAll(detail, secret, "[redacted]")
		}
	}
	s.log.Error(description, "code", code, "idp_iss", idpIss, "error", detail)
	s.renderError(w, code, description, idpIss, returnTo)
}

// sanitizeReturnTo guards the rd= return-to against open redirects and login loops: a local absolute path
// that is not one of pep's own /oauth2/* endpoints. Returning into /oauth2/* bounces the browser back into
// the auth flow instead of the app, and it is how a forward_auth that fails to exclude /oauth2/* accretes an
// ever-growing rd=/oauth2/start?rd=/oauth2/start?… It must be valid UTF-8 as well, since the session record that
// keeps it is JSON and would not encode. Anything rejected collapses to "" (callers default to "/").
func sanitizeReturnTo(rd string) string {
	if !utf8.ValidString(rd) || !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return ""
	}
	u, err := url.Parse(rd)
	if err != nil {
		return ""
	}
	if p := path.Clean(u.Path); p == "/oauth2" || strings.HasPrefix(p, "/oauth2/") {
		return ""
	}
	return rd
}
