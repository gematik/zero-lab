// Package proxy is an oauth2-proxy-style authentication gateway: it runs the login (against direct OIDC/
// OIDF/gemidp providers or — later — a PDP), keeps the tokens server-side, and exposes the oauth2-proxy
// endpoint contract (/oauth2/{auth,start,sign_in,callback,sign_out,…}) so it works behind Caddy in
// forward_auth mode and as a standalone gateway. It is the token-mediating BFF, generalized, and will
// replace the bff over time.
package proxy

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// Config configures the proxy server.
type Config struct {
	Backend        Backend       // the auth backend (providerBackend today; pdpBackend later)
	Store          kv.Store      // session store
	SessionTTL     time.Duration // sliding session TTL (0 = 1h); ignored when the snapshot fast path is on
	CookieName     string        // session cookie name (default ZERO-PEP-SID)
	InsecureCookie bool          // drop the __Host- prefix + Secure for http dev; default is secure
	TemplateDir    string        // override the embedded UI templates (os.DirFS); "" = embedded

	// Snapshot fast path (docs/stateless-session-validation.md). When SnapshotKeyPath is set, /oauth2/auth
	// validates an encrypted snapshot cookie locally (no kv) for the whole session. Keys are read from files.
	SnapshotKeyPath         string        // base64 256-bit key file; "" disables the fast path
	SnapshotPreviousKeyPath string        // optional previous key file (rotation overlap)
	SnapshotTTL             time.Duration // = session absolute lifetime (0 = 8h)

	// SessionStoreKeyPath enables at-rest encryption of kv session records (AES-256-GCM, the id as AAD) with a
	// SEPARATE base64 256-bit key file, independent of the snapshot key. "" leaves records as plaintext JSON.
	// Defends a rogue storage admin against disclosure, forgery, and record substitution. See
	// docs/at-rest-encryption.md.
	SessionStoreKeyPath string

	// Bus carries session revocations to all replicas so logout/lockout is fleet-wide instant. nil = a
	// single-instance in-memory revoker.
	Bus kv.Bus

	// Routes, when non-empty, turn on standalone gateway mode: pep gates + reverse-proxies these upstreams
	// itself (no Caddy). Empty = forward_auth-only, unchanged. gate: snapshot routes require the snapshot fast
	// path (SnapshotKeyPath).
	Routes []Route
}

// defaultSnapshotTTL is the snapshot lifetime, and — when the fast path is on — the session lifetime: the
// snapshot covers the whole session (forward_auth can't refresh the cookie), with instant revocation via the
// revoked-set as the only early termination.
const defaultSnapshotTTL = 8 * time.Hour

// Server serves the /oauth2/* endpoints over a Backend + session store.
type Server struct {
	sessions   *sessionStore
	cookie     *http.Cookie
	render     *renderer
	backend    Backend
	snap       *snapshotter // nil when the fast path is disabled (no key file)
	snapCookie *http.Cookie // snapshot cookie template (only when snap != nil)
	revoker    revoker
	gateway    *Gateway // nil in forward_auth-only mode (no Routes)
}

func New(cfg Config) (*Server, error) {
	if cfg.Backend == nil {
		return nil, fmt.Errorf("proxy: backend is required")
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("proxy: store is required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "ZERO-PEP-SID"
	}
	r, err := newRenderer(cfg.TemplateDir)
	if err != nil {
		return nil, err
	}

	snapTTL := cfg.SnapshotTTL
	if snapTTL <= 0 {
		snapTTL = defaultSnapshotTTL
	}
	snap, err := newSnapshotter(cfg.SnapshotKeyPath, cfg.SnapshotPreviousKeyPath, snapTTL)
	if err != nil {
		return nil, err
	}

	var rev revoker = newMemRevoker(snapTTL)
	if cfg.Bus != nil {
		rev = newBusRevoker(cfg.Bus, cfg.Store, snapTTL)
	}

	sessions := newSessionStore(cfg.Store, cfg.SessionTTL)
	if cfg.SessionStoreKeyPath != "" {
		key, err := loadBase64Key(cfg.SessionStoreKeyPath)
		if err != nil {
			return nil, fmt.Errorf("session store key: %w", err)
		}
		crypter, err := newAESRecordCrypter(key)
		if err != nil {
			return nil, fmt.Errorf("session store cipher: %w", err)
		}
		sessions.crypter = crypter
	}
	s := &Server{
		sessions: sessions,
		cookie:   newCookieTemplate(cfg.CookieName, cfg.InsecureCookie),
		render:   r,
		backend:  cfg.Backend,
		snap:     snap,
		revoker:  rev,
	}
	if snap != nil {
		// The snapshot covers the whole session, so the kv session must live as long (it holds the refresh
		// token) and there is no sliding idle: pin both the idle and absolute TTLs to the snapshot lifetime.
		sessions.ttl = snapTTL
		sessions.maxLifetime = snapTTL
		s.snapCookie = newCookieTemplate(cfg.CookieName+"-SNAP", cfg.InsecureCookie)
		slog.Info("snapshot fast path enabled", "ttl", snapTTL)
	}

	if len(cfg.Routes) > 0 {
		deps := gatewayDeps{currentSession: s.currentSession, backend: s.backend}
		if snap != nil {
			deps.cookieName = s.snapCookie.Name // the snapshot gate validates the -SNAP cookie
			deps.snapshotKeys = snap.decKeys
		}
		gw, err := newGateway(cfg.Routes, deps)
		if err != nil {
			return nil, fmt.Errorf("gateway: %w", err)
		}
		s.gateway = gw
		slog.Info("standalone gateway enabled", "routes", len(cfg.Routes))
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
	// Fast path: validate the encrypted snapshot locally — no kv — for the whole session lifetime. Revoked
	// sessions are rejected immediately via the revoked-set.
	if s.snap != nil {
		if c, err := r.Cookie(s.snapCookie.Name); err == nil {
			if claims, ok := s.snap.open(c.Value); ok {
				if s.revoker.IsRevoked(claims.SID) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				setIdentityHeaders(w.Header(), claims.Identity)
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}
		// No valid snapshot → fall through to the kv path; the /auth subrequest can't re-mint the cookie
		// (forward_auth), so the snapshot is (re)minted on the browser-direct callback/poll responses.
	}
	sess, ok := s.currentSession(r)
	if !ok || !sess.Authenticated() {
		_, cookieErr := r.Cookie(s.cookie.Name)
		slog.Debug("forward_auth deny", "uri", r.Header.Get("X-Forwarded-Uri"),
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
		slog.Warn("mint snapshot failed", "session", sess.ID, "error", err)
		return
	}
	setCookie(w, s.snapCookie, tok)
}

// sortProviders orders the chooser list: oidc + gemidp keep their configured order at the top, and the OIDF
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

// handleSignIn renders the provider chooser.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	rd := sanitizeReturnTo(r.URL.Query().Get("rd"))
	providers, err := s.backend.Providers(r.Context())
	if err != nil {
		s.renderError(w, "providers_error", err.Error(), "", rd)
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
		s.renderError(w, "login_failed", err.Error(), idpIss, rd)
		return
	}
	if err := s.sessions.save(sess); err != nil {
		s.renderError(w, "server_error", err.Error(), idpIss, rd)
		return
	}
	setCookie(w, s.cookie, sess.token)

	slog.Info("login start", "session", sess.ID, "idp_iss", idpIss, "mode", start.Mode, "auth_url", start.AuthURL)

	var name string
	if start.Provider != nil {
		name = start.Provider.Name
	}
	switch start.Mode {
	case "decoupled": // OIDF — QR for a second device + on-device redirect, polled
		img, err := qrImage(start.AuthURL)
		if err != nil {
			s.renderError(w, "qr_error", err.Error(), idpIss, rd)
			return
		}
		s.render.render(w, http.StatusOK, "qr.html", qrData{
			ProviderName: name, AuthURL: start.AuthURL, QRImage: img,
			PollURL: "/oauth2/poll", ReturnTo: sess.ReturnTo,
		})
	case "authenticator": // gemidp — open the authenticator:// app on this device + poll
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
		if err := s.sessions.rotate(sess); err != nil {
			slog.Warn("session rotation failed", "session", sess.ID, "error", err)
		} else {
			s.revoker.Revoke(oldID)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleCallback is the redirect_uri: it completes the login (by OAuth state) and returns to rd. The
// browser already holds the cookie from /oauth2/start, so no re-set is needed (and must not happen on a
// second device in the decoupled flow).
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Resolve the session by state first so error pages know which provider to retry.
	sess, serr := s.sessions.byState(q.Get("state"))
	var idpIss, rd string
	if serr == nil {
		idpIss, rd = sess.IDPIss, sess.ReturnTo
	}
	if e := q.Get("error"); e != "" {
		s.renderError(w, e, q.Get("error_description"), idpIss, rd)
		return
	}
	if serr != nil {
		s.renderError(w, "invalid_state", "unknown or expired login state", "", "")
		return
	}
	if err := s.backend.Complete(r.Context(), sess, q.Get("code")); err != nil {
		s.renderError(w, "exchange_failed", err.Error(), idpIss, rd)
		return
	}
	// Consume the one-time state so it can't be replayed; clearing it also stops save() from re-indexing it.
	s.sessions.deleteState(sess.State)
	sess.State = ""
	if err := s.sessions.save(sess); err != nil {
		s.renderError(w, "server_error", err.Error(), idpIss, rd)
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
	if !s.requestOwnsSession(r, sess) {
		slog.Info("login complete", "session", sess.ID, "idp_iss", sess.IDPIss, "decoupled", true)
		s.render.render(w, http.StatusOK, "complete.html", nil)
		return
	}
	// On-device: now that the user is authenticated, rotate the session id (anti-fixation), revoke the old id
	// (kills any old snapshot), re-bind the cookie, and mint a fresh snapshot before returning to rd.
	oldID := sess.ID
	if err := s.sessions.rotate(sess); err != nil {
		s.renderError(w, "server_error", err.Error(), idpIss, rd)
		return
	}
	s.revoker.Revoke(oldID)
	setCookie(w, s.cookie, sess.token)
	s.setSnapshot(w, sess)
	slog.Info("login complete", "session", sess.ID, "idp_iss", sess.IDPIss, "return_to", dest)
	http.Redirect(w, r, dest, http.StatusFound)
}

// requestOwnsSession reports whether the request carries the session cookie set at /oauth2/start for this
// session — true on the device that began the login, false on a second device in the decoupled flow.
func (s *Server) requestOwnsSession(r *http.Request, sess *Session) bool {
	c, err := r.Cookie(s.cookie.Name)
	return err == nil && hashToken(c.Value) == sess.ID
}

// handleSignOut clears the session. POST (XHR) requires the X-Requested-With CSRF header and returns 204;
// GET (a link) renders signed_out.html.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Header.Get("X-Requested-With") == "" {
		http.Error(w, "missing X-Requested-With", http.StatusForbidden)
		return
	}
	if sess, ok := s.currentSession(r); ok {
		_ = s.sessions.deleteByID(sess.ID)
		s.revoker.Revoke(sess.ID) // instant: any valid snapshot for this sid is rejected on the fast path
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
	sess, err := s.sessions.byToken(c.Value)
	if err != nil {
		return nil, false
	}
	return sess, true
}

// renderError renders the error page. idpIss (when non-empty) makes "Try again" retry that provider;
// returnTo is carried through both actions.
func (s *Server) renderError(w http.ResponseWriter, code, description, idpIss, returnTo string) {
	s.render.render(w, http.StatusBadRequest, "error.html", errorData{
		Code: code, Description: description, IDPIss: idpIss, ReturnTo: returnTo,
	})
}

// sanitizeReturnTo guards the rd= return-to against open redirects and login loops: a local absolute path
// that is not one of pep's own /oauth2/* endpoints. Returning into /oauth2/* bounces the browser back into
// the auth flow instead of the app, and it is how a forward_auth that fails to exclude /oauth2/* accretes an
// ever-growing rd=/oauth2/start?rd=/oauth2/start?… Anything rejected collapses to "" (callers default to "/").
func sanitizeReturnTo(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
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
