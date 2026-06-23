// Package proxy is an oauth2-proxy-style authentication gateway: it runs the login (against direct OIDC/
// OIDF/gemidp providers or — later — a PDP), keeps the tokens server-side, and exposes the oauth2-proxy
// endpoint contract (/oauth2/{auth,start,sign_in,callback,sign_out,…}) so it works behind Caddy in
// forward_auth mode and as a standalone gateway. It is the token-mediating BFF, generalized, and will
// replace the bff over time.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

// Config configures the proxy server.
type Config struct {
	Backend          Backend       // the auth backend (providerBackend today; pdpBackend later)
	Store            kv.Store      // session store
	SessionTTL       time.Duration // sliding session TTL (0 = 1h)
	CookieName       string        // session cookie name (default ZERO-PEP-SID)
	ProductionCookie bool          // __Host- + Secure (true behind HTTPS)
	TemplateDir      string        // override the embedded UI templates (os.DirFS); "" = embedded
}

// Server serves the /oauth2/* endpoints over a Backend + session store.
type Server struct {
	sessions *sessionStore
	cookie   *http.Cookie
	render   *renderer
	backend  Backend
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
	return &Server{
		sessions: newSessionStore(cfg.Store, cfg.SessionTTL),
		cookie:   newCookieTemplate(cfg.CookieName, cfg.ProductionCookie),
		render:   r,
		backend:  cfg.Backend,
	}, nil
}

// Handler returns the /oauth2/* mux. Mount it at the root; in forward_auth mode Caddy reverse_proxies
// /oauth2/* here and forward_auths every other route to /oauth2/auth.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/auth", s.handleAuth)
	mux.HandleFunc("GET /oauth2/start", s.handleStart)
	mux.HandleFunc("GET /oauth2/sign_in", s.handleSignIn)
	mux.HandleFunc("GET /oauth2/callback", s.handleCallback)
	mux.HandleFunc("GET /oauth2/sign_out", s.handleSignOut)
	mux.HandleFunc("POST /oauth2/sign_out", s.handleSignOut)
	return mux
}

type signInData struct {
	Providers []Provider
	ReturnTo  string
}

type errorData struct {
	Code        string
	Description string
}

// handleAuth is the forward_auth subrequest: 202 + identity headers when authenticated, bare 401 otherwise
// (Caddy's handle_response then redirects to /oauth2/start?rd=).
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok || !sess.Authenticated() {
		_, cookieErr := r.Cookie(s.cookie.Name)
		slog.Debug("forward_auth deny", "uri", r.Header.Get("X-Forwarded-Uri"),
			"cookie_present", cookieErr == nil, "session_found", ok)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	setIdentityHeaders(w.Header(), sess.Identity)
	slog.Debug("forward_auth allow", "session", sess.ID, "user", claimString(sess.Identity, "preferred_username", "sub"))
	w.WriteHeader(http.StatusAccepted)
}

// handleSignIn renders the provider chooser.
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	providers, err := s.backend.Providers(r.Context())
	if err != nil {
		s.renderError(w, "providers_error", err.Error())
		return
	}
	s.render.render(w, http.StatusOK, "sign_in.html", signInData{
		Providers: providers,
		ReturnTo:  sanitizeReturnTo(r.URL.Query().Get("rd")),
	})
}

// handleStart begins a login: it creates a pending session, binds the cookie, and redirects to the IdP.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sess := s.sessions.create()
	sess.ReturnTo = sanitizeReturnTo(q.Get("rd"))

	start, err := s.backend.StartLogin(r.Context(), sess, q.Get("idp_iss"), q.Get("scope"))
	if err != nil {
		s.renderError(w, "login_failed", err.Error())
		return
	}
	if err := s.sessions.save(sess); err != nil {
		s.renderError(w, "server_error", err.Error())
		return
	}
	setCookie(w, s.cookie, sess.ID)
	// S1: all direct providers redirect. The decoupled (OIDF QR) branch lands in S2.
	http.Redirect(w, r, start.AuthURL, http.StatusFound)
}

// handleCallback is the redirect_uri: it completes the login (by OAuth state) and returns to rd. The
// browser already holds the cookie from /oauth2/start, so no re-set is needed (and must not happen on a
// second device in the decoupled flow).
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.renderError(w, e, q.Get("error_description"))
		return
	}
	sess, err := s.sessions.byState(q.Get("state"))
	if err != nil {
		s.renderError(w, "invalid_state", "unknown or expired login state")
		return
	}
	if err := s.backend.Complete(r.Context(), sess, q.Get("code")); err != nil {
		s.renderError(w, "exchange_failed", err.Error())
		return
	}
	if err := s.sessions.save(sess); err != nil {
		s.renderError(w, "server_error", err.Error())
		return
	}
	dest := sess.ReturnTo
	if dest == "" {
		dest = "/"
	}
	slog.Info("login complete", "session", sess.ID, "idp_iss", sess.IDPIss, "return_to", dest)
	http.Redirect(w, r, dest, http.StatusFound)
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
	}
	expireCookie(w, s.cookie)
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
	sess, err := s.sessions.byID(c.Value)
	if err != nil {
		return nil, false
	}
	return sess, true
}

func (s *Server) renderError(w http.ResponseWriter, code, description string) {
	s.render.render(w, http.StatusBadRequest, "error.html", errorData{Code: code, Description: description})
}

// sanitizeReturnTo guards the rd= return-to against open redirects: a local absolute path only.
func sanitizeReturnTo(rd string) string {
	if strings.HasPrefix(rd, "/") && !strings.HasPrefix(rd, "//") && !strings.HasPrefix(rd, "/\\") {
		return rd
	}
	return ""
}
