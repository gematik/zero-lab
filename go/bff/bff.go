package bff

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type Error struct {
	// HttpStatusCode is used as the HTTP status code when the error is rendered as a response.
	HttpStatusCode int `json:"-"`
	// OAuth2 error fields.
	Code        string `json:"error"`
	Description string `json:"error_description"`
	Uri         string `json:"error_uri,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("error: %s, description: %s", e.Code, e.Description)
}

var errTemplateUnauthorized = Error{
	HttpStatusCode: http.StatusUnauthorized,
	Code:           "unauthorized",
	Description:    "Unauthorized",
}

var errTemplateInternalError = Error{
	HttpStatusCode: http.StatusInternalServerError,
	Code:           "internal_error",
	Description:    "Internal error",
}

type Config struct {
	AuthorizationServer   AuthorizationServerConfig `json:"authorization_server" validate:"required"`
	CookieName            string                    `json:"cookie_name" validate:"required"`
	ProductionGradeCookie bool                      `json:"production_grade_cookie"`
	FrontendRedirectUri   string                    `json:"frontend_redirect_uri" validate:"required"`

	// SessionManager overrides the default in-memory mock when non-nil. Not serialized.
	SessionManager SessionManager `json:"-"`
	// HTTPClient is used for all server-to-server calls (discovery, introspection, providers). Not serialized.
	HTTPClient *http.Client `json:"-"`
}

// AuthorizationServerConfig describes the BFF's confidential-client credentials at the AS. The BFF
// MUST be a confidential client (BCP draft-ietf-oauth-browser-based-apps), which is also required so
// it may introspect its own access token at the AS.
type AuthorizationServerConfig struct {
	Issuer       string `json:"issuer" validate:"required"`
	ClientId     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	RedirectUri  string `json:"redirect_uri" validate:"required"`
}

// asMetadata is the subset of RFC 8414 authorization-server metadata the BFF needs.
type asMetadata struct {
	Issuer                  string `json:"issuer"`
	AuthorizationEndpoint   string `json:"authorization_endpoint"`
	TokenEndpoint           string `json:"token_endpoint"`
	IntrospectionEndpoint   string `json:"introspection_endpoint"`
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
}

// providerInfo mirrors the AS openid-providers list entry.
type providerInfo struct {
	Issuer  string `json:"iss"`
	LogoUri string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

type BackendForFrontend struct {
	cfg                 Config
	httpClient          *http.Client
	sessionManager      SessionManager
	cookieTemplate      *http.Cookie
	oauth2Client        *oauth2.Config
	metadata            asMetadata
	frontendRedirectUrl *url.URL
}

func New(cfg Config) (*BackendForFrontend, error) {
	b := &BackendForFrontend{cfg: cfg}

	b.httpClient = cfg.HTTPClient
	if b.httpClient == nil {
		b.httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	if cfg.ProductionGradeCookie {
		b.cookieTemplate = &http.Cookie{
			Name:     fmt.Sprintf("__Host-%s", cfg.CookieName),
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
	} else {
		b.cookieTemplate = &http.Cookie{
			Name:     cfg.CookieName,
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
	}

	var err error
	if b.frontendRedirectUrl, err = url.Parse(cfg.FrontendRedirectUri); err != nil {
		return nil, fmt.Errorf("parse frontend redirect uri: %w", err)
	}

	if cfg.SessionManager != nil {
		b.sessionManager = cfg.SessionManager
	} else {
		b.sessionManager = NewSessionManagerMock()
	}

	if b.metadata, err = b.discoverMetadata(cfg.AuthorizationServer.Issuer); err != nil {
		return nil, fmt.Errorf("discover authorization server metadata: %w", err)
	}

	b.oauth2Client = &oauth2.Config{
		ClientID:     cfg.AuthorizationServer.ClientId,
		ClientSecret: cfg.AuthorizationServer.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  b.metadata.AuthorizationEndpoint,
			TokenURL: b.metadata.TokenEndpoint,
		},
		RedirectURL: cfg.AuthorizationServer.RedirectUri,
	}

	return b, nil
}

// discoverMetadata fetches the RFC 8414 authorization-server metadata document.
func (b *BackendForFrontend) discoverMetadata(issuer string) (asMetadata, error) {
	var md asMetadata
	u := strings.TrimRight(issuer, "/") + "/.well-known/oauth-authorization-server"
	resp, err := b.httpClient.Get(u)
	if err != nil {
		return md, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return md, fmt.Errorf("metadata endpoint %s returned %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return md, fmt.Errorf("decode metadata: %w", err)
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" {
		return md, fmt.Errorf("metadata missing authorization/token endpoint")
	}
	return md, nil
}

// Mount registers the BFF control plane under /bff/auth/ on the given mux, wrapped by the panic
// recovery middleware. /bff/api/ is reserved for a future token-injecting resource-server proxy.
func (b *BackendForFrontend) Mount(mux *http.ServeMux) {
	authMux := http.NewServeMux()
	authMux.HandleFunc("GET /bff/auth/login", b.LoginEndpoint)
	authMux.HandleFunc("GET /bff/auth/callback", b.CallbackEndpoint)
	authMux.HandleFunc("GET /bff/auth/poll", b.PollEndpoint)
	authMux.HandleFunc("GET /bff/auth/session", b.SessionEndpoint)
	authMux.HandleFunc("POST /bff/auth/logout", b.LogoutEndpoint)
	authMux.HandleFunc("GET /bff/auth/providers", b.ProvidersEndpoint)

	mux.Handle("/bff/", RecoverMiddleware(authMux))
}

// RecoverMiddleware catches panics, logs the stack, and renders a 500 JSON error so a single bad
// request cannot take down the server. Exported so the host can wrap its top-level mux (incl. static).
func RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("recovered from panic", "error", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				respondWithError(w, &Error{
					HttpStatusCode: http.StatusInternalServerError,
					Code:           "internal_error",
					Description:    "Internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type loginResponse struct {
	AuthUrl string        `json:"auth_url"`
	Mode    string        `json:"mode"` // "redirect" or "decoupled"
	Op      *providerInfo `json:"op,omitempty"`
}

// LoginEndpoint starts a login: it creates a pending session, binds this browser to it via the
// session cookie (so a decoupled second device can complete it), and returns the authorization URL.
// For OIDF providers it advertises mode "decoupled" (the SPA renders a QR + polls); otherwise the
// SPA performs a full-page redirect to auth_url.
func (b *BackendForFrontend) LoginEndpoint(w http.ResponseWriter, r *http.Request) {
	opIssuer := r.URL.Query().Get("op_issuer")
	scope := r.URL.Query().Get("scope")

	session, err := b.sessionManager.CreateSession(oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), "S256")
	if err != nil {
		respondWithError(w, elaborateError(errTemplateInternalError, "create session: %v", err))
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(session.CodeVerifier)}
	if scope != "" {
		opts = append(opts, oauth2.SetAuthURLParam("scope", scope))
	}
	if opIssuer != "" {
		opts = append(opts, oauth2.SetAuthURLParam("op_issuer", opIssuer))
	}
	authUrl := b.oauth2Client.AuthCodeURL(session.State, opts...)

	b.setCookie(w, session.Id)

	mode := "redirect"
	var op *providerInfo
	if opIssuer != "" {
		if p, err := b.lookupProvider(opIssuer); err != nil {
			slog.Warn("provider lookup failed", "op_issuer", opIssuer, "error", err)
		} else {
			op = p
			if p.Type == "oidf" {
				mode = "decoupled"
			}
		}
	}

	respondJSON(w, http.StatusOK, loginResponse{AuthUrl: authUrl, Mode: mode, Op: op})
}

// CallbackEndpoint is the OAuth redirect_uri. It exchanges the code, introspects the access token at
// the AS to capture the upstream identity, stores everything in the session, and redirects to the SPA.
func (b *BackendForFrontend) CallbackEndpoint(w http.ResponseWriter, r *http.Request) {
	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		b.redirectToFrontend(w, r, &Error{
			Code:        oauthErr,
			Description: r.URL.Query().Get("error_description"),
			Uri:         r.URL.Query().Get("error_uri"),
		})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	session, sessErr := b.sessionManager.GetSessionByState(state)
	if sessErr != nil {
		respondWithError(w, elaborateError(errTemplateUnauthorized, "get session by state: %v", sessErr))
		return
	}

	token, err := b.oauth2Client.Exchange(r.Context(), code, oauth2.VerifierOption(session.CodeVerifier))
	if err != nil {
		b.redirectToFrontend(w, r, elaborateError(errTemplateInternalError, "exchange code: %v", err))
		return
	}

	session.AccessToken = token.AccessToken
	session.AccessTokenExpiresAt = token.Expiry
	session.RefreshToken = token.RefreshToken

	// Capture the upstream identity via introspection (best-effort; the session is still valid without it).
	if identity, err := b.introspectIdentity(r.Context(), token.AccessToken); err != nil {
		slog.Warn("introspection failed", "error", err)
	} else {
		session.Identity = identity
	}

	if err := b.sessionManager.UpdateSession(session); err != nil {
		b.redirectToFrontend(w, r, elaborateError(errTemplateInternalError, "update session: %v", err))
		return
	}

	b.redirectToFrontend(w, r, nil)
}

// PollEndpoint reports whether the cookie-bound session has completed authentication yet. Used by the
// SPA during the decoupled (QR) flow: 202 while pending, 200 once the session holds an access token.
func (b *BackendForFrontend) PollEndpoint(w http.ResponseWriter, r *http.Request) {
	session, err := b.sessionByCookie(r)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, map[string]bool{"authenticated": false})
		return
	}
	if session.AccessToken == "" {
		respondJSON(w, http.StatusAccepted, map[string]bool{"authenticated": false})
		return
	}
	respondJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

type sessionResponse struct {
	Authenticated bool           `json:"authenticated"`
	UserInfo      map[string]any `json:"userinfo,omitempty"`
}

// SessionEndpoint returns the authenticated user's identity for the cookie-bound session, refreshing
// the access token as needed. Returns 401 {authenticated:false} when there is no valid session.
func (b *BackendForFrontend) SessionEndpoint(w http.ResponseWriter, r *http.Request) {
	session, err := b.retrieveSession(r)
	if err != nil {
		respondJSON(w, http.StatusUnauthorized, sessionResponse{Authenticated: false})
		return
	}

	ts := b.oauth2Client.TokenSource(r.Context(), &oauth2.Token{
		AccessToken:  session.AccessToken,
		Expiry:       session.AccessTokenExpiresAt,
		RefreshToken: session.RefreshToken,
	})
	token, tokenErr := ts.Token()
	if tokenErr != nil {
		slog.Warn("session token refresh failed", "error", tokenErr)
		b.sessionManager.DeleteSessionById(session.Id)
		b.expireCookie(w)
		respondJSON(w, http.StatusUnauthorized, sessionResponse{Authenticated: false})
		return
	}
	if token.AccessToken != session.AccessToken {
		session.AccessToken = token.AccessToken
		session.AccessTokenExpiresAt = token.Expiry
		session.RefreshToken = token.RefreshToken
		_ = b.sessionManager.UpdateSession(session)
	}

	respondJSON(w, http.StatusOK, sessionResponse{Authenticated: true, UserInfo: session.Identity})
}

// LogoutEndpoint terminates the session. CSRF is defended by requiring a custom header that a
// cross-site form submission cannot set (in addition to the SameSite=Strict cookie).
func (b *BackendForFrontend) LogoutEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") == "" {
		respondWithError(w, &Error{
			HttpStatusCode: http.StatusForbidden,
			Code:           "invalid_request",
			Description:    "missing X-Requested-With header",
		})
		return
	}
	if session, err := b.sessionByCookie(r); err == nil {
		_ = b.sessionManager.DeleteSessionById(session.Id)
	}
	b.expireCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// ProvidersEndpoint returns the AS openid-providers list for the SPA's provider chooser.
func (b *BackendForFrontend) ProvidersEndpoint(w http.ResponseWriter, r *http.Request) {
	providers, err := b.fetchProviders()
	if err != nil {
		respondWithError(w, elaborateError(errTemplateInternalError, "fetch providers: %v", err))
		return
	}
	respondJSON(w, http.StatusOK, providers)
}

// Protect wraps a downstream handler so it only runs for an authenticated session (e.g. a future
// resource-server proxy under /bff/api/).
func (b *BackendForFrontend) Protect(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := b.retrieveSession(r); err != nil {
			slog.Error("failed to retrieve session", "error", err)
			respondWithError(w, err)
			return
		}
		next(w, r)
	}
}

// introspectIdentity asks the AS for the upstream identity behind an access token, authenticating as
// the BFF's confidential client (only the client a token was issued to may introspect it).
func (b *BackendForFrontend) introspectIdentity(ctx context.Context, accessToken string) (map[string]any, error) {
	if b.metadata.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("no introspection_endpoint in metadata")
	}
	form := url.Values{"token": {accessToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.metadata.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(b.cfg.AuthorizationServer.ClientId, b.cfg.AuthorizationServer.ClientSecret)

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned %d", resp.StatusCode)
	}
	var ir struct {
		Active   bool           `json:"active"`
		Identity map[string]any `json:"identity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, err
	}
	if !ir.Active {
		return nil, fmt.Errorf("token is not active")
	}
	return ir.Identity, nil
}

func (b *BackendForFrontend) fetchProviders() ([]providerInfo, error) {
	if b.metadata.OpenidProvidersEndpoint == "" {
		return nil, fmt.Errorf("no openid_providers_endpoint in metadata")
	}
	resp, err := b.httpClient.Get(b.metadata.OpenidProvidersEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("providers endpoint returned %d", resp.StatusCode)
	}
	var providers []providerInfo
	if err := json.NewDecoder(resp.Body).Decode(&providers); err != nil {
		return nil, err
	}
	return providers, nil
}

func (b *BackendForFrontend) lookupProvider(issuer string) (*providerInfo, error) {
	providers, err := b.fetchProviders()
	if err != nil {
		return nil, err
	}
	for i := range providers {
		if providers[i].Issuer == issuer {
			return &providers[i], nil
		}
	}
	return nil, fmt.Errorf("provider %q not found", issuer)
}

func (b *BackendForFrontend) sessionByCookie(r *http.Request) (*Session, *Error) {
	cookie, err := r.Cookie(b.cookieTemplate.Name)
	if err != nil {
		return nil, elaborateError(errTemplateUnauthorized, "missing cookie '%s': %v", b.cookieTemplate.Name, err)
	}
	session, err := b.sessionManager.GetSessionById(cookie.Value)
	if err != nil {
		return nil, elaborateError(errTemplateUnauthorized, "session not found: %v", err)
	}
	return session, nil
}

func (b *BackendForFrontend) retrieveSession(r *http.Request) (*Session, *Error) {
	session, err := b.sessionByCookie(r)
	if err != nil {
		return nil, err
	}
	if session.AccessToken == "" {
		return nil, elaborateError(errTemplateUnauthorized, "access token not found in session")
	}
	return session, nil
}

func (b *BackendForFrontend) setCookie(w http.ResponseWriter, sessionID string) {
	cookie := *b.cookieTemplate
	cookie.Value = sessionID
	http.SetCookie(w, &cookie)
}

func (b *BackendForFrontend) expireCookie(w http.ResponseWriter) {
	cookie := *b.cookieTemplate
	cookie.Value = ""
	cookie.MaxAge = -1
	http.SetCookie(w, &cookie)
}

func (b *BackendForFrontend) redirectToFrontend(w http.ResponseWriter, r *http.Request, errForClient *Error) {
	redirectURI := *b.frontendRedirectUrl
	if errForClient != nil {
		params := url.Values{}
		params.Set("error", errForClient.Code)
		params.Set("error_description", errForClient.Description)
		if errForClient.Uri != "" {
			params.Set("error_uri", errForClient.Uri)
		}
		redirectURI.RawQuery = params.Encode()
	}
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func elaborateError(template Error, description string, a ...any) *Error {
	template.Description = fmt.Sprintf(description, a...)
	return &template
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func respondWithError(w http.ResponseWriter, err *Error) {
	respondJSON(w, err.HttpStatusCode, err)
}
