package bff

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/oauth2"
)

// clientAssertionTypeJWTBearer is the client_assertion_type for private_key_jwt (RFC 7523 §2.2).
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

type Error struct {
	// HTTPStatusCode is used as the HTTP status code when the error is rendered as a response.
	HTTPStatusCode int `json:"-"`
	// OAuth2 error fields.
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("error: %s, description: %s", e.Code, e.Description)
}

var errTemplateUnauthorized = Error{
	HTTPStatusCode: http.StatusUnauthorized,
	Code:           "unauthorized",
	Description:    "Unauthorized",
}

var errTemplateInternalError = Error{
	HTTPStatusCode: http.StatusInternalServerError,
	Code:           "internal_error",
	Description:    "Internal error",
}

type Config struct {
	AuthorizationServer   AuthorizationServerConfig `json:"authorization_server" validate:"required"`
	CookieName            string                    `json:"cookie_name" validate:"required"`
	ProductionGradeCookie bool                      `json:"production_grade_cookie"`
	FrontendRedirectURI   string                    `json:"frontend_redirect_uri" validate:"required"`

	// SessionManager overrides the default in-memory mock when non-nil. Not serialized.
	SessionManager SessionManager `json:"-"`
	// HTTPClient is used for all server-to-server calls (discovery, introspection, providers). Not serialized.
	HTTPClient *http.Client `json:"-"`
}

// AuthorizationServerConfig describes the BFF's confidential-client credentials at the AS. The BFF
// MUST be a confidential client (BCP draft-ietf-oauth-browser-based-apps), which is also required so
// it may introspect its own access token at the AS. It authenticates with private_key_jwt (RFC 7523):
// it signs a client_assertion with SigningKey (whose public half is registered at the AS) and declares
// DPoPKey's thumbprint as the assertion's cnf.jkt, binding the issued access token to that key.
type AuthorizationServerConfig struct {
	Issuer      string `json:"issuer" validate:"required"`
	ClientID    string `json:"client_id" validate:"required"`
	RedirectURI string `json:"redirect_uri" validate:"required"`
	// Scopes the BFF requests from the AS when a login does not specify its own. Space-joined into the
	// authorization request's scope parameter.
	Scopes []string `json:"scopes"`

	// SigningKey signs the client_assertion; its public JWK is registered at the AS. Set programmatically.
	SigningKey jwk.Key `json:"-"`
	// DPoPKey is the sender-constraining key whose thumbprint is the assertion's cnf.jkt. Set programmatically.
	DPoPKey jwk.Key `json:"-"`
}

// asMetadata is the subset of RFC 8414 authorization-server metadata the BFF needs.
type asMetadata struct {
	Issuer                  string `json:"issuer"`
	AuthorizationEndpoint   string `json:"authorization_endpoint"`
	TokenEndpoint           string `json:"token_endpoint"`
	IntrospectionEndpoint   string `json:"introspection_endpoint"`
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
	NonceEndpoint           string `json:"nonce_endpoint"`
}

// providerInfo mirrors the AS openid-providers list entry.
type providerInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
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
	frontendRedirectURL *url.URL
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
	if b.frontendRedirectURL, err = url.Parse(cfg.FrontendRedirectURI); err != nil {
		return nil, fmt.Errorf("parse frontend redirect uri: %w", err)
	}

	if cfg.SessionManager != nil {
		b.sessionManager = cfg.SessionManager
	} else {
		b.sessionManager = NewSessionManager(kv.NewMemory(), 0)
	}

	if b.metadata, err = b.discoverMetadata(cfg.AuthorizationServer.Issuer); err != nil {
		return nil, fmt.Errorf("discover authorization server metadata: %w", err)
	}

	b.oauth2Client = &oauth2.Config{
		ClientID: cfg.AuthorizationServer.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:   b.metadata.AuthorizationEndpoint,
			TokenURL:  b.metadata.TokenEndpoint,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: cfg.AuthorizationServer.RedirectURI,
	}

	return b, nil
}

// clientAssertion mints a private_key_jwt assertion (RFC 7523 §2.2) authenticating the BFF to the AS:
// iss=sub=client_id, aud=issuer, a fresh AS nonce, and cnf.jkt = the DPoP key thumbprint. Signed with
// the BFF's registered signing key.
func (b *BackendForFrontend) clientAssertion(ctx context.Context) (string, error) {
	as := b.cfg.AuthorizationServer
	if as.SigningKey == nil || as.DPoPKey == nil {
		return "", fmt.Errorf("client signing/DPoP key not configured")
	}
	nonce, err := b.fetchNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch nonce: %w", err)
	}
	thumb, err := as.DPoPKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)

	now := time.Now()
	// aud must be the AS's real issuer (which it validates against), not the local discovery URL.
	tok := jwt.New()
	tok.Set(jwt.IssuerKey, as.ClientID)
	tok.Set(jwt.SubjectKey, as.ClientID)
	tok.Set(jwt.AudienceKey, b.metadata.Issuer)
	tok.Set(jwt.IssuedAtKey, now.Unix())
	tok.Set(jwt.ExpirationKey, now.Add(time.Minute).Unix())
	tok.Set("nonce", nonce)
	tok.Set("cnf", map[string]string{"jkt": jkt})

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), as.SigningKey))
	if err != nil {
		return "", fmt.Errorf("sign client_assertion: %w", err)
	}
	return string(signed), nil
}

// fetchNonce gets a one-time nonce from the AS nonce endpoint (plain-text body).
func (b *BackendForFrontend) fetchNonce(ctx context.Context) (string, error) {
	if b.metadata.NonceEndpoint == "" {
		return "", fmt.Errorf("no nonce_endpoint in metadata")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.metadata.NonceEndpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("nonce endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
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
					HTTPStatusCode: http.StatusInternalServerError,
					Code:           "internal_error",
					Description:    "Internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type loginResponse struct {
	AuthURL string        `json:"auth_url"`
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
	if scope == "" {
		scope = strings.Join(b.cfg.AuthorizationServer.Scopes, " ")
	}

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
	authURL := b.oauth2Client.AuthCodeURL(session.State, opts...)

	b.setCookie(w, session.ID)

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

	// For the decoupled (OIDF) flow, resolve the authorization request server-side: the AS performs the
	// PAR and 302-redirects to the provider's authorization URL, so the second device gets a direct link
	// to the OpenID provider (the AS stays behind the scenes). The whole flow is state-correlated, so a
	// server-initiated PAR completes normally. If the AS does not redirect, surface the error instead of
	// a QR.
	if mode == "decoupled" {
		directURL, err := b.resolveDecoupledAuthURL(authURL)
		if err != nil {
			respondWithError(w, elaborateError(errTemplateInternalError, "start decoupled login: %v", err))
			return
		}
		authURL = directURL
	}

	respondJSON(w, http.StatusOK, loginResponse{AuthURL: authURL, Mode: mode, Op: op})
}

// resolveDecoupledAuthURL drives the AS authorization request in the backend (the AS performs the PAR)
// without following the redirect, and returns the provider authorization URL from the 3xx Location — the
// link the second device opens. The redirect is only handed to the browser if it is a clean redirect to
// the provider: a non-3xx response, or a redirect back to our redirect_uri carrying ?error= (PAR or
// validation failed), is returned as an error so the caller renders it instead of a QR to our own callback.
func (b *BackendForFrontend) resolveDecoupledAuthURL(authURL string) (string, error) {
	noRedirect := *b.httpClient
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := noRedirect.Get(authURL)
	if err != nil {
		return "", fmt.Errorf("fetch authorization url: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("authorization server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("authorization redirect without Location: %w", err)
	}
	if e := loc.Query().Get("error"); e != "" {
		return "", fmt.Errorf("%s: %s", e, loc.Query().Get("error_description"))
	}
	return loc.String(), nil
}

// CallbackEndpoint is the OAuth redirect_uri. It exchanges the code, introspects the access token at
// the AS to capture the upstream identity, stores everything in the session, and redirects to the SPA.
func (b *BackendForFrontend) CallbackEndpoint(w http.ResponseWriter, r *http.Request) {
	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		b.redirectToFrontend(w, r, &Error{
			Code:        oauthErr,
			Description: r.URL.Query().Get("error_description"),
			URI:         r.URL.Query().Get("error_uri"),
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

	assertion, err := b.clientAssertion(r.Context())
	if err != nil {
		b.redirectToFrontend(w, r, elaborateError(errTemplateInternalError, "build client assertion: %v", err))
		return
	}
	token, err := b.oauth2Client.Exchange(r.Context(), code,
		oauth2.VerifierOption(session.CodeVerifier),
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionTypeJWTBearer),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	)
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
	Authenticated bool         `json:"authenticated"`
	Session       *SessionView `json:"session,omitempty"`
}

// SessionView is the browser-facing projection of a session: decoded token CLAIMS and non-secret
// fields only. The raw access/refresh tokens, the session id, and the PKCE verifier are never
// serialized — keeping the BFF property that bearer tokens stay server-side.
type SessionView struct {
	Identity    map[string]any `json:"identity,omitempty"`     // upstream identity claims
	AccessToken map[string]any `json:"access_token,omitempty"` // decoded access-token claims (not the raw JWT)
	IDToken     map[string]any `json:"id_token,omitempty"`     // decoded id_token claims (not the raw JWT)
	Scope       string         `json:"scope,omitempty"`
	ClientID    string         `json:"client_id,omitempty"`
	ExpiresAt   time.Time      `json:"expires_at,omitempty"`
}

// newSessionView decodes the access token and id_token to their claims and copies the non-secret
// introspection fields, dropping all raw token material.
func newSessionView(session *Session) *SessionView {
	sv := &SessionView{
		AccessToken: decodeJWTClaims(session.AccessToken),
		ExpiresAt:   session.AccessTokenExpiresAt,
	}
	if intro := session.Identity; intro != nil {
		sv.Identity, _ = intro["identity"].(map[string]any)
		sv.Scope, _ = intro["scope"].(string)
		sv.ClientID, _ = intro["client_id"].(string)
		if idt, _ := intro["id_token"].(string); idt != "" {
			sv.IDToken = decodeJWTClaims(idt)
		}
	}
	return sv
}

// decodeJWTClaims returns a JWT's payload claims (no signature verification). Returns nil for non-JWTs.
func decodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims
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
		b.sessionManager.DeleteSessionByID(session.ID)
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

	respondJSON(w, http.StatusOK, sessionResponse{Authenticated: true, Session: newSessionView(session)})
}

// LogoutEndpoint terminates the session. CSRF is defended by requiring a custom header that a
// cross-site form submission cannot set (in addition to the SameSite=Strict cookie).
func (b *BackendForFrontend) LogoutEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") == "" {
		respondWithError(w, &Error{
			HTTPStatusCode: http.StatusForbidden,
			Code:           "invalid_request",
			Description:    "missing X-Requested-With header",
		})
		return
	}
	if session, err := b.sessionByCookie(r); err == nil {
		_ = b.sessionManager.DeleteSessionByID(session.ID)
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
	assertion, err := b.clientAssertion(ctx)
	if err != nil {
		return nil, fmt.Errorf("build client assertion: %w", err)
	}
	form := url.Values{
		"token":                 {accessToken},
		"client_assertion_type": {clientAssertionTypeJWTBearer},
		"client_assertion":      {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.metadata.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned %d", resp.StatusCode)
	}
	// Capture the whole RFC 7662 introspection response (identity claims, id_token, scope, cnf, session,
	// …) so the BFF can surface the full session, not only the identity sub-object.
	var ir map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		return nil, err
	}
	if active, _ := ir["active"].(bool); !active {
		return nil, fmt.Errorf("token is not active")
	}
	return ir, nil
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
	session, err := b.sessionManager.GetSessionByID(cookie.Value)
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
	redirectURI := *b.frontendRedirectURL
	params := url.Values{}
	if errForClient != nil {
		params.Set("error", errForClient.Code)
		params.Set("error_description", errForClient.Description)
		if errForClient.URI != "" {
			params.Set("error_uri", errForClient.URI)
		}
	} else {
		// Mark a completed login so the landing page (e.g. the cookie-less decoupled device) shows
		// success instead of the provider chooser.
		params.Set("login", "success")
	}
	redirectURI.RawQuery = params.Encode()
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
	respondJSON(w, err.HTTPStatusCode, err)
}
