package bff

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

type CryptoFunc func([]byte) ([]byte, error)

type Error struct {
	//  this will be used as the HTTP status code, when the error is rendered as a response
	HttpStatusCode int `json:"-"`
	// oauth2 error fields
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
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
	EncryptKeyString      string                    `json:"encrypt_key" validate:"required"`
	SignKeyString         string                    `json:"sign_key" validate:"required"`
	CookieName            string                    `json:"cookie_name" validate:"required"`
	ProductionGradeCookie bool                      `json:"production_grade_cookie"`
	FrontendRedirectURI   string                    `json:"frontend_redirect_uri" validate:"required"`
}

type AuthorizationServerConfig struct {
	Issuer       string `json:"issuer" validate:"required"`
	ClientID     string `json:"client_id" validate:"required"`
	ClientSecret string `json:"client_secret" validate:"required"`
	RedirectURI  string `json:"redirect_uri" validate:"required"`
}

type BackendForFrontend struct {
	pathPrefix          string
	cfg                 Config
	sessionManager      SessionManager
	cookieTemplate      *http.Cookie
	encryptCookie       CryptoFunc
	decryptCookie       CryptoFunc
	signCookie          CryptoFunc
	verifyCookie        CryptoFunc
	oauth2Client        *oauth2.Config
	frontendRedirectURL *url.URL
}

func New(cfg Config) (*BackendForFrontend, error) {
	b := &BackendForFrontend{
		cfg:        cfg,
		pathPrefix: "/bff",
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
		return nil, err
	}

	encryptKey, err := base64.StdEncoding.DecodeString(cfg.EncryptKeyString)
	if err != nil {
		return nil, err
	}
	b.encryptCookie = EncryptWithDirectKeyFunc(encryptKey)
	b.decryptCookie = DecryptWithDirectKeyFunc(encryptKey)

	signKey, err := base64.StdEncoding.DecodeString(cfg.SignKeyString)
	if err != nil {
		return nil, err
	}
	b.signCookie = SignWithHS256KeyFunc(signKey)
	b.verifyCookie = VerifyWithHS256KeyFunc(signKey)

	// TODO: implement session manager
	b.sessionManager = NewSessionManagerMock()

	b.oauth2Client = &oauth2.Config{
		ClientID:     cfg.AuthorizationServer.ClientID,
		ClientSecret: cfg.AuthorizationServer.ClientSecret,
		Endpoint: oauth2.Endpoint{
			// TODO: use metadata
			AuthURL:  fmt.Sprintf("%s/auth", cfg.AuthorizationServer.Issuer),
			TokenURL: fmt.Sprintf("%s/token", cfg.AuthorizationServer.Issuer),
		},
		RedirectURL: cfg.AuthorizationServer.RedirectURI,
	}

	return b, nil
}

func (b *BackendForFrontend) Protect(handlerFunc func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieRaw, err := b.retrieveSession(r)
		if err != nil {
			slog.Error("Failed to retrieve session", "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(err.HttpStatusCode)
			_ = json.NewEncoder(w).Encode(err)
			return
		}
		slog.Info("Cookie verified", "cookie", cookieRaw)
		handlerFunc(w, r)
	})
}

func elaborateError(template Error, description string, a ...any) *Error {
	template.Description = fmt.Sprintf(description, a...)
	return &template
}

func (b *BackendForFrontend) retrieveSession(r *http.Request) (*Session, *Error) {
	cookie, err := r.Cookie(b.cookieTemplate.Name)
	if err != nil {
		return nil, elaborateError(errTemplateUnauthorized, "Failed to get cookie '%s': %v", b.cookieTemplate.Name, err)
	}

	session, err := b.sessionManager.GetSessionByID(cookie.Value)
	if err != nil {
		return nil, elaborateError(errTemplateUnauthorized, "Failed to get session '%s': %v", cookie.Value, err)
	}

	if session.AccessToken == "" {
		return nil, elaborateError(errTemplateUnauthorized, "Access token not found in session")
	}

	return session, nil
}

func (b *BackendForFrontend) CheckSessionEndpoint(w http.ResponseWriter, r *http.Request) {
	session, err := b.retrieveSession(r)
	if err != nil {
		slog.Error("Failed to verify cookie", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(err.HttpStatusCode)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	ts := b.oauth2Client.TokenSource(r.Context(), &oauth2.Token{
		AccessToken:  session.AccessToken,
		Expiry:       session.AccessTokenExpiresAt,
		RefreshToken: session.RefreshToken,
	})

	token, tokenErr := ts.Token()
	if tokenErr != nil {
		slog.Error("Failed to get token", "error", tokenErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(elaborateError(errTemplateUnauthorized, "Failed to get token: %v", tokenErr))
		return
	}

	slog.Info("Token is valid", "token", token)

	if session.AccessTokenExpiresAt.Before(time.Now()) {
		slog.Info("Session is expired", "session", session)
		b.sessionManager.DeleteSessionByID(session.ID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (b *BackendForFrontend) AuthorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	session, err := b.sessionManager.CreateSession(oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), "S256")
	if err != nil {
		slog.Error("Failed to create session", "error", err)
		respondWithError(w, elaborateError(errTemplateInternalError, "Failed to create session: %v", err))
		return
	}

	scope := r.URL.Query().Get("scope")

	authURL := b.oauth2Client.AuthCodeURL(session.State, oauth2.S256ChallengeOption(session.CodeVerifier), oauth2.SetAuthURLParam("scope", scope))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (b *BackendForFrontend) CallbackEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		b.redirectToFrontend(w, r, &Error{
			Code:        r.URL.Query().Get("error"),
			Description: r.URL.Query().Get("error_description"),
			URI:         r.URL.Query().Get("error_uri"),
		})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	session, err := b.sessionManager.GetSessionByState(state)
	if err != nil {
		respondWithError(w, elaborateError(errTemplateUnauthorized, "Failed to get session: %v", err))
		return
	}

	token, err := b.oauth2Client.Exchange(r.Context(), code, oauth2.VerifierOption(session.CodeVerifier))
	if err != nil {
		b.redirectToFrontend(w, r, elaborateError(errTemplateInternalError, "Failed to exchange code for token: %v", err))
		return
	}

	session.AccessToken = token.AccessToken
	session.AccessTokenExpiresAt = token.Expiry
	session.RefreshToken = token.RefreshToken

	err = b.sessionManager.UpdateSession(session)
	if err != nil {
		b.redirectToFrontend(w, r, elaborateError(errTemplateInternalError, "Failed to update session: %v", err))
		return
	}

	b.setCookie(w, session.ID)
	b.redirectToFrontend(w, r, nil)
}

func (b *BackendForFrontend) setCookie(w http.ResponseWriter, sessionID string) {
	cookie := *b.cookieTemplate
	cookie.Value = sessionID
	http.SetCookie(w, &cookie)
	slog.Info("Set cookie", "cookie", cookie)
}

func (b *BackendForFrontend) redirectToFrontend(w http.ResponseWriter, r *http.Request, errForClient *Error) {
	redirectURI := *b.frontendRedirectURL

	if errForClient != nil {
		params := &url.Values{}
		params.Set("error", errForClient.Code)
		params.Set("error_description", errForClient.Description)
		if errForClient.URI != "" {
			params.Set("error_uri", errForClient.URI)
		}

		redirectURI.RawQuery = params.Encode()
	}

	slog.Info("Redirecting to frontend", "uri", redirectURI.String())
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func respondWithError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HttpStatusCode)
	_ = json.NewEncoder(w).Encode(err)
}

func (b *BackendForFrontend) Mount(mux *http.ServeMux) {

	bffMux := http.NewServeMux()

	bffMux.HandleFunc("GET /check-session", b.CheckSessionEndpoint)
	bffMux.HandleFunc("GET /auth", b.AuthorizeEndpoint)
	bffMux.HandleFunc("GET /as-callback", b.CallbackEndpoint)

	mux.Handle(b.pathPrefix+"/", http.StripPrefix(b.pathPrefix, bffMux))
}
