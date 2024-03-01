package zas

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
)

type Server struct {
	identityIssuers []*oidc.Client
	clientsPolicy   *ClientsPolicy
	sessionStore    SessionStore
}

func NewServer(sessionStore SessionStore, clientsPolicy *ClientsPolicy) *Server {
	if sessionStore == nil {
		sessionStore = newMockSessionStore()
	}
	return &Server{
		identityIssuers: make([]*oidc.Client, 0),
		sessionStore:    sessionStore,
		clientsPolicy:   clientsPolicy,
	}
}

func (s *Server) AddIdentityIssuers(issuer ...*oidc.Client) {
	s.identityIssuers = append(s.identityIssuers, issuer...)
}

func (s *Server) MountRoutes(group *echo.Group) {
	group.GET("/auth", s.AuthorizationEndpoint)
	group.GET("/op-callback", s.OPCallbackEndpoint)
	group.POST("/par", s.PAREndpoint)
	group.POST("/token", s.TokenEndpoint)
}

type AuthorizationSession struct {
	ResponseType              string
	ClientId                  string
	RedirectUri               string
	CodeChallenge             string
	CodeChallengeMethod       string
	Nonce                     string
	State                     string
	Scope                     string
	Issuer                    string
	OPIntermediaryRedirectUri string
	RequestUri                string
	OPSession                 *OpenidProviderSession
	Code                      string
}

type OpenidProviderSession struct {
	Issuer        string
	State         string
	Nonce         string
	Verifier      string
	RedirectUri   string
	TokenResponse *oauth2.TokenResponse
}

func (s *Server) AuthorizationEndpoint(c echo.Context) error {
	var session AuthorizationSession
	binderr := echo.FormFieldBinder(c).
		MustString("response_type", &session.ResponseType).
		MustString("client_id", &session.ClientId).
		MustString("redirect_uri", &session.RedirectUri).
		MustString("code_challenge", &session.CodeChallenge).
		MustString("code_challenge_method", &session.CodeChallengeMethod).
		MustString("nonce", &session.Nonce).
		MustString("state", &session.State).
		MustString("scope", &session.Scope).
		MustString("issuer", &session.Issuer).
		String("op_intermediary_redirect_uri", &session.OPIntermediaryRedirectUri).
		BindError()

	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	if !s.clientsPolicy.AllowedClient(session.ClientId) {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown client_id",
		})
	}

	if session.OPIntermediaryRedirectUri == "" {
		session.OPIntermediaryRedirectUri = session.RedirectUri
		slog.Info("OP Intermediary Redirect URI is not set. Using redirect_uri instead.", "redirect_uri", session.OPIntermediaryRedirectUri)
	} else {
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectUri)
	}

	if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientId, session.OPIntermediaryRedirectUri) {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid redirect_uri",
		})
	}

	identityIssuer := s.findIdentityIssuer(session.Issuer)
	if identityIssuer == nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown issuer",
		})
	}

	opSession := OpenidProviderSession{
		Issuer:      session.Issuer,
		State:       util.GenerateRandomString(128),
		Nonce:       session.Nonce,
		Verifier:    oauth2.GenerateCodeVerifier(),
		RedirectUri: session.OPIntermediaryRedirectUri,
	}

	authUrl := identityIssuer.AuthCodeURL(
		opSession.State,
		opSession.Nonce,
		opSession.Verifier,
		oauth2.WithRedirectURI(opSession.RedirectUri),
	)

	session.OPSession = &opSession
	if err := s.sessionStore.SaveSession(&session); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PAREndpoint(c echo.Context) error {
	requestUri := "urn:ietf:params:oauth:request_uri:" + util.GenerateRandomString(128)
	slog.Info("PAR accepted", "request_uri", requestUri)

	return echo.ErrBadRequest
}

func (s *Server) findIdentityIssuer(issuer string) *oidc.Client {
	for _, id := range s.identityIssuers {
		if id.Config.Issuer == issuer {
			return id
		}
	}
	return nil
}

func (s *Server) TokenEndpoint(c echo.Context) error {
	return echo.ErrBadRequest
}

func (s *Server) OPCallbackEndpoint(c echo.Context) error {
	var state string
	var scope string
	var code string
	binderr := echo.FormFieldBinder(c).
		MustString("state", &state).
		MustString("scope", &scope).
		MustString("code", &code).
		BindError()
	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	session, err := s.sessionStore.GetSessionByOPState(state)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		})
	}

	if session.OPSession == nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "missing openid session",
		})
	}

	identityIssuer := s.findIdentityIssuer(session.Issuer)
	if identityIssuer == nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown issuer",
		})
	}

	tokenResponse, err := identityIssuer.Exchange(
		code,
		session.OPSession.Verifier,
		oauth2.WithRedirectURI(session.OPSession.RedirectUri),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to exchange code: %w", err).Error(),
		})
	}

	session.OPSession.TokenResponse = tokenResponse
	session.Code = util.GenerateRandomString(128)

	if err := s.sessionStore.SaveSession(session); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	params := url.Values{}
	params.Set("code", session.Code)
	params.Set("state", session.State)

	return c.Redirect(http.StatusFound, session.RedirectUri+"?"+params.Encode())
}
