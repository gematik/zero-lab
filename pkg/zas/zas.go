package zas

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
)

type Server struct {
	identityIssuers []*oidc.Client
	clientsPolicy   *ClientsPolicy
	sessionStore    SessionStore
	sigKey          *jwk.Key
}

func NewServer(sessionStore SessionStore, clientsPolicy *ClientsPolicy) (*Server, error) {
	if sessionStore == nil {
		sessionStore = newMockSessionStore()
	}

	sigKey, err := util.RandomJWK()
	if err != nil {
		return nil, fmt.Errorf("unable to generate keys: %w", err)
	}

	return &Server{
		identityIssuers: make([]*oidc.Client, 0),
		sessionStore:    sessionStore,
		clientsPolicy:   clientsPolicy,
		sigKey:          &sigKey,
	}, nil
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
	OPIssuer                  string
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

func redirectWithError(c echo.Context, redirectUri string, err oauth2.Error) error {
	params := url.Values{}
	params.Add("error", err.Code)
	params.Add("error_description", err.Description)

	return c.Redirect(http.StatusFound, redirectUri+"?"+params.Encode())
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
		MustString("op_issuer", &session.OPIssuer).
		String("op_intermediary_redirect_uri", &session.OPIntermediaryRedirectUri).
		BindError()

	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	if !s.clientsPolicy.AllowedClient(session.ClientId) {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown client_id",
		})
	}

	identityIssuer := s.findIdentityIssuer(session.OPIssuer)
	if identityIssuer == nil {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown issuer",
		})
	}

	if session.OPIntermediaryRedirectUri != "" {
		if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientId, session.OPIntermediaryRedirectUri) {
			return redirectWithError(c, session.RedirectUri, oauth2.Error{
				Code:        "invalid_request",
				Description: "invalid redirect_uri",
			})
		}
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectUri)
	} else {
		session.OPIntermediaryRedirectUri = identityIssuer.DefaultRedirectURI()
		slog.Info("Using default OP redirect uri", "redirect_uri", identityIssuer.DefaultRedirectURI())
	}

	opSession := OpenidProviderSession{
		Issuer:      session.OPIssuer,
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
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
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

	identityIssuer := s.findIdentityIssuer(session.OPIssuer)
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

func (s *Server) TokenEndpoint(c echo.Context) error {
	var grantType string
	var code string
	var codeVerifier string
	var redirectUri string
	var clientId string
	binderr := echo.FormFieldBinder(c).
		MustString("grant_type", &grantType).
		MustString("code", &code).
		MustString("code_verifier", &codeVerifier).
		MustString("redirect_uri", &redirectUri).
		String("client_id", &clientId).
		BindError()

	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	slog.Info("Token request", "grant_type", grantType, "code", code, "redirect_uri", redirectUri, "client_id", clientId)

	session, err := s.sessionStore.GetSessionByCode(code)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		})
	}

	slog.Info("Token request: session", "session", session)

	if session.ClientId != clientId {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "client_id mismatch",
		})
	}

	if session.RedirectUri != redirectUri {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "redirect_uri mismatch",
		})
	}

	accessToken, err := s.issueAccessToken(session)
	if err != nil {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		})
	}

	slog.Info("Token request: access token issued", "access_token", accessToken, "details", util.JWSToText(accessToken))

	response := oauth2.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "",
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) issueAccessToken(authzSession *AuthorizationSession) (string, error) {
	accessJwt := jwt.New()
	accessJwt.Set("sub", authzSession.ClientId)
	accessJwt.Set("aud", "https://as.example.com") // TODO: use actual audience
	accessJwt.Set("exp", time.Now().Add(24*time.Hour).Unix())
	accessJwt.Set("jti", ksuid.New().String())
	accessJwt.Set("scope", authzSession.Scope)

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, *s.sigKey))
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	return string(accessTokenBytes), nil
}
