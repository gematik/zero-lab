package zas

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/oidf"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
)

type Server struct {
	identityIssuers  []oidc.Client
	oidfRelyingParty *oidf.RelyingParty
	clientsPolicy    *ClientsPolicy
	sessionStore     SessionStore
	sigPrK           jwk.Key
	jwks             jwk.Set
	encPuK           jwk.Key
}

type Option func(*Server) error

func NewServer(opts ...Option) (*Server, error) {
	s := &Server{
		identityIssuers: []oidc.Client{},
	}

	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func ErrorLogMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil {
			slog.Error("Error", "error", err, "path", c.Path(), "remote_addr", c.RealIP(), "headers", c.Request().Header)
		}
		return err
	}
}

func (s *Server) MountRoutes(group *echo.Group) {
	group.Use(ErrorLogMiddleware)
	group.GET("/auth", s.AuthorizationEndpoint)
	group.GET("/op-callback", s.OPCallbackEndpoint)
	group.POST("/par", s.PAREndpoint)
	group.POST("/token", s.TokenEndpoint)
	group.GET("/jwks", s.JWKS)
	group.GET("/openid-providers", s.OpenidProviders)

	if s.oidfRelyingParty != nil {
		group.GET("/.well-known/openid-federation", echo.WrapHandler(http.HandlerFunc(s.oidfRelyingParty.Serve)))
	}
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
	Claims        map[string]interface{}
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

	opClient, err := s.opClient(session.OPIssuer)
	if err != nil {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	if !s.clientsPolicy.AllowedRedirectURI(session.ClientId, session.RedirectUri) {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "invalid_request",
			Description: "redirect_uri forbidden by policy",
		})
	}

	if session.OPIntermediaryRedirectUri != "" {
		if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientId, session.OPIntermediaryRedirectUri) {
			return redirectWithError(c, session.RedirectUri, oauth2.Error{
				Code:        "invalid_request",
				Description: "op_indermediary_redirect_uri forbidden by policy",
			})
		}
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectUri)
	} else {
		session.OPIntermediaryRedirectUri = fmt.Sprintf("%s://%s/op-callback", c.Scheme(), c.Request().Host)
		slog.Info("Using default OP redirect uri", "redirect_uri", session.OPIntermediaryRedirectUri)
	}

	opSession := OpenidProviderSession{
		Issuer:      session.OPIssuer,
		State:       util.GenerateRandomString(128),
		Nonce:       session.Nonce,
		Verifier:    oauth2.GenerateCodeVerifier(),
		RedirectUri: session.OPIntermediaryRedirectUri,
	}

	authUrl, err := opClient.AuthCodeURL(
		opSession.State,
		opSession.Nonce,
		opSession.Verifier,
		oauth2.WithRedirectURI(opSession.RedirectUri),
	)
	if err != nil {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to generate auth url: %w", err).Error(),
		})
	}

	session.OPSession = &opSession
	if err := s.sessionStore.SaveSession(&session); err != nil {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	slog.Info("Redirecting to OP", "auth_url", authUrl)

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PAREndpoint(c echo.Context) error {
	requestUri := "urn:ietf:params:oauth:request_uri:" + util.GenerateRandomString(128)
	slog.Info("PAR accepted", "request_uri", requestUri)
	// TODO: implement PAR
	return echo.ErrBadRequest
}

func (s *Server) opClient(issuer string) (oidc.Client, error) {
	for _, op := range s.identityIssuers {
		if op.Issuer() == issuer {
			return op, nil
		}
	}
	if s.oidfRelyingParty != nil {
		return s.oidfRelyingParty.NewClient(issuer)
	}
	return nil, fmt.Errorf("unknown issuer: %s", issuer)
}

func (s *Server) OPCallbackEndpoint(c echo.Context) error {
	var state string
	var code string
	binderr := echo.FormFieldBinder(c).
		MustString("state", &state).
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

	identityIssuer, err := s.opClient(session.OPIssuer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
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

	idToken, err := identityIssuer.ParseIDToken(tokenResponse)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse id token: %w", err).Error(),
		})
	}

	session.OPSession.Claims, err = idToken.AsMap(context.TODO())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse id token: %w", err).Error(),
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

	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	if codeChallenge != session.CodeChallenge {
		return redirectWithError(c, session.RedirectUri, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
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
	accessJwt.Set("act", authzSession.OPSession.Claims)

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, s.sigPrK))
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	return string(accessTokenBytes), nil
}

func (s *Server) JWKS(c echo.Context) error {
	return c.JSON(http.StatusOK, s.jwks)
}

func (s *Server) OpenidProviders(c echo.Context) error {
	type openidProvider struct {
		Issuer           string `json:"iss"`
		LogoURI          string `json:"logo_uri"`
		OrganizationName string `json:"organization_name"`
	}
	providers := []openidProvider{}
	for _, op := range s.identityIssuers {
		providers = append(providers, openidProvider{
			Issuer:           op.Issuer(),
			LogoURI:          op.LogoURI(),
			OrganizationName: op.Name(),
		})
	}
	if s.oidfRelyingParty != nil {
		idps, err := s.oidfRelyingParty.Federation().FetchIdpList()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
		for _, op := range idps {
			// todo: remove this later
			if !strings.Contains(op.Issuer, ".tk.ru2") {
				continue
			}
			providers = append(providers, openidProvider{
				Issuer:           op.Issuer,
				LogoURI:          op.LogoURI,
				OrganizationName: op.OrganizationName,
			})
		}
	}
	return c.JSON(http.StatusOK, providers)
}
