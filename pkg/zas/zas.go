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
	IdentityIssuers  []oidc.Client
	OIDFRelyingParty *oidf.RelyingParty
	clientsPolicy    *ClientsPolicy
	SessionStore     AuthzSessionStore
	sigPrK           jwk.Key
	jwks             jwk.Set
	encPuK           jwk.Key
}

type Option func(*Server) error

func NewServer(opts ...Option) (*Server, error) {
	s := &Server{
		IdentityIssuers: []oidc.Client{},
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
	group.GET("/openid-providers", s.OpenidProvidersEndpoint)

	if s.OIDFRelyingParty != nil {
		group.GET("/.well-known/openid-federation", echo.WrapHandler(http.HandlerFunc(s.OIDFRelyingParty.Serve)))
	}
}

func redirectWithError(c echo.Context, redirectUri string, err oauth2.Error) error {
	params := url.Values{}
	params.Add("error", err.Code)
	params.Add("error_description", err.Description)

	return c.Redirect(http.StatusFound, redirectUri+"?"+params.Encode())
}

func (s *Server) AuthorizationEndpoint(c echo.Context) error {
	var session AuthzSession
	binderr := echo.FormFieldBinder(c).
		MustString("response_type", &session.ResponseType).
		MustString("client_id", &session.ClientID).
		MustString("redirect_uri", &session.RedirectURI).
		MustString("code_challenge", &session.CodeChallenge).
		MustString("code_challenge_method", &session.CodeChallengeMethod).
		MustString("nonce", &session.Nonce).
		MustString("state", &session.State).
		MustString("scope", &session.Scope).
		MustString("op_issuer", &session.OPIssuer).
		String("op_intermediary_redirect_uri", &session.OPIntermediaryRedirectURI).
		BindError()

	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	if !s.clientsPolicy.AllowedClient(session.ClientID) {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown client_id",
		})
	}

	opClient, err := s.OpenidProvider(session.OPIssuer)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	if !s.clientsPolicy.AllowedRedirectURI(session.ClientID, session.RedirectURI) {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
			Code:        "invalid_request",
			Description: "redirect_uri forbidden by policy",
		})
	}

	if session.OPIntermediaryRedirectURI != "" {
		if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientID, session.OPIntermediaryRedirectURI) {
			return redirectWithError(c, session.RedirectURI, oauth2.Error{
				Code:        "invalid_request",
				Description: "op_indermediary_redirect_uri forbidden by policy",
			})
		}
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectURI)
	} else {
		session.OPIntermediaryRedirectURI = fmt.Sprintf("%s://%s/op-callback", c.Scheme(), c.Request().Host)
		slog.Info("Using default OP redirect uri", "redirect_uri", session.OPIntermediaryRedirectURI)
	}

	opSession := oidc.AuthnSession{
		ID:          ksuid.New().String(),
		Issuer:      session.OPIssuer,
		State:       ksuid.New().String(),
		Nonce:       session.Nonce,
		Verifier:    oauth2.GenerateCodeVerifier(),
		RedirectURI: session.OPIntermediaryRedirectURI,
	}

	authUrl, err := opClient.AuthCodeURL(
		opSession.State,
		opSession.Nonce,
		opSession.Verifier,
		oauth2.WithAlternateRedirectURI(opSession.RedirectURI),
	)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to generate auth url: %w", err).Error(),
		})
	}
	opSession.AuthURL = authUrl

	session.AuthnSession = &opSession
	if err := s.SessionStore.SaveAutzhSession(&session); err != nil {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
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

func (s *Server) OpenidProvider(issuer string) (oidc.Client, error) {
	for _, op := range s.IdentityIssuers {
		if op.Issuer() == issuer {
			return op, nil
		}
	}

	if s.OIDFRelyingParty != nil {
		return s.OIDFRelyingParty.NewClient(issuer)
	}
	return nil, fmt.Errorf("unknown issuer: %s", issuer)
}

func (s *Server) StartOpenidProviderSession(issuer string) (*oidc.AuthnSession, error) {
	op, err := s.OpenidProvider(issuer)
	if err != nil {
		return nil, err
	}

	session := &oidc.AuthnSession{
		ID:       ksuid.New().String(),
		Issuer:   op.Issuer(),
		State:    ksuid.New().String(),
		Nonce:    util.GenerateRandomString(64),
		Verifier: oauth2.GenerateCodeVerifier(),
	}

	authURL, err := op.AuthCodeURL(session.State, session.Nonce, session.Verifier)
	if err != nil {
		return nil, fmt.Errorf("unable to generate auth url: %w", err)
	}

	session.AuthURL = authURL

	return session, nil
}

func (s *Server) OPCallbackEndpoint(c echo.Context) error {
	if c.QueryParam("error") != "" {
		slog.Error("OP callback error", "query", c.QueryString())
		return c.Redirect(
			http.StatusFound,
			fmt.Sprintf("/web/error?error=%s&error_description=%s",
				url.QueryEscape(c.QueryParam("error")),
				url.QueryEscape(c.QueryParam("error_description")),
			),
		)
	}
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

	var authnSession *oidc.AuthnSession
	authzSession, err := s.SessionStore.GetAuthzSessionByAuthnState(state)
	if err == nil {
		authnSession = authzSession.AuthnSession
		if authnSession == nil {
			return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
				Code:        "invalid_request",
				Description: "missing openid session",
			})
		}
	} else {
		authnSession, err = s.SessionStore.GetAuthnSessionByState(state)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
				Code:        "invalid_request",
				Description: fmt.Errorf("unable to get session: %w", err).Error(),
			})
		}
	}

	identityIssuer, err := s.OpenidProvider(authnSession.Issuer)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	tokenResponse, err := identityIssuer.Exchange(
		code,
		authnSession.Verifier,
		oauth2.WithAlternateRedirectURI(authnSession.RedirectURI),
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

	authnSession.Claims, err = idToken.AsMap(context.TODO())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse id token: %w", err).Error(),
		})
	}

	authnSession.TokenResponse = tokenResponse

	if authzSession != nil {
		authzSession.Code = util.GenerateRandomString(128)

		if err := s.SessionStore.SaveAutzhSession(authzSession); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, oauth2.Error{
				Code:        "server_error",
				Description: fmt.Errorf("unable to save session: %w", err).Error(),
			})
		}

		params := url.Values{}
		params.Set("code", authzSession.Code)
		params.Set("state", authzSession.State)

		return c.Redirect(http.StatusFound, authzSession.RedirectURI+"?"+params.Encode())
	}

	return c.JSON(http.StatusOK, idToken.PrivateClaims())
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

	session, err := s.SessionStore.GetAuthzSessionByCode(code)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		})
	}

	slog.Info("Token request: session", "session", session)

	if session.ClientID != clientId {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "client_id mismatch",
		})
	}

	if session.RedirectURI != redirectUri {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "redirect_uri mismatch",
		})
	}

	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	if codeChallenge != session.CodeChallenge {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	accessToken, err := s.issueAccessToken(session)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, oauth2.Error{
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

func (s *Server) issueAccessToken(authzSession *AuthzSession) (string, error) {
	accessJwt := jwt.New()
	accessJwt.Set("sub", authzSession.ClientID)
	accessJwt.Set("aud", "https://as.example.com") // TODO: use actual audience
	accessJwt.Set("exp", time.Now().Add(24*time.Hour).Unix())
	accessJwt.Set("jti", ksuid.New().String())
	accessJwt.Set("scope", authzSession.Scope)
	accessJwt.Set("act", authzSession.AuthnSession.Claims)

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, s.sigPrK))
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	return string(accessTokenBytes), nil
}

func (s *Server) JWKS(c echo.Context) error {
	return c.JSON(http.StatusOK, s.jwks)
}

type OpenidProviderInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
}

func (s *Server) OpenidProvidersEndpoint(c echo.Context) error {
	providers, err := s.OpenidProviders()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, providers)
}

func (s *Server) OpenidProviders() ([]OpenidProviderInfo, error) {
	providers := []OpenidProviderInfo{}
	for _, op := range s.IdentityIssuers {
		providers = append(providers, OpenidProviderInfo{
			Issuer:  op.Issuer(),
			LogoURI: op.LogoURI(),
			Name:    op.Name(),
		})
	}
	if s.OIDFRelyingParty != nil {
		idps, err := s.OIDFRelyingParty.Federation().FetchIdpList()
		if err != nil {
			return nil, fmt.Errorf("fetching idp list from federation: %w", err)
		}
		for _, op := range idps {
			// todo: remove this later
			if !strings.Contains(op.Issuer, ".tk.ru2") {
				continue
			}
			providers = append(providers, OpenidProviderInfo{
				Issuer:  op.Issuer,
				LogoURI: op.LogoURI,
				Name:    op.OrganizationName,
			})
		}
	}

	return providers, nil
}
