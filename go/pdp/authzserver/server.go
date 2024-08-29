package authzserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gematik/zero-lab/go/libzero/gemidp"
	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/gematik/zero-lab/go/libzero/oidc"
	"github.com/gematik/zero-lab/go/libzero/oidf"
	"github.com/gematik/zero-lab/go/libzero/util"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type Option func(*Server) error

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// Extend the standard OAuth2 server metadata from RFC8414
type ExtendedMetadata struct {
	oauth2.ServerMetadata
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
}

type Server struct {
	Metadata         ExtendedMetadata
	identityIssuers  []oidc.Client
	oidfRelyingParty *oidf.RelyingParty
	clientsPolicy    *ClientsPolicy
	sessionStore     AuthzServerSessionStore
	sigPrK           jwk.Key
	jwks             jwk.Set
	encPuK           jwk.Key
}

func ErrorHandlerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil {
			slog.Error("Error", "error", err, "path", c.Path(), "remote_addr", c.RealIP(), "headers", c.Request().Header)
			authzError, ok := err.(*Error)
			if ok {
				return c.JSON(authzError.HttpStatus, authzError)
			} else {
				return c.JSON(http.StatusInternalServerError, &Error{
					HttpStatus:  http.StatusInternalServerError,
					Code:        "server_error",
					Description: err.Error(),
				})
			}
		}
		return nil
	}
}

func (s *Server) MountRoutes(group *echo.Group) {
	group.Use(
		middleware.Logger(),
		ErrorHandlerMiddleware,
	)

	group.GET("/.well-known/oauth-authorization-server", s.MetadataEndpoint)
	group.GET("/auth", s.AuthorizationEndpoint)
	group.GET("/op-callback", s.OPCallbackEndpoint)
	group.GET("/gemidp-callback", s.OPCallbackEndpoint)
	group.POST("/par", s.PAREndpoint)
	group.POST("/token", s.TokenEndpoint)
	group.GET("/jwks", s.JWKS)
	group.GET("/openid-providers", s.OpenidProvidersEndpoint)

	if s.oidfRelyingParty != nil {
		group.GET("/.well-known/openid-federation", echo.WrapHandler(http.HandlerFunc(s.oidfRelyingParty.Serve)))
		group.GET("/oidf-relying-party-jwks", echo.WrapHandler(http.HandlerFunc(s.oidfRelyingParty.ServeSignedJwks)))
	}
}

func redirectWithError(c echo.Context, redirectUri string, state string, err oauth2.Error) error {
	params := url.Values{}
	if state != "" {
		params.Add("state", state)
	}
	params.Add("error", err.Code)
	params.Add("error_description", err.Description)

	return c.Redirect(http.StatusFound, redirectUri+"?"+params.Encode())
}

func (s *Server) MetadataEndpoint(c echo.Context) error {
	return c.JSON(http.StatusOK, s.Metadata)
}

func (s *Server) AuthorizationEndpoint(c echo.Context) error {
	var session AuthzServerSession
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
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: binderr.Error(),
		}
	}

	if !s.clientsPolicy.AllowedClient(session.ClientID) {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown client_id",
		})
	}

	opClient, err := s.OpenidProvider(session.OPIssuer)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	if !s.clientsPolicy.AllowedRedirectURI(session.ClientID, session.RedirectURI) {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "invalid_request",
			Description: "redirect_uri forbidden by policy",
		})
	}

	if session.OPIntermediaryRedirectURI != "" {
		if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientID, session.OPIntermediaryRedirectURI) {
			return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
				Code:        "invalid_request",
				Description: "op_indermediary_redirect_uri forbidden by policy",
			})
		}
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectURI)
	}

	opSession := oidc.AuthnClientSession{
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
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to generate auth url: %w", err).Error(),
		})
	}
	opSession.AuthURL = authUrl

	session.AuthnClientSession = &opSession
	if err := s.sessionStore.SaveAutzhServerSession(&session); err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	slog.Info("Redirecting to OP", "auth_url", authUrl)

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PAREndpoint(c echo.Context) error {
	requestUri := "urn:ietf:params:oauth:request_uri:" + util.GenerateRandomString(128)
	slog.Error("PAR not implemented", "request_uri", requestUri)
	// TODO: implement PAR
	return &Error{
		HttpStatus:  http.StatusBadRequest,
		Code:        "unsupported_grant_type",
		Description: "PAR grant type not supported",
	}
}

// OpenidProvider returns an OpenID Connect client for the given issuer
func (s *Server) OpenidProvider(issuer string) (oidc.Client, error) {
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

// OPCallbackEndpoint handles the callback from the OpenID Provider
func (s *Server) OPCallbackEndpoint(c echo.Context) error {
	// retrieve state from query
	state := c.QueryParam("state")
	if state == "" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing state",
		}
	}

	// find running session by the OP state
	var authnSession *oidc.AuthnClientSession
	authzSession, err := s.sessionStore.GetAuthzServerSessionByAuthnState(state)
	if err == nil {
		authnSession = authzSession.AuthnClientSession
		if authnSession == nil {
			return &Error{
				HttpStatus:  http.StatusBadRequest,
				Code:        "invalid_request",
				Description: "missing openid session",
			}
		}
	} else {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		}
	}

	if c.QueryParam("error") != "" {
		slog.Error("OP callback error", "query", c.QueryString())
		return redirectWithError(c, authnSession.RedirectURI, authnSession.State, oauth2.Error{
			Code:        c.QueryParam("error"),
			Description: c.QueryParam("error_description"),
		})
	}

	// retrieve PKCE code from query
	code := c.QueryParam("code")
	if code == "" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing code",
		}
	}

	slog.Info("OP callback", "s", s, "authnSessiom", authnSession, "authzSession", authzSession)

	identityIssuer, err := s.OpenidProvider(authnSession.Issuer)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}

	// exchange code for tokens with the OP
	tokenResponse, err := identityIssuer.Exchange(
		code,
		authnSession.Verifier,
		oauth2.WithAlternateRedirectURI(authnSession.RedirectURI),
	)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to exchange code: %w", err).Error(),
		}
	}

	idToken, err := identityIssuer.ParseIDToken(tokenResponse)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse id token: %w", err).Error(),
		}
	}

	authnSession.Claims, err = idToken.AsMap(context.TODO())
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse id token: %w", err).Error(),
		}
	}

	authnSession.TokenResponse = tokenResponse

	if authzSession != nil {
		authzSession.Code = util.GenerateRandomString(128)

		if err := s.sessionStore.SaveAutzhServerSession(authzSession); err != nil {
			return &Error{
				HttpStatus:  http.StatusInternalServerError,
				Code:        "server_error",
				Description: fmt.Errorf("unable to save session: %w", err).Error(),
			}
		}

		params := url.Values{}
		params.Set("code", authzSession.Code)
		params.Set("state", authzSession.State)

		return c.Redirect(http.StatusFound, authzSession.RedirectURI+"?"+params.Encode())
	}

	return c.JSON(http.StatusOK, idToken.PrivateClaims())
}

// TokenEndpoint handles the token request for varous grant types
func (s *Server) TokenEndpoint(c echo.Context) error {
	r := c.Request()
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "invalid content type",
		}
	}
	if err := r.ParseForm(); err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to parse form: %w", err).Error(),
		}
	}

	if !r.Form.Has("grant_type") {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing grant_type",
		}
	}
	grantType := r.FormValue("grant_type")
	switch grantType {
	case GrantTypeAuthorizationCode:
		return s.TokenEndpointAuthorizationCode(c)
	case GrantTypeClientCredentials:
		return s.TokenEndpointClientCredentials(c)
	default:
		slog.Error("Unsupported grant type", "grant_type", grantType)
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unsupported_grant_type",
			Description: fmt.Sprintf("unsupported grant type: %s", grantType),
		}
	}

}

func (s *Server) TokenEndpointClientCredentials(c echo.Context) error {
	return &Error{
		HttpStatus:  http.StatusBadRequest,
		Code:        "unsupported_grant_type",
		Description: "client_credentials grant type not supported",
	}
}

// TokenEndpointAuthorizationCode handles the token request for the authorization code grant type
func (s *Server) TokenEndpointAuthorizationCode(c echo.Context) error {
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
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: binderr.Error(),
		}
	}

	slog.Info("Token request", "grant_type", grantType, "code", code, "redirect_uri", redirectUri, "client_id", clientId)

	session, err := s.sessionStore.GetAuthzServerSessionByCode(code)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		}
	}

	slog.Info("Token request: session", "session", session)

	if session.ClientID != clientId {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "client_id mismatch",
		}
	}

	if session.RedirectURI != redirectUri {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "redirect_uri mismatch",
		}
	}

	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	if codeChallenge != session.CodeChallenge {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	accessToken, err := s.issueAccessToken(session)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, oauth2.Error{
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

// issueAccessToken issues an access token for the given authorization session
// upon successful authentication with the OpenID Provider and authorization
func (s *Server) issueAccessToken(authzSession *AuthzServerSession) (string, error) {
	accessJwt := jwt.New()
	accessJwt.Set("sub", authzSession.ClientID)
	accessJwt.Set("aud", authzSession.ClientID)
	accessJwt.Set("exp", time.Now().Add(24*time.Hour).Unix())
	accessJwt.Set("jti", ksuid.New().String())
	accessJwt.Set("scope", authzSession.Scope)
	if authzSession.AuthnClientSession.Claims != nil {
		accessJwt.Set("urn:telematik:zta:subject", authzSession.AuthnClientSession.Claims)
	}

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, s.sigPrK))
	if err != nil {
		return "", fmt.Errorf("unable to sign access token: %w", err)
	}

	return string(accessTokenBytes), nil
}

// JWKS serves the JSON Web Key Set for the server
func (s *Server) JWKS(c echo.Context) error {
	return c.JSON(http.StatusOK, s.jwks)
}

// OpenidProvidersEndpoint serves the list of OpenID Providers supported by the server
func (s *Server) OpenidProvidersEndpoint(c echo.Context) error {
	providers, err := s.OpenidProviders()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, providers)
}

// OpenidProviders returns the list of OpenID Providers supported by the server
func (s *Server) OpenidProviders() ([]oidc.OpenidProviderInfo, error) {
	providers := []oidc.OpenidProviderInfo{}
	for _, op := range s.identityIssuers {
		info := oidc.OpenidProviderInfo{
			Issuer:  op.Issuer(),
			LogoURI: op.LogoURI(),
			Name:    op.Name(),
		}
		switch op.(type) {
		case *gemidp.Client:
			info.Type = "gemidp"
		default:
			info.Type = "oidc"
		}
		providers = append(providers, info)

	}
	if s.oidfRelyingParty != nil {
		idps, err := s.oidfRelyingParty.Federation().FetchIdpList()
		if err != nil {
			return nil, fmt.Errorf("fetching idp list from federation: %w", err)
		}
		for _, op := range idps {
			providers = append(providers, oidc.OpenidProviderInfo{
				Issuer:  op.Issuer,
				LogoURI: op.LogoURI,
				Name:    op.OrganizationName,
				Type:    "oidf",
			})
		}
	}

	return providers, nil
}
