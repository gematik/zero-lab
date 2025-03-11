package oauth2server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oidf"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type Server struct {
	Metadata                  ExtendedMetadata
	endpointPaths             *EndpointsConfig
	clientsRegistry           ClientsRegistry
	openidProviders           []oidc.Client
	oidfRelyingParty          *oidf.RelyingParty
	defaultOPIssuer           string
	clientsPolicy             *ClientsPolicy
	sessionStore              AuthzServerSessionStore
	sigPrK                    jwk.Key
	jwks                      jwk.Set
	encPuK                    jwk.Key
	nonceService              nonce.Service
	verifyClientAssertionFunc VerifyClientAssertionFunc
	dpopMaxAge                time.Duration
}

func NewFromConfigFile(filename string) (*Server, error) {
	cfg := new(Config)
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config file '%s': %w", filename, err)
	}
	if err := yaml.Unmarshal(yamlFile, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config file '%s': %w", filename, err)
	}

	return New(*cfg)
}

func New(cfg Config) (*Server, error) {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		return fld.Tag.Get("yaml")
	})

	s := &Server{
		Metadata:        cfg.MetadataTemplate,
		openidProviders: make([]oidc.Client, 0),
	}

	issuerUri, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URI: %w", err)
	}

	s.endpointPaths = &cfg.Endpoints
	s.endpointPaths.applyDefaults(issuerUri)

	for _, c := range cfg.OidcProviders {
		client, err := oidc.NewClient(c)
		if err != nil {
			return nil, fmt.Errorf("create oidc client: %w", err)
		}
		slog.Info("created oidc client", "issuer", client.Issuer())
		s.openidProviders = append(s.openidProviders, client)
	}

	s.Metadata.Issuer = cfg.Issuer
	s.Metadata.ScopesSupported = cfg.ScopesSupported

	// set urls explicitly using the issuer
	s.Metadata.AuthorizationEndpoint = buildURI(s.Metadata.Issuer, s.endpointPaths.Authorization)
	s.Metadata.TokenEndpoint = buildURI(s.Metadata.Issuer, s.endpointPaths.Token)
	s.Metadata.JwksURI = buildURI(s.Metadata.Issuer, s.endpointPaths.Jwks)
	s.Metadata.OpenidProvidersEndpoint = buildURI(s.Metadata.Issuer, s.endpointPaths.OpenIDProviders)
	s.Metadata.NonceEndpoint = buildURI(s.Metadata.Issuer, s.endpointPaths.Nonce)

	// set supported parameters explicitly
	s.Metadata.ResponseTypesSupported = []string{"code"}
	s.Metadata.ResponseModesSupported = []string{"query"}
	s.Metadata.GrantTypesSupported = []string{
		GrantTypeAuthorizationCode,
		GrantTypeRefreshToken,
		GrantTypeClientCredentials,
		GrantTypeJWTBearer,
	}
	s.Metadata.TokenEndpointAuthMethodsSupported = []string{"none", "client_secret_basic"}
	s.Metadata.TokenEndpointAuthSigningAlgValuesSupported = []string{"ES256"}
	s.Metadata.CodeChallengeMethodsSupported = []string{"S256"}

	s.defaultOPIssuer = cfg.DefaultOPIssuer

	// load clients registry
	if len(cfg.Clients) > 0 {
		s.clientsRegistry = &StaticClientsRegistry{Clients: cfg.Clients}
	} else {
		slog.Warn("no OAuth2 clients configured")
	}

	// load signing key
	sigPrK, err := loadJwkFromPem(absPath(cfg.BaseDir, cfg.SignPrivateKeyPath))
	if err != nil {
		slog.Warn("failed to load signing key, will create random", "path", cfg.SignPrivateKeyPath)
		sigPrK, err = GenerateRandomJwk()
		if err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
	}
	s.sigPrK = sigPrK

	// create JWK set
	sigPuK, err := sigPrK.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	s.jwks = jwk.NewSet()
	s.jwks.AddKey(sigPuK)

	// load encryption key
	encPuK, err := loadJwkFromPem(absPath(cfg.BaseDir, cfg.EncPublicKeyPath))
	if err != nil {
		slog.Warn("failed to load encryption key, will create random", "path", cfg.EncPublicKeyPath)
		encPrK, err := GenerateRandomJwk()
		if err != nil {
			return nil, fmt.Errorf("generate encryption key: %w", err)
		}
		encPuK, err = encPrK.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
	}
	s.encPuK = encPuK

	// load clients policy
	if cfg.ClientsPolicyPath != "" {
		filename := absPath(cfg.BaseDir, cfg.ClientsPolicyPath)
		s.clientsPolicy, err = LoadClientsPolicy(filename)
		if err != nil {
			return nil, fmt.Errorf("load clients policy: %w", err)
		}
		slog.Info("loaded clients policy", "path", filename)
	}
	// session store is mock atm
	s.sessionStore = newMockSessionStore()

	// if relying party config is provided, load it
	if cfg.OidfRelyingPartyConfigPath != "" {
		filename := absPath(cfg.BaseDir, cfg.OidfRelyingPartyConfigPath)
		s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfigFile(filename)
		if err != nil {
			return nil, fmt.Errorf("load relying party config: %w", err)
		}
		slog.Info("loaded relying party config", "path", filename)
	} else if cfg.OidfRelyingPartyConfig != nil {
		cfg.OidfRelyingPartyConfig.BaseDir = cfg.BaseDir
		if s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfig(cfg.OidfRelyingPartyConfig); err != nil {
			return nil, fmt.Errorf("create relying party: %w", err)
		}
	}

	// configure gematik IDP-Dienst client if configured
	for _, c := range cfg.GematikIdp {
		client, err := gemidp.NewClientFromConfig(c)
		if err != nil {
			return nil, fmt.Errorf("create gematik IDP-Dienst client: %w", err)
		}
		slog.Info("created gematik IDP-Dienst client", "issuer", client.Issuer())
		s.openidProviders = append(s.openidProviders, client)
	}

	// TODO: configure nonce service
	s.nonceService, err = nonce.NewHashicorpNonceService()
	if err != nil {
		return nil, fmt.Errorf("create nonce service: %w", err)
	}

	// TODO: configure client assertion verification function
	if cfg.VerifyClientAssertionFunc != nil {
		s.verifyClientAssertionFunc = cfg.VerifyClientAssertionFunc
	}

	// TODO: configure DPoP validity period
	s.dpopMaxAge = 5 * time.Minute

	return s, nil
}

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

type Error struct {
	HttpStatus  int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
}

func ErrorHandlerMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil {
			slog.Error("Error", "error", err, "path", c.Path(), "remote_addr", c.RealIP(), "headers", c.Request().Header)

			if authzError, ok := err.(*Error); ok {
				return c.JSON(authzError.HttpStatus, authzError)
			} else if echoErr, ok := err.(*echo.HTTPError); ok {
				return c.JSON(echoErr.Code, &Error{
					HttpStatus:  echoErr.Code,
					Code:        "server_error",
					Description: echoErr.Message.(string),
				})
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

	group.GET(s.endpointPaths.AuthorizationServerMetadata, s.MetadataEndpoint)
	group.GET(s.endpointPaths.Jwks, s.JWKS)
	group.GET(s.endpointPaths.OpenIDProviders, s.OpenidProvidersEndpoint)
	group.GET(s.endpointPaths.Authorization, s.AuthorizationEndpoint)
	group.POST(s.endpointPaths.Par, s.PAREndpoint)
	group.GET(s.endpointPaths.OPCallback, s.OPCallbackEndpoint)
	group.GET(s.endpointPaths.GemIDPCallback, s.OPCallbackEndpoint)
	group.POST(s.endpointPaths.Token, s.TokenEndpoint)
	group.GET(s.endpointPaths.Nonce, s.NonceEndpoint)
	group.HEAD(s.endpointPaths.Nonce, s.NonceEndpoint)

	if s.oidfRelyingParty != nil {
		group.GET(s.endpointPaths.EntityStatement, echo.WrapHandler(http.HandlerFunc(s.oidfRelyingParty.Serve)))
	}
}

func redirectWithError(c echo.Context, redirectUri string, state string, err Error) error {
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
	session := &AuthzServerSession{
		ID:        ksuid.New().String(),
		CreatedAt: time.Now(),
	}
	var responseType string
	var scope string

	binderr := echo.FormFieldBinder(c).
		MustString("response_type", &responseType).
		MustString("client_id", &session.ClientID).
		MustString("redirect_uri", &session.RedirectURI).
		MustString("code_challenge", &session.CodeChallenge).
		MustString("code_challenge_method", &session.CodeChallengeMethod).
		MustString("state", &session.State).
		MustString("scope", &scope).
		String("op_issuer", &session.OPIssuer).
		String("op_intermediary_redirect_uri", &session.OPIntermediaryRedirectURI).
		BindError()

	if binderr != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: binderr.Error(),
		}
	}

	if responseType != "code" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unsupported_response_type",
			Description: fmt.Sprintf("unsupported response_type: %s", responseType),
		}
	}

	if session.OPIssuer == "" {
		session.OPIssuer = s.defaultOPIssuer
	}

	if session.CodeChallengeMethod != "S256" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("unsupported code_challenge_method: %s", session.CodeChallengeMethod),
		}
	}

	if s.clientsRegistry == nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: "clients registry not configured",
		}
	}

	client, err := s.clientsRegistry.GetClientMetadata(session.ClientID)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}

	if !client.IsAllowedRedirectURI(session.RedirectURI) {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "Invalid redirect_uri",
		}
	}

	session.Scopes = strings.Split(scope, " ")
	if !client.IsAllowedScopes(session.Scopes) {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")),
		})
	}

	opClient, err := s.GetOpenidClient(session.OPIssuer)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	opRedirectURI := opClient.RedirectURI()

	if session.OPIntermediaryRedirectURI != "" {
		if !s.clientsPolicy.IsOPIntermediaryRedirectURIAllowed(session.ClientID, session.OPIntermediaryRedirectURI) {
			return redirectWithError(c, session.RedirectURI, session.State, Error{
				Code:        "invalid_request",
				Description: fmt.Sprintf("OP Intermediary Redirect URI not allowed: %s, client: %s", session.OPIntermediaryRedirectURI, session.ClientID),
			})
		}
		opRedirectURI = session.OPIntermediaryRedirectURI
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectURI)
	}

	opSession := &oidc.AuthnClientSession{
		ID:          ksuid.New().String(),
		Issuer:      session.OPIssuer,
		State:       ksuid.New().String(),
		Nonce:       ksuid.New().String(),
		Verifier:    oauth2.GenerateVerifier(),
		RedirectURI: opRedirectURI,
	}

	slog.Info("OP session", "op_session", fmt.Sprintf("%+v", opSession))

	authUrl, err := opClient.AuthenticationURL(
		opSession.State,
		opSession.Nonce,
		opSession.Verifier,
		oidc.WithAlternateRedirectURI(opSession.RedirectURI),
	)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to generate auth url: %w", err).Error(),
		})
	}
	opSession.AuthURL = authUrl

	session.AuthnClientSession = opSession
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	slog.Info("Redirecting to OpenID Provider", "auth_url", authUrl)

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PAREndpoint(c echo.Context) error {
	requestUri := "urn:ietf:params:oauth:request_uri:" + generateNonce(64)
	slog.Error("PAR not implemented", "request_uri", requestUri)
	// TODO: implement PAR
	return &Error{
		HttpStatus:  http.StatusNotImplemented,
		Code:        "unsupported_grant_type",
		Description: "PAR grant type not supported",
	}
}

// GetOpenidClient returns an OpenID Connect client for the given issuer
func (s *Server) GetOpenidClient(issuer string) (oidc.Client, error) {
	for _, op := range s.openidProviders {
		if op.Issuer() == issuer {
			return op, nil
		}
	}

	if s.oidfRelyingParty != nil {
		return s.oidfRelyingParty.NewClient(issuer, buildURI(s.Metadata.Issuer, s.endpointPaths.EntityStatement))
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
		return redirectWithError(c, authnSession.RedirectURI, authnSession.State, Error{
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

	identityIssuer, err := s.GetOpenidClient(authnSession.Issuer)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}

	// exchange code for tokens with the OP
	tokenResponse, err := identityIssuer.ExchangeForIdentity(
		code,
		authnSession.Verifier,
		oidc.WithAlternateRedirectURI(authnSession.RedirectURI),
	)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to exchange code: %w", err).Error(),
		}
	}

	authnSession.TokenResponse = tokenResponse

	if authzSession != nil {
		authzSession.Code = generateNonce(64)

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

	return c.JSON(http.StatusOK, tokenResponse)
}

// TokenEndpoint handles the token request for various grant types
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
		return s.tokenEndpointAuthorizationCode(c)
	case GrantTypeClientCredentials:
		return s.tokenEndpointClientCredentials(c)
	case GrantTypeRefreshToken:
		return s.tokenEndpointRefreshToken(c)
	case GrantTypeJWTBearer:
		return s.tokenEndpointJWTBearer(c)
	default:
		slog.Error("Unsupported grant type", "grant_type", grantType)
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unsupported_grant_type",
			Description: fmt.Sprintf("unsupported grant type: %s", grantType),
		}
	}

}

func (s *Server) verifyClient(c echo.Context) (*ClientMetadata, *Error) {
	formClientId := c.FormValue("client_id")

	if formClientId != "" {
		cm, err := s.clientsRegistry.GetClientMetadata(formClientId)
		if err != nil {
			return nil, &Error{
				HttpStatus:  http.StatusBadRequest,
				Code:        "invalid_client",
				Description: fmt.Errorf("unable to get client metadata: %w", err).Error(),
			}
		}

		if cm.Type == ClientTypeConfidential {
			formClientSecret := c.FormValue("client_secret")
			if formClientSecret == "" {
				return nil, &Error{
					HttpStatus:  http.StatusBadRequest,
					Code:        "invalid_client",
					Description: "missing client_secret",
				}
			}
			return verifyClientSecret(formClientSecret, cm)
		} else {
			// public client
			return cm, nil
		}

	}

	// no client_id in form, try basic auth
	return s.verifyClientCredentialsBasic(c)
}

func (s *Server) verifyClientCredentialsBasic(c echo.Context) (*ClientMetadata, *Error) {
	clientId, clientSecret, ok := c.Request().BasicAuth()
	if !ok {
		return nil, &Error{
			HttpStatus:  http.StatusUnauthorized,
			Code:        "unauthorized_client",
			Description: "missing basic auth",
		}
	}

	client, err := s.clientsRegistry.GetClientMetadata(clientId)
	if err != nil {
		return nil, &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_client",
			Description: err.Error(),
		}
	}

	return verifyClientSecret(clientSecret, client)
}

func verifyClientSecret(clientSecret string, client *ClientMetadata) (*ClientMetadata, *Error) {
	if client.ClientSecretHash == "" && client.Type == ClientTypePublic {
		return nil, &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unauthorized_client",
			Description: "public client must not use client_secret",
		}
	}

	if ok, err := VerifySecretHash(clientSecret, client.ClientSecretHash); !ok {
		if err != nil {
			slog.Error("VerifySecretHash failed", "error", err)
		}

		return nil, &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unauthorized_client",
			Description: "invalid client_secret",
		}
	}

	// client secret is valid
	return client, nil
}

func (s *Server) tokenEndpointClientCredentials(c echo.Context) error {

	client, clientError := s.verifyClient(c)
	if clientError != nil {
		return clientError
	}

	slog.Info("Token request", "client", client)

	scope := c.FormValue("scope")
	if scope == "" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing scope",
		}
	}

	if !client.IsAllowedScope(scope) {
		return &Error{
			HttpStatus:  http.StatusForbidden,
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", scope),
		}
	}

	session := &AuthzServerSession{
		ID:           ksuid.New().String(),
		CreatedAt:    time.Now(),
		ClientID:     client.ClientID,
		Scopes:       strings.Split(scope, " "),
		RefreshCount: -1,
	}

	if err := s.applyPolicyNewSession(client, session); err != nil {
		return err
	}

	response, err := s.refreshTokens(session)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Sprintf("unable to issue access token: %v", err),
		}
	}

	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Sprintf("unable to save session: %v", err),
		}
	}

	return c.JSON(http.StatusOK, response)
}

// TokenEndpointAuthorizationCode handles the token request for the authorization code grant type
func (s *Server) tokenEndpointAuthorizationCode(c echo.Context) error {
	client, clientError := s.verifyClient(c)
	if clientError != nil {
		return clientError
	}

	var code string
	var codeVerifier string
	var redirectUri string
	binderr := echo.FormFieldBinder(c).
		MustString("code", &code).
		MustString("code_verifier", &codeVerifier).
		MustString("redirect_uri", &redirectUri).
		BindError()

	if binderr != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: binderr.Error(),
		}
	}

	slog.Info("Token request", "code", code, "redirect_uri", redirectUri, "client_id", client.ClientID)

	session, err := s.sessionStore.GetAuthzServerSessionByCode(code)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Errorf("unable to get session: %w", err).Error(),
		}
	}

	slog.Info("Token request: session", "session", fmt.Sprintf("%+v", session))

	if session.ClientID != client.ClientID {
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
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	if err := s.applyPolicyNewSession(client, session); err != nil {
		return err
	}

	response, err := s.refreshTokens(session)

	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		})
	}

	slog.Info("Token request: tokens issued", "response", fmt.Sprintf("%+v", response))

	return c.JSON(http.StatusOK, response)
}

func (s *Server) tokenEndpointJWTBearer(c echo.Context) error {
	if s.verifyClientAssertionFunc == nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "bad_request",
			Description: "JWT Bearer grant type not configured",
		}
	}
	r := c.Request()

	assertion, ok := r.Form["assertion"]
	if !ok {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing assertion parameter",
		}
	}

	claims, err := s.verifyClientAssertionFunc(assertion[0])
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusUnauthorized,
			Code:        "bad_request",
			Description: fmt.Sprintf("failed to verify assertion: %v", err),
		}
	}

	slog.Info("Token request", "claims", claims)

	if err := claims.Validate(); err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "bad_request",
			Description: fmt.Sprintf("invalid assertion claims: %v", err),
		}
	}

	// redeem nonce
	err = s.nonceService.Redeem(claims.Nonce)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("invalid nonce: %v", err),
		}
	}

	dpopToken, dpoppErr := dpop.ParseRequest(r, dpop.ParseOptions{
		MaxAge:        s.dpopMaxAge,
		NonceRequired: true,
	})
	if dpoppErr != nil {
		return &Error{
			HttpStatus:  dpoppErr.HttpStatus,
			Code:        dpoppErr.Code,
			Description: dpoppErr.Description,
		}
	}
	slog.Info("DPoP token", "dpop", fmt.Sprintf("%+v", dpopToken), "raw", r.Header.Get("DPoP"))

	if dpopToken.Nonce != claims.Nonce {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "nonce mismatch",
		}
	}

	if dpopToken.KeyThumbprint != "" && dpopToken.KeyThumbprint != claims.Cnf.Jkt {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "key thumbprint mismatch",
		}
	}

	return &Error{
		HttpStatus:  http.StatusUnauthorized,
		Code:        "not_implemented",
		Description: "JWT Bearer grant type not implemented",
	}

}

func (s *Server) tokenEndpointRefreshToken(c echo.Context) error {
	client, clientError := s.verifyClient(c)
	if clientError != nil {
		return clientError
	}

	refreshToken := c.FormValue("refresh_token")
	if refreshToken == "" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing refresh_token",
		}
	}

	slog.Info("Token request", "client", client, "refresh_token", refreshToken)

	return c.JSON(http.StatusUnauthorized, nil)
}

func (s *Server) refreshTokens(session *AuthzServerSession) (*TokenResponse, error) {
	accessJwt := jwt.New()
	accessJwt.Set("jti", session.ID)
	if session.Audience != nil {
		accessJwt.Set("aud", session.Audience)
	}
	accessJwt.Set("iat", time.Now().Unix())
	exp := time.Now().Add(session.AccessTokenDuration)
	if session.ExpiresAt.Before(exp) {
		exp = session.ExpiresAt
	}
	accessJwt.Set("exp", exp.Unix())
	if session.Scopes != nil {
		accessJwt.Set("scope", strings.Join(session.Scopes, " "))
	}

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, s.sigPrK))
	if err != nil {
		return nil, fmt.Errorf("unable to sign access token: %w", err)
	}

	session.RefreshToken = generateNonce(64)
	session.RefreshCount++

	return &TokenResponse{
		AccessToken:      string(accessTokenBytes),
		TokenType:        "Bearer",
		ExpiresIn:        int(time.Until(exp).Seconds()),
		Scope:            strings.Join(session.Scopes, " "),
		RefreshToken:     session.RefreshToken,
		RefreshExpiresIn: int(time.Until(session.ExpiresAt).Seconds()),
	}, nil
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
func (s *Server) OpenidProviders() ([]OpenidProviderInfo, error) {
	providers := make([]OpenidProviderInfo, 0, len(s.openidProviders))
	for _, op := range s.openidProviders {
		info := OpenidProviderInfo{
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
			providers = append(providers, OpenidProviderInfo{
				Issuer:  op.Issuer,
				LogoURI: op.LogoURI,
				Name:    op.OrganizationName,
				Type:    "oidf",
			})
		}
	}

	return providers, nil
}

func loadJwkFromPem(path string) (jwk.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return jwk.ParseKey(data, jwk.WithPEM(true))
}

// OpenidProviderInfo represents the information about an OpenID Provider
type OpenidProviderInfo struct {
	Issuer  string `json:"iss"`
	LogoURI string `json:"logo_uri"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

func (s *Server) applyPolicyNewSession(client *ClientMetadata, session *AuthzServerSession) *Error {
	if !client.IsAllowedScopes(session.Scopes) {
		return &Error{
			HttpStatus:  http.StatusForbidden,
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")),
		}
	}
	session.AccessTokenDuration = 60 * time.Second
	session.ExpiresAt = session.CreatedAt.Add(10 * time.Minute)
	return nil
}

// generateNonce generates a cryptographically secure random nonce of the given size.
func generateNonce(size int) string {
	// Create a byte slice of the desired size
	nonceBytes := make([]byte, size)

	// Read random bytes into the slice
	_, err := rand.Read(nonceBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Encode the bytes into a base64 string without padding (URL-safe)
	nonce := base64.RawURLEncoding.WithPadding(base64.NoPadding).EncodeToString(nonceBytes)

	return nonce
}

func buildURI(base string, paths ...string) string {
	result := strings.TrimRight(base, "/")
	for _, p := range paths {
		if p == "" {
			continue
		}
		result = fmt.Sprintf("%s/%s", result, strings.Trim(p, "/"))
	}
	return result
}

type NonceType struct {
	Nonce string `json:"nonce"`
}

func (s *Server) NonceEndpoint(c echo.Context) error {
	nonce, err := s.nonceService.Get()
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Sprintf("unable to get nonce: %v", err),
		}
	}
	if c.Request().Method == http.MethodHead {
		c.Response().Header().Set("Replay-Nonce", nonce)
		return c.NoContent(http.StatusOK)
	} else {
		return c.JSON(http.StatusOK, NonceType{Nonce: nonce})
	}
}
