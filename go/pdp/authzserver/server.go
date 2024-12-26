package authzserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gemidp"
	"github.com/gematik/zero-lab/go/oauth"
	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/gematik/zero-lab/go/oauth/oidf"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
	"gopkg.in/yaml.v3"
)

type Server struct {
	Metadata         ExtendedMetadata
	clientsRegistry  ClientsRegistry
	openidProviders  []oidc.Client
	oidfRelyingParty *oidf.RelyingParty
	defaultOPIssuer  string
	clientsPolicy    *ClientsPolicy
	sessionStore     AuthzServerSessionStore
	sigPrK           jwk.Key
	jwks             jwk.Set
	encPuK           jwk.Key
}

type Config struct {
	BaseDir                string                   `yaml:"-"`
	Issuer                 string                   `yaml:"issuer" validate:"required"`
	SignPrivateKeyPath     string                   `yaml:"sign_private_key_path"`
	EncPublicKeyPath       string                   `yaml:"enc_public_key_path"`
	ScopesSupported        []string                 `yaml:"scopes_supported"`
	MetadataTemplate       ExtendedMetadata         `yaml:"metadata_template"`
	DefaultOPIssuer        string                   `yaml:"default_op_issuer"`
	OidcProviders          []oidc.Config            `yaml:"oidc_providers" validate:"dive"`
	GematikIdp             []gemidp.ClientConfig    `yaml:"gematik_idp" validate:"dive"`
	ClientsPolicyPath      string                   `yaml:"clients_policy_path"`
	Clients                []ClientMetadata         `yaml:"clients" validate:"omitempty,dive"`
	OidfRelyingPartyPath   string                   `yaml:"oidf_relying_party_path"`
	OidfRelyingPartyConfig *oidf.RelyingPartyConfig `yaml:"oidf_relying_party" validate:"omitempty"`
}

func absPath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
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
	s.Metadata.AuthorizationEndpoint = fmt.Sprint(s.Metadata.Issuer, "/auth")
	s.Metadata.TokenEndpoint = fmt.Sprint(s.Metadata.Issuer, "/token")
	s.Metadata.JwksURI = fmt.Sprint(s.Metadata.Issuer, "/jwks")
	s.Metadata.OpenidProvidersEndpoint = fmt.Sprint(s.Metadata.Issuer, "/openid-providers")

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
		return nil, fmt.Errorf("no clients configured")
	}

	// load signing key
	sigPrK, err := loadJwkFromPem(absPath(cfg.BaseDir, cfg.SignPrivateKeyPath))
	if err != nil {
		slog.Warn("failed to load signing key, will create random", "path", cfg.SignPrivateKeyPath)
		sigPrK, err = generateRandomJWK()
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
		encPrK, err := generateRandomJWK()
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
	if cfg.OidfRelyingPartyPath != "" {
		filename := absPath(cfg.BaseDir, cfg.OidfRelyingPartyPath)
		s.oidfRelyingParty, err = oidf.NewRelyingPartyFromConfigFile(filename)
		if err != nil {
			return nil, fmt.Errorf("load relying party config: %w", err)
		}
		slog.Info("loaded relying party config", "path", filename)
	} else if cfg.OidfRelyingPartyConfig != nil {
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

// OAuth2 Authorization Server Metadata
// See https://datatracker.ietf.org/doc/html/rfc8414
type Metadata struct {
	Issuer                                             string   `json:"issuer" yaml:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint" yaml:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint" yaml:"token_endpoint"`
	JwksURI                                            string   `json:"jwks_uri,omitempty" yaml:"jwks_uri"`
	RegistrationEndpoint                               string   `json:"registration_endpoint,omitempty" yaml:"registration_endpoint"`
	ScopesSupported                                    []string `json:"scopes_supported" yaml:"scopes_supported"`
	ResponseTypesSupported                             []string `json:"response_types_supported" yaml:"response_types_supported"`
	ResponseModesSupported                             []string `json:"response_modes_supported" yaml:"response_modes_supported"`
	GrantTypesSupported                                []string `json:"grant_types_supported" yaml:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported" yaml:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported" yaml:"token_endpoint_auth_signing_alg_values_supported"`
	ServiceDocumentation                               string   `json:"service_documentation,omitempty" yaml:"service_documentation"`
	UILocalesSupported                                 []string `json:"ui_locales_supported,omitempty" yaml:"ui_locales_supported"`
	OPPolicyURI                                        string   `json:"op_policy_uri,omitempty" yaml:"op_policy_uri"`
	OPTosURI                                           string   `json:"op_tos_uri,omitempty" yaml:"op_tos_uri"`
	RevocationEndpoint                                 string   `json:"revocation_endpoint,omitempty" yaml:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty" yaml:"revocation_endpoint_auth_methods_supported"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty" yaml:"revocation_endpoint_auth_signing_alg_values_supported"`
	IntrospectionEndpoint                              string   `json:"introspection_endpoint,omitempty" yaml:"introspection_endpoint"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty" yaml:"introspection_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty" yaml:"introspection_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported" yaml:"code_challenge_methods_supported"`
}

// Extend the standard OAuth2 server metadata from RFC8414
type ExtendedMetadata struct {
	Metadata
	OpenidProvidersEndpoint string `json:"openid_providers_endpoint"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
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

// TODO: make paths configurable
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
	var session AuthzServerSession
	session.ID = ksuid.New().String()

	binderr := echo.FormFieldBinder(c).
		MustString("response_type", &session.ResponseType).
		MustString("client_id", &session.ClientID).
		MustString("redirect_uri", &session.RedirectURI).
		MustString("code_challenge", &session.CodeChallenge).
		MustString("code_challenge_method", &session.CodeChallengeMethod).
		MustString("nonce", &session.Nonce).
		MustString("state", &session.State).
		MustString("scope", &session.Scope).
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

	clientMetadata, err := s.clientsRegistry.GetClientMetadata(session.ClientID)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}

	if !clientMetadata.AllowedScope(session.Scope) {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", session.Scope),
		})
	}

	opClient, err := s.OpenidProvider(session.OPIssuer)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	if !clientMetadata.AllowedRedirectURI(session.RedirectURI) {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "redirect_uri forbidden by policy",
		})
	}

	if session.OPIntermediaryRedirectURI != "" {
		if !s.clientsPolicy.AllowedOPIntermediaryURL(session.ClientID, session.OPIntermediaryRedirectURI) {
			return redirectWithError(c, session.RedirectURI, session.State, Error{
				Code:        "invalid_request",
				Description: "op_indermediary_redirect_uri forbidden by policy",
			})
		}
		slog.Info("OP Intermediary Redirect URI is set", "op_intermediary_redirect_uri", session.OPIntermediaryRedirectURI)
	}

	opRedirectURI := opClient.RedirectURI()

	slog.Info("OP redirect URI", "redirect_uri", opRedirectURI)

	opSession := &oidc.AuthnClientSession{
		ID:          ksuid.New().String(),
		Issuer:      session.OPIssuer,
		State:       ksuid.New().String(),
		Nonce:       session.Nonce,
		Verifier:    oauth.GenerateVerifier(),
		RedirectURI: opRedirectURI,
	}

	slog.Info("OP session", "redirect_uri", opSession.RedirectURI)

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
	if err := s.sessionStore.SaveAutzhServerSession(&session); err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	slog.Info("Redirecting to OP", "auth_url", authUrl)

	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PAREndpoint(c echo.Context) error {
	requestUri := "urn:ietf:params:oauth:request_uri:" + generateRandomString(128)
	slog.Error("PAR not implemented", "request_uri", requestUri)
	// TODO: implement PAR
	return &Error{
		HttpStatus:  http.StatusNotImplemented,
		Code:        "unsupported_grant_type",
		Description: "PAR grant type not supported",
	}
}

// OpenidProvider returns an OpenID Connect client for the given issuer
func (s *Server) OpenidProvider(issuer string) (oidc.Client, error) {
	for _, op := range s.openidProviders {
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

	identityIssuer, err := s.OpenidProvider(authnSession.Issuer)
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

	authnSession.Claims = make(map[string]any)

	if err := tokenResponse.Claims(&authnSession.Claims); err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to parse claims: %w", err).Error(),
		}
	}

	authnSession.TokenResponse = tokenResponse

	if authzSession != nil {
		authzSession.Code = generateRandomString(128)

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

func (s *Server) verifyClientCredentials(c echo.Context) (*ClientMetadata, error) {
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

	if ok, err := VerifySecretHash(clientSecret, client.ClientSecretHash); !ok {
		if err != nil {
			slog.Error("VerifySecretHash failed", "error", err)
		}

		return nil, &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_client",
			Description: "invalid client_secret",
		}
	}

	return client, nil
}

func (s *Server) TokenEndpointClientCredentials(c echo.Context) error {

	client, err := s.verifyClientCredentials(c)
	if err != nil {
		return err
	}

	slog.Info("Token request", "client", client)

	session := &AuthzServerSession{
		ID:       ksuid.New().String(),
		ClientID: client.ClientID,
		Duration: 1 * time.Hour,
		Scope:    c.FormValue("scope"),
	}

	if err = s.applyPolicy(client, session); err != nil {
		return &Error{
			HttpStatus:  http.StatusForbidden,
			Code:        "access_denied",
			Description: fmt.Errorf("unable to apply policy: %w", err).Error(),
		}
	}

	accessToken, err := s.issueAccessToken(session)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		}
	}

	return c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(session.Duration.Seconds()),
		RefreshToken: "",
	})
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

	clientMetadata, err := s.clientsRegistry.GetClientMetadata(clientId)
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "server_error",
			Description: fmt.Errorf("unable to get client metadata: %w", err).Error(),
		}
	}

	if clientMetadata.Type == ClientTypeConfidential {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "client_secret required",
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
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	accessToken, err := s.issueAccessToken(session)
	if err != nil {
		return redirectWithError(c, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		})
	}

	slog.Info("Token request: access token issued", "access_token", accessToken)

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(session.Duration.Seconds()),
		RefreshToken: "",
	}

	return c.JSON(http.StatusOK, response)
}

// issueAccessToken issues an access token for the given authorization session
// upon successful authentication with the OpenID Provider and authorization
func (s *Server) issueAccessToken(authzSession *AuthzServerSession) (string, error) {
	accessJwt := jwt.New()
	accessJwt.Set("jti", authzSession.ID)
	accessJwt.Set("aud", []string{"TODO"})
	accessJwt.Set("iat", time.Now().Unix())
	accessJwt.Set("exp", time.Now().Add(authzSession.Duration).Unix())
	if authzSession.Scope != "" {
		accessJwt.Set("scope", authzSession.Scope)
	}
	if authzSession.AuthnClientSession != nil && authzSession.AuthnClientSession.Claims != nil {
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

func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic("Random number generation failed")
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func generateRandomJWK() (jwk.Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create jwk from key: %w", err)
	}
	return jwkKey, nil
}

func (s *Server) applyPolicy(client *ClientMetadata, autzSession *AuthzServerSession) error {
	if autzSession.Scope == "" {
		slog.Warn("No scope requested")
	} else {
		scopes := strings.Split(autzSession.Scope, " ")
		slog.Info("Requested scopes", "scopes", scopes)
		for _, scope := range scopes {
			if !client.AllowedScope(scope) {
				return fmt.Errorf("scope %s not allowed by policy", scope)
			}
		}
	}
	return nil
}
