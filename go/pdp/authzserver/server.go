package authzserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/segmentio/ksuid"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type Server struct {
	Metadata                  ExtendedMetadata
	nonProdMode               bool
	endpointPaths             *EndpointsConfig
	clientsRegistry           ClientsRegistry
	openidProviders           []oidc.Client
	oidfRelyingParty          *oidf.RelyingParty
	defaultOPIssuer           string
	clientsPolicy             *ClientsPolicy
	sessionStore              AuthzServerSessionStore
	sigPrK                    jwk.Key
	jwks                      jwk.Set
	nonceService              nonce.Service
	verifyClientAssertionFunc VerifyClientAssertionFunc
	dpopMaxAge                time.Duration
	valkey                    valkey.Client
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
		nonProdMode:     cfg.NonProdMode,
	}

	if s.nonProdMode {
		slog.Warn("Authorization server is running in non-production mode")
	}

	if cfg.ValkeyConfig != nil {
		valkeyClientOption := valkey.ClientOption{
			InitAddress: []string{fmt.Sprintf("%s:%d", cfg.ValkeyConfig.Host, cfg.ValkeyConfig.Port)},
		}
		if cfg.ValkeyConfig.Username != "" {
			valkeyClientOption.Username = cfg.ValkeyConfig.Username
		}

		if cfg.ValkeyConfig.UseTLS {
			valkeyClientOption.TLSConfig = &tls.Config{}
		}

		var err error
		if s.valkey, err = valkey.NewClient(valkeyClientOption); err != nil {
			return nil, fmt.Errorf("create valkey client: %w", err)
		}

	}
	issuerUrl, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer URI: %w", err)
	}

	s.endpointPaths = &cfg.Endpoints
	s.endpointPaths.applyDefaults(issuerUrl)

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
	s.Metadata.AuthorizationEndpoint = buildURI(issuerUrl, s.endpointPaths.Authorization)
	s.Metadata.TokenEndpoint = buildURI(issuerUrl, s.endpointPaths.Token)
	s.Metadata.JwksURI = buildURI(issuerUrl, s.endpointPaths.Jwks)
	s.Metadata.OpenidProvidersEndpoint = buildURI(issuerUrl, s.endpointPaths.OpenIDProviders)
	s.Metadata.NonceEndpoint = buildURI(issuerUrl, s.endpointPaths.Nonce)
	s.Metadata.PushedAuthorizationRequestEndpoint = buildURI(issuerUrl, s.endpointPaths.PushedAuthorizationRequest)
	s.Metadata.RegistrationEndpoint = buildURI(issuerUrl, s.endpointPaths.Registration)

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
	sigPrK, err := func(filename string) (jwk.Key, error) {
		bytes, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read signing key file '%s': %w", filename, err)
		}
		return jwk.ParseKey(bytes)
	}(absPath(cfg.BaseDir, cfg.SignJwkPath))
	if err != nil {
		slog.Warn("failed to load signing key, will create random", "path", cfg.SignJwkPath, "error", err)
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

// MountRoutes registers the authorization server routes on the given ServeMux. Each handler
// is wrapped by s.handle, which renders returned errors as OAuth JSON (RFC 6749 §5.2).
func (s *Server) MountRoutes(mux *http.ServeMux) {
	routes := []struct {
		method  string
		path    string
		handler handlerFunc
	}{
		{http.MethodGet, s.endpointPaths.AuthorizationServerMetadata, s.MetadataEndpoint},
		{http.MethodGet, s.endpointPaths.Jwks, s.JWKS},
		{http.MethodGet, s.endpointPaths.OpenIDProviders, s.OpenidProvidersEndpoint},
		{http.MethodGet, s.endpointPaths.Authorization, s.AuthorizationEndpoint},
		{http.MethodPost, s.endpointPaths.PushedAuthorizationRequest, s.PAREndpoint},
		{http.MethodGet, s.endpointPaths.OPCallback, s.OPCallbackEndpoint},
		{http.MethodGet, s.endpointPaths.GemIDPCallback, s.OPCallbackEndpoint},
		{http.MethodPost, s.endpointPaths.Token, s.TokenEndpoint},
		{http.MethodGet, s.endpointPaths.Nonce, s.NonceEndpoint},
		{http.MethodHead, s.endpointPaths.Nonce, s.NonceEndpoint},
		{http.MethodPost, s.endpointPaths.Registration, s.RegistrationEndpoint},
	}
	for _, rt := range routes {
		mux.Handle(rt.method+" "+rt.path, s.handle(rt.handler))
		slog.Info("registered route", "method", rt.method, "path", rt.path)
	}

	if s.oidfRelyingParty != nil {
		mux.Handle(http.MethodGet+" "+s.endpointPaths.EntityStatement, http.HandlerFunc(s.oidfRelyingParty.Serve))
		slog.Info("registered route", "method", http.MethodGet, "path", s.endpointPaths.EntityStatement)
	}
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectUri string, state string, err Error) error {
	params := url.Values{}
	if state != "" {
		params.Add("state", state)
	}
	params.Add("error", err.Code)
	params.Add("error_description", err.Description)

	http.Redirect(w, r, redirectUri+"?"+params.Encode(), http.StatusFound)
	return nil
}

func (s *Server) MetadataEndpoint(w http.ResponseWriter, r *http.Request) error {
	return writeJSON(w, http.StatusOK, s.Metadata)
}

func (s *Server) AuthorizationEndpoint(w http.ResponseWriter, r *http.Request) error {
	session := &AuthzServerSession{
		ID:        ksuid.New().String(),
		CreatedAt: time.Now(),
	}
	var responseType string
	var scope string

	binderr := newFormBinder(r).
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
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")),
		})
	}

	opClient, err := s.GetOpenidClient(session.OPIssuer)
	if err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	opRedirectURI := opClient.RedirectURI()

	if session.OPIntermediaryRedirectURI != "" {
		if !s.clientsPolicy.IsOPIntermediaryRedirectURIAllowed(session.ClientID, session.OPIntermediaryRedirectURI) {
			return redirectWithError(w, r, session.RedirectURI, session.State, Error{
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
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to generate auth url: %w", err).Error(),
		})
	}
	opSession.AuthURL = authUrl

	session.AuthnClientSession = opSession
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to save session: %w", err).Error(),
		})
	}

	slog.Info("Redirecting to OpenID Provider", "auth_url", authUrl)

	http.Redirect(w, r, authUrl, http.StatusFound)
	return nil
}

func (s *Server) PAREndpoint(w http.ResponseWriter, r *http.Request) error {
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
		return s.oidfRelyingParty.NewClient(issuer)
	}
	return nil, fmt.Errorf("unknown issuer: %s", issuer)
}

// OPCallbackEndpoint handles the callback from the OpenID Provider
func (s *Server) OPCallbackEndpoint(w http.ResponseWriter, r *http.Request) error {
	query := r.URL.Query()
	// retrieve state from query
	state := query.Get("state")
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

	if query.Get("error") != "" {
		slog.Error("OP callback error", "query", r.URL.RawQuery)
		return redirectWithError(w, r, authnSession.RedirectURI, authnSession.State, Error{
			Code:        query.Get("error"),
			Description: query.Get("error_description"),
		})
	}

	// retrieve PKCE code from query
	code := query.Get("code")
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

		http.Redirect(w, r, authzSession.RedirectURI+"?"+params.Encode(), http.StatusFound)
		return nil
	}

	return writeJSON(w, http.StatusOK, tokenResponse)
}

// TokenEndpoint handles the token request for various grant types
func (s *Server) TokenEndpoint(w http.ResponseWriter, r *http.Request) error {
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
		return s.tokenEndpointAuthorizationCode(w, r)
	case GrantTypeClientCredentials:
		return s.tokenEndpointClientCredentials(w, r)
	case GrantTypeRefreshToken:
		return s.tokenEndpointRefreshToken(w, r)
	case GrantTypeJWTBearer:
		return s.tokenEndpointJWTBearer(w, r)
	default:
		slog.Error("Unsupported grant type", "grant_type", grantType)
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "unsupported_grant_type",
			Description: fmt.Sprintf("unsupported grant type: %s", grantType),
		}
	}

}

func (s *Server) verifyClient(r *http.Request) (*ClientMetadata, *Error) {
	formClientId := r.FormValue("client_id")

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
			formClientSecret := r.FormValue("client_secret")
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
	return s.verifyClientCredentialsBasic(r)
}

func (s *Server) verifyClientCredentialsBasic(r *http.Request) (*ClientMetadata, *Error) {
	clientId, clientSecret, ok := r.BasicAuth()
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

func (s *Server) tokenEndpointClientCredentials(w http.ResponseWriter, r *http.Request) error {

	client, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	slog.Info("Token request", "client", client)

	scope := r.FormValue("scope")
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

	response, err := s.issueOrRefreshTokens(session)
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

	return writeJSON(w, http.StatusOK, response)
}

// tokenEndpointAuthorizationCode handles the token request for the authorization code grant type
func (s *Server) tokenEndpointAuthorizationCode(w http.ResponseWriter, r *http.Request) error {
	client, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	var code string
	var codeVerifier string
	var redirectUri string
	binderr := newFormBinder(r).
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
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	if err := s.applyPolicyNewSession(client, session); err != nil {
		return err
	}

	response, err := s.issueOrRefreshTokens(session)

	if err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		})
	}

	slog.Info("Token request: tokens issued", "response", fmt.Sprintf("%+v", response))

	return writeJSON(w, http.StatusOK, response)
}

func (s *Server) tokenEndpointJWTBearer(w http.ResponseWriter, r *http.Request) error {
	if s.verifyClientAssertionFunc == nil {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "bad_request",
			Description: "JWT Bearer grant type not configured",
		}
	}

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

	dpopBinding, dpoppErr := dpop.ParseRequest(r, dpop.ParseOptions{
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
	slog.Info("DPoP token", "dpop", fmt.Sprintf("%+v", dpopBinding), "raw", r.Header.Get("DPoP"))

	if dpopBinding.DPoP.Nonce != claims.Nonce {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "nonce mismatch",
		}
	}

	if dpopBinding.DPoP.KeyThumbprint != "" && dpopBinding.DPoP.KeyThumbprint != claims.Cnf.Jkt {
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

func (s *Server) tokenEndpointRefreshToken(w http.ResponseWriter, r *http.Request) error {
	client, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return &Error{
			HttpStatus:  http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "missing refresh_token",
		}
	}

	slog.Info("Token request", "client", client, "refresh_token", refreshToken)

	return writeJSON(w, http.StatusUnauthorized, nil)
}

func (s *Server) issueOrRefreshTokens(session *AuthzServerSession) (*TokenResponse, error) {
	var tokenType string
	if session.DPoPThumbprint != "" {
		tokenType = "DPoP"
	} else {
		tokenType = "Bearer"
	}

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
	accessJwt.Set("client_id", session.ClientID)
	// TODO: set proper subject
	accessJwt.Set("sub", session.ClientID)

	accessJwt.Set("exp", exp.Unix())
	if len(session.Scopes) > 0 {
		accessJwt.Set("scope", strings.Join(session.Scopes, " "))
	}

	if session.DPoPThumbprint != "" {
		accessJwt.Set("cnf", map[string]interface{}{
			"jkt": session.DPoPThumbprint,
		})
	}

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256, s.sigPrK))
	if err != nil {
		return nil, fmt.Errorf("unable to sign access token: %w", err)
	}

	session.RefreshToken = generateNonce(64)
	session.RefreshCount++

	return &TokenResponse{
		AccessToken:      string(accessTokenBytes),
		TokenType:        tokenType,
		ExpiresIn:        int(time.Until(exp).Seconds()),
		Scope:            strings.Join(session.Scopes, " "),
		RefreshToken:     session.RefreshToken,
		RefreshExpiresIn: int(time.Until(session.ExpiresAt).Seconds()),
	}, nil
}

// JWKS serves the JSON Web Key Set for the server
func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) error {
	return writeJSON(w, http.StatusOK, s.jwks)
}

// OpenidProvidersEndpoint serves the list of OpenID Providers supported by the server
func (s *Server) OpenidProvidersEndpoint(w http.ResponseWriter, r *http.Request) error {
	providers, err := s.OpenidProviders()
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: err.Error(),
		}
	}
	return writeJSON(w, http.StatusOK, providers)
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

func buildURI(baseURL *url.URL, path string) string {
	result := *baseURL
	result.Path = path
	return result.String()
}

type NonceType struct {
	Nonce string `json:"nonce"`
}

func (s *Server) NonceEndpoint(w http.ResponseWriter, r *http.Request) error {
	nonce, err := s.nonceService.Get()
	if err != nil {
		return &Error{
			HttpStatus:  http.StatusInternalServerError,
			Code:        "server_error",
			Description: fmt.Sprintf("unable to get nonce: %v", err),
		}
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Replay-Nonce", nonce)
		w.WriteHeader(http.StatusOK)
		return nil
	}
	return writeJSON(w, http.StatusOK, NonceType{Nonce: nonce})
}
