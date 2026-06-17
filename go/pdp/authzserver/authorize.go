package authzserver

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
	"github.com/segmentio/ksuid"
	"golang.org/x/oauth2"
)

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

// AuthorizationEndpoint validates an OAuth2 authorization-code request and starts the
// upstream OpenID Provider login.
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
		return oauthErr(http.StatusBadRequest, "invalid_request", binderr.Error())
	}

	if responseType != "code" {
		return oauthErr(http.StatusBadRequest, "unsupported_response_type", fmt.Sprintf("unsupported response_type: %s", responseType))
	}

	if session.OPIssuer == "" {
		session.OPIssuer = s.defaultOPIssuer
	}

	if session.CodeChallengeMethod != "S256" {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("unsupported code_challenge_method: %s", session.CodeChallengeMethod))
	}

	if s.clientsRegistry == nil {
		return oauthErr(http.StatusInternalServerError, "server_error", "clients registry not configured")
	}

	client, err := s.clientsRegistry.GetClientMetadata(session.ClientID)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", err.Error())
	}

	if !client.IsAllowedRedirectURI(session.RedirectURI) {
		return oauthErr(http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
	}

	session.Scopes = strings.Split(scope, " ")
	if !client.IsAllowedScopes(session.Scopes) {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")),
		})
	}

	return s.startOpenidProviderLogin(w, r, session)
}

// startOpenidProviderLogin resolves the upstream OP, creates the authentication session and
// redirects the user-agent to the provider. On error it redirects back to the client with an
// OAuth error.
func (s *Server) startOpenidProviderLogin(w http.ResponseWriter, r *http.Request, session *AuthzServerSession) error {
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
	return oauthErr(http.StatusNotImplemented, "unsupported_grant_type", "PAR grant type not supported")
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
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing state")
	}

	// find running session by the OP state
	var authnSession *oidc.AuthnClientSession
	authzSession, err := s.sessionStore.GetAuthzServerSessionByAuthnState(state)
	if err == nil {
		authnSession = authzSession.AuthnClientSession
		if authnSession == nil {
			return oauthErr(http.StatusBadRequest, "invalid_request", "missing openid session")
		}
	} else {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Errorf("unable to get session: %w", err).Error())
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
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing code")
	}

	slog.Info("OP callback", "s", s, "authnSessiom", authnSession, "authzSession", authzSession)

	identityIssuer, err := s.GetOpenidClient(authnSession.Issuer)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", err.Error())
	}

	// exchange code for tokens with the OP
	tokenResponse, err := identityIssuer.ExchangeForIdentity(
		code,
		authnSession.Verifier,
		oidc.WithAlternateRedirectURI(authnSession.RedirectURI),
	)
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Errorf("unable to exchange code: %w", err).Error())
	}

	authnSession.TokenResponse = tokenResponse

	if authzSession != nil {
		authzSession.Code = generateNonce(64)

		if err := s.sessionStore.SaveAutzhServerSession(authzSession); err != nil {
			return oauthErr(http.StatusInternalServerError, "server_error", fmt.Errorf("unable to save session: %w", err).Error())
		}

		params := url.Values{}
		params.Set("code", authzSession.Code)
		params.Set("state", authzSession.State)

		http.Redirect(w, r, authzSession.RedirectURI+"?"+params.Encode(), http.StatusFound)
		return nil
	}

	return writeJSON(w, http.StatusOK, tokenResponse)
}
