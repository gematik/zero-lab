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
// bindAuthzRequest parses + validates an authorization request — from the /authorize query OR a /par body —
// into a pending session and resolves its product. Shared so direct authorization and PAR enforce identical
// policy. The scope-allowlist check is left to the caller (it redirects at /authorize, returns JSON at /par).
func (s *Server) bindAuthzRequest(r *http.Request) (*AuthzServerSession, *Product, *Error) {
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
		String("idp_iss", &session.IDPIss).
		BindError()
	if binderr != nil {
		return nil, nil, oauthErr(http.StatusBadRequest, "invalid_request", binderr.Error())
	}
	if responseType != "code" {
		return nil, nil, oauthErr(http.StatusBadRequest, "unsupported_response_type", fmt.Sprintf("unsupported response_type: %s", responseType))
	}
	if session.IDPIss == "" {
		session.IDPIss = s.defaultIDPIss
	}
	if session.CodeChallengeMethod != "S256" {
		return nil, nil, oauthErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("unsupported code_challenge_method: %s", session.CodeChallengeMethod))
	}
	if cerr := validateCodeChallenge(session.CodeChallenge); cerr != nil {
		return nil, nil, cerr
	}
	if s.clientsRegistry == nil {
		return nil, nil, oauthErr(http.StatusInternalServerError, "server_error", "clients registry not configured")
	}
	client, err := s.clientsRegistry.GetClient(session.ClientID)
	if err != nil {
		return nil, nil, oauthErr(http.StatusBadRequest, "invalid_request", err.Error())
	}
	product, productErr := s.clientProduct(client)
	if productErr != nil {
		return nil, nil, productErr
	}
	if !product.IsAllowedRedirectURI(session.RedirectURI) {
		return nil, nil, oauthErr(http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
	}
	session.Scopes = strings.Split(scope, " ")
	return session, product, nil
}

func (s *Server) AuthorizationEndpoint(w http.ResponseWriter, r *http.Request) error {
	if requestURI := r.FormValue("request_uri"); requestURI != "" {
		// PAR (RFC 9126): the request was validated + client-authenticated at /par. Load it single-use
		// (the index is consumed); the rest of the query is ignored.
		session, err := s.sessionStore.GetAutzhServerSessionByRequestURI(requestURI)
		if err != nil {
			return oauthErr(http.StatusBadRequest, "invalid_request", "invalid or expired request_uri")
		}
		client, cerr := s.clientsRegistry.GetClient(session.ClientID)
		if cerr != nil {
			return oauthErr(http.StatusBadRequest, "invalid_request", cerr.Error())
		}
		product, perr := s.clientProduct(client)
		if perr != nil {
			return perr
		}
		return s.startOpenidProviderLogin(w, r, session, product)
	}

	session, product, perr := s.bindAuthzRequest(r)
	if perr != nil {
		return perr
	}
	if !product.IsAllowedScopes(session.Scopes) {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_scope",
			Description: fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")),
		})
	}
	return s.startOpenidProviderLogin(w, r, session, product)
}

// startOpenidProviderLogin resolves the upstream OP, creates the authentication session and
// redirects the user-agent to the provider. On error it redirects back to the client with an
// OAuth error.
func (s *Server) startOpenidProviderLogin(w http.ResponseWriter, r *http.Request, session *AuthzServerSession, product *Product) error {
	opClient, err := s.GetOpenidClient(session.IDPIss)
	if err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
	}

	// A product may register its own redirect_uri at the upstream IdP (oidc_redirect_uri): the IdP then
	// redirects straight back to the AS at that URL instead of the default /op-callback, so no app-side
	// intermediary popup is needed. When unset, fall back to the AS's own op-callback.
	opRedirectURI := opClient.RedirectURI()
	if len(product.OIDCRedirectURIs) > 0 {
		opRedirectURI = product.OIDCRedirectURIs[0]
	}

	opSession := &oidc.AuthnClientSession{
		ID:          ksuid.New().String(),
		Issuer:      session.IDPIss,
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

// PAREndpoint (RFC 9126) accepts a client-authenticated pushed authorization request: it validates the
// parameters exactly as /authorize would, stores them, and returns a single-use request_uri the client then
// hands to /authorize. FAPI 2.0 requires this — the request is integrity-protected (back-channel,
// private_key_jwt) rather than carried in the browser URL.
func (s *Server) PAREndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "invalid content type")
	}
	if err := r.ParseForm(); err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", "unable to parse form")
	}
	// PAR is client-authenticated (private_key_jwt) — that's what makes the pushed request trustworthy.
	client, _, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}
	session, product, perr := s.bindAuthzRequest(r)
	if perr != nil {
		return perr
	}
	if session.ClientID != client.ClientID {
		return oauthErr(http.StatusBadRequest, "invalid_request", "client_id does not match the authenticated client")
	}
	if !product.IsAllowedScopes(session.Scopes) {
		return oauthErr(http.StatusBadRequest, "invalid_scope", fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")))
	}
	session.RequestUri = "urn:ietf:params:oauth:request_uri:" + generateNonce(64)
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", "unable to store pushed request")
	}
	return writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": session.RequestUri,
		"expires_in":  int(defaultSessionTTL.Seconds()),
	})
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

	// Bind the id_token to THIS login: its nonce must equal the one we sent the OP (OIDC Core §3.1.3.7
	// step 11 — anti-replay / token injection). The oidc client requires a nonce claim; here we match it.
	var idClaims struct {
		Nonce string `json:"nonce"`
	}
	if err := tokenResponse.Claims(&idClaims); err != nil || idClaims.Nonce != authnSession.Nonce {
		return oauthErr(http.StatusBadRequest, "invalid_request", "id_token nonce mismatch")
	}

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
