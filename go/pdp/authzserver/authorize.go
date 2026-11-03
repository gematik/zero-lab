// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package authzserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/gematik/zero-lab/go/openid"
)

// sessionRef is what a log says for a session: enough to correlate its lines, and nothing of its ID, which is the jti of
// its access tokens and the key of its record (server rule 5).
func sessionRef(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:6])
}

// scrubbed is err's text for the log, without the given values: an upstream's refusal can echo what it was sent, and a
// store's error can name a key, as:code:<the code> among them, whichever store it is.
func scrubbed(err error, secrets ...string) string {
	text := err.Error()
	for _, secret := range secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, "[redacted]")
		}
	}
	return text
}

// serverError logs the detail and gives the client the description alone (server rule 2).
func serverError(description string, err error, secrets ...string) *Error {
	slog.Error(description, "error", scrubbed(err, secrets...))
	return oauthErr(http.StatusInternalServerError, "server_error", description)
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI string, state string, err Error) error {
	params := url.Values{}
	if state != "" {
		params.Add("state", state)
	}
	params.Add("error", err.Code)
	params.Add("error_description", err.Description)

	http.Redirect(w, r, redirectURI+"?"+params.Encode(), http.StatusFound) //nolint:gosec // redirectURI was matched exactly against the product's registered URIs at PAR, or is a configured OP callback
	return nil
}

// bindAuthzRequest parses + validates an authorization request — from the /authorize query OR a /par body —
// into a pending session and resolves its product. Shared so direct authorization and PAR enforce identical
// policy. The scope-allowlist check is left to the caller (it redirects at /authorize, returns JSON at /par).
func (s *Server) bindAuthzRequest(r *http.Request) (*Session, *Product, *Error) {
	session := &Session{
		ID:        uuid.NewV4().String(),
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
		return nil, nil, oauthErr(http.StatusBadRequest, "unsupported_response_type", "unsupported response_type: "+responseType)
	}
	if session.IDPIss == "" {
		session.IDPIss = s.defaultIDPIss
	}
	if session.CodeChallengeMethod != "S256" {
		return nil, nil, oauthErr(http.StatusBadRequest, "invalid_request", "unsupported code_challenge_method: "+session.CodeChallengeMethod)
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

// AuthorizationEndpoint looks up a pushed authorization request by its single-use request_uri and starts the
// upstream OpenID Provider login.
func (s *Server) AuthorizationEndpoint(w http.ResponseWriter, r *http.Request) error {
	// FAPI 2.0: authorization requests MUST be pushed (RFC 9126). The browser arrives here carrying only the
	// single-use request_uri minted at /par — where the request was validated and client-authenticated.
	// Direct authorization parameters are not accepted.
	requestURI := r.FormValue("request_uri")
	if requestURI == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request",
			"request_uri is required: push the authorization request to the PAR endpoint first")
	}
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

// startOpenidProviderLogin resolves the upstream OP, creates the authentication session and
// redirects the user-agent to the provider. On error it redirects back to the client with an
// OAuth error.
func (s *Server) startOpenidProviderLogin(w http.ResponseWriter, r *http.Request, session *Session, product *Product) error {
	opClient, err := s.GetOpenidClient(r.Context(), session.IDPIss)
	if err != nil {
		slog.Warn("no client for the requested OpenID Provider", "issuer", session.IDPIss, "error", err)
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "the identity provider is not available",
		})
	}

	// A product may register its own redirect_uri at the upstream IdP (oidc_redirect_uri): the IdP then
	// redirects straight back to the AS at that URL instead of the default /op-callback, so no app-side
	// intermediary popup is needed. When unset, fall back to the AS's own op-callback.
	var opRedirectURI string
	if len(product.OIDCRedirectURIs) > 0 {
		opRedirectURI = product.OIDCRedirectURIs[0]
	}

	opSession := &openid.AuthnClientSession{
		ID:          uuid.NewV4().String(),
		Issuer:      session.IDPIss,
		State:       uuid.NewV4().String(),
		Nonce:       uuid.NewV4().String(),
		Verifier:    openid.GenerateVerifier(),
		RedirectURI: opRedirectURI,
	}

	authURL, err := opClient.AuthenticationURL(r.Context(), openid.Login{
		State:       opSession.State,
		Nonce:       opSession.Nonce,
		Verifier:    opSession.Verifier,
		RedirectURI: opSession.RedirectURI,
	})
	if err != nil {
		refused := serverError("unable to start the login at the identity provider", err, opSession.State, opSession.Nonce, opSession.Verifier)
		return redirectWithError(w, r, session.RedirectURI, session.State, *refused)
	}
	opSession.AuthURL = authURL

	session.AuthnClientSession = opSession
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		refused := serverError("unable to start the login", err, opSession.State)
		return redirectWithError(w, r, session.RedirectURI, session.State, *refused)
	}

	slog.Info("Redirecting to OpenID Provider", "issuer", opSession.Issuer, "session_ref", sessionRef(session.ID))

	http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // the target is the authorization endpoint of a configured provider or of a federation-verified entity statement
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
		return oauthErr(http.StatusBadRequest, "invalid_scope", "scope not allowed: "+strings.Join(session.Scopes, " "))
	}
	session.RequestURI = "urn:ietf:params:oauth:request_uri:" + generateNonce(64)
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", "unable to store pushed request")
	}
	return writeJSON(w, http.StatusCreated, map[string]any{
		"request_uri": session.RequestURI,
		"expires_in":  int(defaultSessionTTL.Seconds()),
	})
}

// GetOpenidClient returns an OpenID Connect client for the given issuer
func (s *Server) GetOpenidClient(ctx context.Context, issuer string) (openid.Client, error) {
	provider, err := s.providers.Provider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return provider.Client, nil
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
	authzSession, err := s.sessionStore.GetAuthzServerSessionByAuthnState(state)
	if errors.Is(err, errSessionNotFound) {
		return oauthErr(http.StatusBadRequest, "invalid_request", "unknown or expired login")
	}
	if err != nil {
		return serverError("unable to continue the login", err, state)
	}
	authnSession := authzSession.AuthnClientSession
	if authnSession == nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing openid session")
	}

	if upstream := query.Get("error"); upstream != "" {
		slog.Error("OP callback error", "issuer", authnSession.Issuer, "error", upstream, "session_ref", sessionRef(authzSession.ID))
		// RFC 6749 section 4.1.2.1: to the client that asked, with its state. authnSession's are this server's own
		// callback and the state it sent the provider.
		return redirectWithError(w, r, authzSession.RedirectURI, authzSession.State, Error{
			Code:        upstream,
			Description: query.Get("error_description"),
		})
	}

	// retrieve PKCE code from query
	code := query.Get("code")
	if code == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing code")
	}

	slog.Info("OP callback", "issuer", authnSession.Issuer, "session_ref", sessionRef(authzSession.ID))

	identityIssuer, err := s.GetOpenidClient(r.Context(), authnSession.Issuer)
	if err != nil {
		slog.Warn("no client for the login's OpenID Provider", "issuer", authnSession.Issuer, "error", err)
		return oauthErr(http.StatusBadRequest, "invalid_request", "the identity provider is not available")
	}

	// exchange code for tokens with the OP
	tokenResponse, err := identityIssuer.Exchange(r.Context(), openid.Login{
		Nonce:       authnSession.Nonce,
		Verifier:    authnSession.Verifier,
		RedirectURI: authnSession.RedirectURI,
	}, code)
	if err != nil {
		return serverError("unable to complete the login at the identity provider", err, code, state, authnSession.Nonce, authnSession.Verifier)
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

	authzSession.Code = generateNonce(64)

	if err := s.sessionStore.SaveAutzhServerSession(authzSession); err != nil {
		return serverError("unable to complete the login", err, authzSession.Code, state)
	}

	params := url.Values{}
	params.Set("code", authzSession.Code)
	params.Set("state", authzSession.State)

	http.Redirect(w, r, authzSession.RedirectURI+"?"+params.Encode(), http.StatusFound) //nolint:gosec // the session's RedirectURI was matched exactly against the product's registered URIs at PAR
	return nil
}
