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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	Scope            string `json:"scope,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
}

// TokenEndpoint handles the token request for various grant types
func (s *Server) TokenEndpoint(w http.ResponseWriter, r *http.Request) error {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "invalid content type")
	}
	if err := r.ParseForm(); err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Errorf("unable to parse form: %w", err).Error())
	}

	if !r.Form.Has("grant_type") {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing grant_type")
	}
	grantType := r.FormValue("grant_type")
	switch grantType {
	case GrantTypeAuthorizationCode:
		return s.tokenEndpointAuthorizationCode(w, r)
	case GrantTypeClientCredentials:
		return s.tokenEndpointClientCredentials(w, r)
	case GrantTypeRefreshToken:
		return s.tokenEndpointRefreshToken(w, r)
	default:
		slog.Error("Unsupported grant type", "grant_type", grantType)
		return oauthErr(http.StatusBadRequest, "unsupported_grant_type", fmt.Sprintf("unsupported grant type: %s", grantType))
	}

}

// verifyClient authenticates the caller via private_key_jwt (RFC 7523 §2.2): the request carries a
// client_assertion JWT whose signature is verified against the calling client's registered public
// JWK. It also redeems the assertion's one-time nonce and returns the validated claims (for the
// kept cnf.jkt DPoP binding). Used by the token endpoint (all grants) and introspection.
func (s *Server) verifyClient(r *http.Request) (*Client, *ClientAssertionClaims, *Error) {
	if at := r.FormValue("client_assertion_type"); at != ClientAssertionTypeJWTBearer {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", "client_assertion_type must be "+ClientAssertionTypeJWTBearer)
	}
	assertion := r.FormValue("client_assertion")
	if assertion == "" {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", "missing client_assertion")
	}
	if s.clientsRegistry == nil {
		return nil, nil, oauthErr(http.StatusInternalServerError, "server_error", "clients registry not configured")
	}

	// Identify the client from the (not yet verified) assertion subject, then verify the signature
	// against that client's registered public JWK.
	claims, err := parseClientAssertionClaims(assertion)
	if err != nil {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", err.Error())
	}
	client, err := s.clientsRegistry.GetClient(claims.Sub)
	if err != nil {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", err.Error())
	}

	if _, err := jwt.Parse([]byte(assertion),
		jwt.WithKey(jwa.ES256(), client.Key()),
		jwt.WithAudience(s.Metadata.Issuer),
		jwt.WithAcceptableSkew(time.Minute),
		jwt.WithValidate(true),
	); err != nil {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", fmt.Sprintf("invalid client_assertion: %v", err))
	}

	if err := claims.Validate(); err != nil {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", fmt.Sprintf("invalid client_assertion claims: %v", err))
	}
	if claims.Iss != client.ClientID || claims.Sub != client.ClientID {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", "iss and sub must equal client_id")
	}

	// Redeem the one-time nonce (freshness / anti-replay).
	if err := s.nonceService.Redeem(claims.Nonce); err != nil {
		return nil, nil, oauthErr(http.StatusUnauthorized, "invalid_client", fmt.Sprintf("invalid nonce: %v", err))
	}

	return client, claims, nil
}

// dpopBinding returns the JWK thumbprint the tokens of this request are bound to, or "" for Bearer
// tokens, for every grant alike (RFC 9449 Section 5: "applicable for all access token requests regardless
// of grant type").
//
// A proof is checked (Section 4.3) when the request carries one, since "the DPoP HTTP header field MUST
// contain a valid DPoP proof JWT", and when the client assertion names a key (cnf.jkt): a key the client
// only names is not one it holds, so the proof must be signed by exactly that key. The tokens are bound to
// the proof's key (Sections 5, 6). The expected URI is the token endpoint from the metadata, never one
// rebuilt from request headers.
func (s *Server) dpopBinding(r *http.Request, claims *ClientAssertionClaims) (string, *Error) {
	if claims.Cnf.Jkt == "" && len(r.Header.Values(dpop.HeaderName)) == 0 {
		return "", nil
	}
	proof, err := s.dpopVerifier.Verify(r.Header, dpop.Request{
		Method:     r.Method,
		URI:        s.Metadata.TokenEndpoint,
		Thumbprint: claims.Cnf.Jkt,
	})
	var refused *dpop.Error
	switch {
	case err == nil:
		return proof.Thumbprint, nil
	case errors.As(err, &refused):
		return "", oauthErr(http.StatusBadRequest, refused.Code, refused.Description)
	default:
		slog.Error("DPoP proof could not be checked", "error", err)
		return "", oauthErr(http.StatusInternalServerError, "server_error", "DPoP proof could not be checked")
	}
}

// clientProduct resolves the product a client belongs to (its redirect-URI and scope policy).
func (s *Server) clientProduct(client *Client) (*Product, *Error) {
	if s.productsRegistry == nil {
		return nil, oauthErr(http.StatusInternalServerError, "server_error", "products registry not configured")
	}
	product, err := s.productsRegistry.GetProduct(client.ProductID)
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_client", err.Error())
	}
	return product, nil
}

func (s *Server) tokenEndpointClientCredentials(w http.ResponseWriter, r *http.Request) error {

	client, claims, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	product, productErr := s.clientProduct(client)
	if productErr != nil {
		return productErr
	}

	slog.Info("Token request", "client", client.ClientID)

	scope := r.FormValue("scope")
	if scope == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing scope")
	}

	if !product.IsAllowedScope(scope) {
		return oauthErr(http.StatusForbidden, "invalid_scope", fmt.Sprintf("scope not allowed: %s", scope))
	}

	jkt, dpopErr := s.dpopBinding(r, claims)
	if dpopErr != nil {
		return dpopErr
	}

	session := &AuthzServerSession{
		ID:             uuid.NewV4().String(),
		CreatedAt:      time.Now(),
		ClientID:       client.ClientID,
		Scopes:         strings.Split(scope, " "),
		DPoPThumbprint: jkt,
		RefreshCount:   -1,
	}

	if err := s.applyPolicyNewSession(product, session); err != nil {
		return err
	}

	response, err := s.issueOrRefreshTokens(session)
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to issue access token: %v", err))
	}

	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to save session: %v", err))
	}

	return writeJSON(w, http.StatusOK, response)
}

// tokenEndpointAuthorizationCode handles the token request for the authorization code grant type
func (s *Server) tokenEndpointAuthorizationCode(w http.ResponseWriter, r *http.Request) error {
	client, claims, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	product, productErr := s.clientProduct(client)
	if productErr != nil {
		return productErr
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
		return oauthErr(http.StatusBadRequest, "invalid_request", binderr.Error())
	}

	slog.Info("Token request", "redirect_uri", redirectUri, "client_id", client.ClientID)

	session, err := s.sessionStore.GetAuthzServerSessionByCode(code)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Errorf("unable to get session: %w", err).Error())
	}

	if session.ClientID != client.ClientID {
		return oauthErr(http.StatusBadRequest, "invalid_request", "client_id mismatch")
	}

	if session.RedirectURI != redirectUri {
		return oauthErr(http.StatusBadRequest, "invalid_request", "redirect_uri mismatch")
	}

	if verr := validateCodeVerifier(codeVerifier); verr != nil {
		return verr
	}
	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	if codeChallenge != session.CodeChallenge {
		// The token endpoint returns JSON errors (RFC 6749 §5.2), never a browser redirect — the caller is a backend.
		return oauthErr(http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
	}

	jkt, dpopErr := s.dpopBinding(r, claims)
	if dpopErr != nil {
		return dpopErr
	}
	session.DPoPThumbprint = jkt

	if err := s.applyPolicyNewSession(product, session); err != nil {
		return err
	}

	response, err := s.issueOrRefreshTokens(session)

	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to issue access token: %v", err))
	}

	// Persist the rotated refresh token (and its index) so the session is refreshable.
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to save session: %v", err))
	}

	slog.Info("Token request: tokens issued", "client_id", client.ClientID, "session", session.ID)

	return writeJSON(w, http.StatusOK, response)
}

func (s *Server) tokenEndpointRefreshToken(w http.ResponseWriter, r *http.Request) error {
	client, claims, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing refresh_token")
	}
	// Only the hash is stored/indexed; hash the presented token to look it up and to compare.
	refreshHash := hashRefreshToken(refreshToken)

	session, err := s.sessionStore.GetAuthzServerSessionByRefreshToken(refreshHash)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "invalid refresh_token")
	}
	if session.ClientID != client.ClientID {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "client mismatch")
	}
	// Rotation/reuse: only the session's CURRENT refresh token is accepted. A superseded token (presented
	// after rotation, or a stolen one that has since been rotated) resolves via its stale index but fails
	// here — a replay signal.
	if session.RefreshToken != refreshHash {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "refresh_token superseded")
	}
	// Sender-constrained (RFC 9449 Section 5): the refresher must prove it holds the key the session's
	// tokens are bound to, with a proof by that key; the asserted cnf.jkt must name the same key.
	if session.DPoPThumbprint != "" && claims.Cnf.Jkt != session.DPoPThumbprint {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "DPoP key mismatch")
	}
	jkt, dpopErr := s.dpopBinding(r, claims)
	if dpopErr != nil {
		return dpopErr
	}
	if jkt != session.DPoPThumbprint {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "DPoP key mismatch")
	}
	// Absolute lifetime: refresh never extends a session past its cap.
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "session expired")
	}

	response, err := s.issueOrRefreshTokens(session) // rotates RefreshToken, re-binds via DPoPThumbprint
	if err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to refresh tokens: %v", err))
	}
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to save session: %v", err))
	}
	// The session now indexes the NEW refresh hash; drop the rotated-out one so it stops resolving.
	_ = s.sessionStore.DeleteRefreshIndex(refreshHash)
	slog.Info("Token refreshed", "client", client.ClientID, "session", session.ID, "refresh_count", session.RefreshCount)
	return writeJSON(w, http.StatusOK, response)
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
		accessJwt.Set("cnf", map[string]any{
			"jkt": session.DPoPThumbprint,
		})
	}

	accessTokenBytes, err := jwt.Sign(accessJwt, jwt.WithKey(jwa.ES256(), s.sigPrK))
	if err != nil {
		return nil, fmt.Errorf("unable to sign access token: %w", err)
	}

	// Rotate the refresh token. Only the HASH is persisted (record + index); the raw token goes back to the
	// client in the response and is never stored — a kv reader gets hashes, not replayable tokens.
	rawRefresh := generateNonce(64)
	session.RefreshToken = hashRefreshToken(rawRefresh)
	session.RefreshCount++

	return &TokenResponse{
		AccessToken:      string(accessTokenBytes),
		TokenType:        tokenType,
		ExpiresIn:        int(time.Until(exp).Seconds()),
		Scope:            strings.Join(session.Scopes, " "),
		RefreshToken:     rawRefresh,
		RefreshExpiresIn: int(time.Until(session.ExpiresAt).Seconds()),
	}, nil
}

func (s *Server) applyPolicyNewSession(product *Product, session *AuthzServerSession) *Error {
	if !product.IsAllowedScopes(session.Scopes) {
		return oauthErr(http.StatusForbidden, "invalid_scope", fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")))
	}
	session.AccessTokenDuration = 60 * time.Second
	session.ExpiresAt = session.CreatedAt.Add(10 * time.Minute)
	return nil
}
