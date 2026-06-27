package authzserver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
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

	session := &AuthzServerSession{
		ID:             ksuid.New().String(),
		CreatedAt:      time.Now(),
		ClientID:       client.ClientID,
		Scopes:         strings.Split(scope, " "),
		DPoPThumbprint: claims.Cnf.Jkt,
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

	slog.Info("Token request", "code", code, "redirect_uri", redirectUri, "client_id", client.ClientID)

	session, err := s.sessionStore.GetAuthzServerSessionByCode(code)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Errorf("unable to get session: %w", err).Error())
	}

	slog.Info("Token request: session", "session", fmt.Sprintf("%+v", session))

	if session.ClientID != client.ClientID {
		return oauthErr(http.StatusBadRequest, "invalid_request", "client_id mismatch")
	}

	if session.RedirectURI != redirectUri {
		return oauthErr(http.StatusBadRequest, "invalid_request", "redirect_uri mismatch")
	}

	codeChallengeBytes := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(codeChallengeBytes[:])
	if codeChallenge != session.CodeChallenge {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "invalid_request",
			Description: "invalid code verifier mismatch",
		})
	}

	session.DPoPThumbprint = claims.Cnf.Jkt

	if err := s.applyPolicyNewSession(product, session); err != nil {
		return err
	}

	response, err := s.issueOrRefreshTokens(session)

	if err != nil {
		return redirectWithError(w, r, session.RedirectURI, session.State, Error{
			Code:        "server_error",
			Description: fmt.Errorf("unable to issue access token: %w", err).Error(),
		})
	}

	// Persist the rotated refresh token (and its index) so the session is refreshable.
	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to save session: %v", err))
	}

	slog.Info("Token request: tokens issued", "response", fmt.Sprintf("%+v", response))

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

	session, err := s.sessionStore.GetAuthzServerSessionByRefreshToken(refreshToken)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "invalid refresh_token")
	}
	if session.ClientID != client.ClientID {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "client mismatch")
	}
	// Rotation/reuse: only the session's CURRENT refresh token is accepted. A superseded token (presented
	// after rotation, or a stolen one that has since been rotated) resolves via its stale index but fails
	// here — a replay signal.
	if session.RefreshToken != refreshToken {
		return oauthErr(http.StatusBadRequest, "invalid_grant", "refresh_token superseded")
	}
	// Sender-constrained (RFC 9449): the refresher must present the same DPoP key the tokens are bound to.
	if session.DPoPThumbprint != "" && claims.Cnf.Jkt != session.DPoPThumbprint {
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

func (s *Server) applyPolicyNewSession(product *Product, session *AuthzServerSession) *Error {
	if !product.IsAllowedScopes(session.Scopes) {
		return oauthErr(http.StatusForbidden, "invalid_scope", fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")))
	}
	session.AccessTokenDuration = 60 * time.Second
	session.ExpiresAt = session.CreatedAt.Add(10 * time.Minute)
	return nil
}
