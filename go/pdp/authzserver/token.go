package authzserver

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/segmentio/ksuid"
)

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
	GrantTypeJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
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
	case GrantTypeJWTBearer:
		return s.tokenEndpointJWTBearer(w, r)
	default:
		slog.Error("Unsupported grant type", "grant_type", grantType)
		return oauthErr(http.StatusBadRequest, "unsupported_grant_type", fmt.Sprintf("unsupported grant type: %s", grantType))
	}

}

func (s *Server) verifyClient(r *http.Request) (*ClientMetadata, *Error) {
	formClientId := r.FormValue("client_id")

	if formClientId != "" {
		cm, err := s.clientsRegistry.GetClientMetadata(formClientId)
		if err != nil {
			return nil, oauthErr(http.StatusBadRequest, "invalid_client", fmt.Errorf("unable to get client metadata: %w", err).Error())
		}

		if cm.Type == ClientTypeConfidential {
			formClientSecret := r.FormValue("client_secret")
			if formClientSecret == "" {
				return nil, oauthErr(http.StatusBadRequest, "invalid_client", "missing client_secret")
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
		return nil, oauthErr(http.StatusUnauthorized, "unauthorized_client", "missing basic auth")
	}

	client, err := s.clientsRegistry.GetClientMetadata(clientId)
	if err != nil {
		return nil, oauthErr(http.StatusBadRequest, "invalid_client", err.Error())
	}

	return verifyClientSecret(clientSecret, client)
}

func verifyClientSecret(clientSecret string, client *ClientMetadata) (*ClientMetadata, *Error) {
	if client.ClientSecretHash == "" && client.Type == ClientTypePublic {
		return nil, oauthErr(http.StatusBadRequest, "unauthorized_client", "public client must not use client_secret")
	}

	if ok, err := VerifySecretHash(clientSecret, client.ClientSecretHash); !ok {
		if err != nil {
			slog.Error("VerifySecretHash failed", "error", err)
		}

		return nil, oauthErr(http.StatusBadRequest, "unauthorized_client", "invalid client_secret")
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
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing scope")
	}

	if !client.IsAllowedScope(scope) {
		return oauthErr(http.StatusForbidden, "invalid_scope", fmt.Sprintf("scope not allowed: %s", scope))
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
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to issue access token: %v", err))
	}

	if err := s.sessionStore.SaveAutzhServerSession(session); err != nil {
		return oauthErr(http.StatusInternalServerError, "server_error", fmt.Sprintf("unable to save session: %v", err))
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
		return oauthErr(http.StatusBadRequest, "bad_request", "JWT Bearer grant type not configured")
	}

	assertion, ok := r.Form["assertion"]
	if !ok {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing assertion parameter")
	}

	claims, err := s.verifyClientAssertionFunc(assertion[0])
	if err != nil {
		return oauthErr(http.StatusUnauthorized, "bad_request", fmt.Sprintf("failed to verify assertion: %v", err))
	}

	slog.Info("Token request", "claims", claims)

	if err := claims.Validate(); err != nil {
		return oauthErr(http.StatusBadRequest, "bad_request", fmt.Sprintf("invalid assertion claims: %v", err))
	}

	// redeem nonce
	err = s.nonceService.Redeem(claims.Nonce)
	if err != nil {
		return oauthErr(http.StatusBadRequest, "invalid_request", fmt.Sprintf("invalid nonce: %v", err))
	}

	dpopBinding, dpoppErr := dpop.ParseRequest(r, dpop.ParseOptions{
		MaxAge:        s.dpopMaxAge,
		NonceRequired: true,
	})
	if dpoppErr != nil {
		return oauthErr(dpoppErr.HttpStatus, dpoppErr.Code, dpoppErr.Description)
	}
	slog.Info("DPoP token", "dpop", fmt.Sprintf("%+v", dpopBinding), "raw", r.Header.Get("DPoP"))

	if dpopBinding.DPoP.Nonce != claims.Nonce {
		return oauthErr(http.StatusBadRequest, "invalid_request", "nonce mismatch")
	}

	if dpopBinding.DPoP.KeyThumbprint != "" && dpopBinding.DPoP.KeyThumbprint != claims.Cnf.Jkt {
		return oauthErr(http.StatusBadRequest, "invalid_request", "key thumbprint mismatch")
	}

	return oauthErr(http.StatusUnauthorized, "not_implemented", "JWT Bearer grant type not implemented")

}

func (s *Server) tokenEndpointRefreshToken(w http.ResponseWriter, r *http.Request) error {
	client, clientError := s.verifyClient(r)
	if clientError != nil {
		return clientError
	}

	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		return oauthErr(http.StatusBadRequest, "invalid_request", "missing refresh_token")
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

func (s *Server) applyPolicyNewSession(client *ClientMetadata, session *AuthzServerSession) *Error {
	if !client.IsAllowedScopes(session.Scopes) {
		return oauthErr(http.StatusForbidden, "invalid_scope", fmt.Sprintf("scope not allowed: %s", strings.Join(session.Scopes, " ")))
	}
	session.AccessTokenDuration = 60 * time.Second
	session.ExpiresAt = session.CreatedAt.Add(10 * time.Minute)
	return nil
}
