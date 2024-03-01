package zas

import (
	"net/http"

	"github.com/gematik/zero-lab/pkg/oauth2"
	"github.com/gematik/zero-lab/pkg/oidc"
	"github.com/gematik/zero-lab/pkg/util"
	"github.com/labstack/echo/v4"
)

type Server struct {
	identityIssuers []*oidc.Client
	ClientsPolicy   *ClientsPolicy
}

func (s *Server) AddIdentityIssuers(issuer ...*oidc.Client) {
	s.identityIssuers = append(s.identityIssuers, issuer...)
}

type AuthorizationSession struct {
	ResponseType        string
	ClientId            string
	RedirectUri         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	State               string
	Scope               string
	Issuer              string
	AuthIntermediaryUrl string
}

func (s *Server) AuthorizationEndpoint(c echo.Context) error {
	var session AuthorizationSession
	binderr := echo.FormFieldBinder(c).
		MustString("response_type", &session.ResponseType).
		MustString("client_id", &session.ClientId).
		MustString("redirect_uri", &session.RedirectUri).
		MustString("code_challenge", &session.CodeChallenge).
		MustString("code_challenge_method", &session.CodeChallengeMethod).
		MustString("nonce", &session.Nonce).
		MustString("state", &session.State).
		MustString("scope", &session.Scope).
		MustString("issuer", &session.Issuer).
		String("auth_intermediary_url", &session.AuthIntermediaryUrl).
		BindError()

	if binderr != nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: binderr.Error(),
		})
	}

	if !s.ClientsPolicy.AllowedClient(session.ClientId) {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown client_id",
		})
	}

	if !s.ClientsPolicy.AllowedAuthIntermediaryURL(session.ClientId, session.RedirectUri) {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "invalid auth_intermediary_url",
		})
	}

	identityIssuer := s.findIdentityIssuer(session.Issuer)
	if identityIssuer == nil {
		return echo.NewHTTPError(http.StatusBadRequest, oauth2.Error{
			Code:        "invalid_request",
			Description: "unknown issuer",
		})
	}

	type IdentityVerificationSession struct {
		Issuer      string
		State       string
		Nonce       string
		Verifier    string
		RedirectUri string
	}

	idSession := IdentityVerificationSession{
		Issuer:   session.Issuer,
		State:    util.GenerateRandomString(128),
		Nonce:    session.Nonce,
		Verifier: oauth2.GenerateCodeVerifier(),
	}

	authUrl := identityIssuer.AuthCodeURL(
		idSession.State,
		idSession.Nonce,
		oauth2.GenerateCodeVerifier(),
		oauth2.WithRedirectURI(session.RedirectUri),
	)
	return c.Redirect(http.StatusFound, authUrl)
}

func (s *Server) PushedAuthorizationRequest(c echo.Context) error {
	return echo.ErrBadRequest
}

func (s *Server) findIdentityIssuer(issuer string) *oidc.Client {
	for _, id := range s.identityIssuers {
		if id.Config.Issuer == issuer {
			return id
		}
	}
	return nil
}
