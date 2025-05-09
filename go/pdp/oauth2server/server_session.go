package oauth2server

import (
	"time"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

type AuthzServerSession struct {
	ID                        string                   `json:"id"`
	CreatedAt                 time.Time                `json:"created_at"`
	ExpiresAt                 time.Time                `json:"expires_at"`
	AccessTokenDuration       time.Duration            `json:"access_token_duration"`
	Audience                  []string                 `json:"audience"`
	ClientID                  string                   `json:"client_id"`
	RedirectURI               string                   `json:"redirect_uri"`
	CodeChallenge             string                   `json:"code_challenge"`
	CodeChallengeMethod       string                   `json:"code_challenge_method"`
	State                     string                   `json:"state"`
	Scopes                    []string                 `json:"scopes"`
	OPIssuer                  string                   `json:"op_issuer"`
	OPIntermediaryRedirectURI string                   `json:"op_intermediary_redirect_uri"`
	RequestUri                string                   `json:"request_uri"`
	AuthnClientSession        *oidc.AuthnClientSession `json:"authn_client_session"`
	Code                      string                   `json:"code"`
	RefreshToken              string                   `json:"refresh_token"`
	RefreshCount              int                      `json:"refresh_count"`
	LastRefreshAt             time.Time                `json:"last_refresh_at"`
	DPoPThumbprint            string                   `json:"dpop_thumbprint"`
}

type AuthzServerSessionStore interface {
	GetAuthzServerSessionByID(id string) (*AuthzServerSession, error)
	GetAuthzServerSessionByState(state string) (*AuthzServerSession, error)
	GetAuthzServerSessionByAuthnState(authnState string) (*AuthzServerSession, error)
	GetAutzhServerSessionByRequestURI(requestURI string) (*AuthzServerSession, error)
	GetAuthzServerSessionByCode(code string) (*AuthzServerSession, error)
	SaveAutzhServerSession(session *AuthzServerSession) error
	DeleteAuthzServerSessionByID(id string) error
}
