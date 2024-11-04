package authzserver

import (
	"time"

	"github.com/gematik/zero-lab/go/libzero/oidc"
)

type AuthzServerSession struct {
	ID                        string                   `json:"id"`
	Duration                  time.Duration            `json:"duration"`
	ResponseType              string                   `json:"response_type"`
	ClientID                  string                   `json:"client_id"`
	RedirectURI               string                   `json:"redirect_uri"`
	CodeChallenge             string                   `json:"code_challenge"`
	CodeChallengeMethod       string                   `json:"code_challenge_method"`
	Nonce                     string                   `json:"nonce"`
	State                     string                   `json:"state"`
	Scope                     string                   `json:"scope"`
	OPIssuer                  string                   `json:"op_issuer"`
	OPIntermediaryRedirectURI string                   `json:"op_intermediary_redirect_uri"`
	RequestUri                string                   `json:"request_uri"`
	AuthnClientSession        *oidc.AuthnClientSession `json:"authn_client_session"`
	Code                      string                   `json:"code"`
	RefreshToken              string                   `json:"refresh_token"`
	RefreshCount              int                      `json:"refresh_count"`
	FirstIssuedAt             time.Time                `json:"first_issued_at"`
	LastIssuedAt              time.Time                `json:"last_issued_at"`
}
type AuthzServerSessionStore interface {
	oidc.AuthnClientSessionStore
	GetAuthzServerSession(state string) (*AuthzServerSession, error)
	GetAuthzServerSessionByAuthnState(authnState string) (*AuthzServerSession, error)
	GetAutzhServerSessionByRequestURI(requestURI string) (*AuthzServerSession, error)
	GetAuthzServerSessionByCode(code string) (*AuthzServerSession, error)
	SaveAutzhServerSession(session *AuthzServerSession) error
	DeleteAuthzServerSession(state string) error
}
