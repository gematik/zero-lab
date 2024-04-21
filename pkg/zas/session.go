package zas

import "github.com/gematik/zero-lab/pkg/oidc"

type AuthzSession struct {
	ResponseType              string
	ClientID                  string
	RedirectURI               string
	CodeChallenge             string
	CodeChallengeMethod       string
	Nonce                     string
	State                     string
	Scope                     string
	OPIssuer                  string
	OPIntermediaryRedirectURI string
	RequestUri                string
	AuthnSession              *oidc.AuthnSession
	Code                      string
}
type AuthzSessionStore interface {
	oidc.AuthnSessionStore
	GetAuthzSession(state string) (*AuthzSession, error)
	GetAuthzSessionByAuthnState(authnState string) (*AuthzSession, error)
	GetAutzhSessionByRequestURI(requestURI string) (*AuthzSession, error)
	GetAuthzSessionByCode(code string) (*AuthzSession, error)
	SaveAutzhSession(session *AuthzSession) error
	DeleteAuthzSession(state string) error
}
