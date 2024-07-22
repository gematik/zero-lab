package oauth2server

import "github.com/gematik/zero-lab/pkg/oidc"

type AuthzServerSession struct {
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
