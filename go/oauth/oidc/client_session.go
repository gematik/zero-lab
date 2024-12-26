package oidc

type AuthnClientSession struct {
	ID            string         `json:"id"`
	Issuer        string         `json:"issuer"`
	State         string         `json:"state"`
	Nonce         string         `json:"nonce"`
	Verifier      string         `json:"verifier"`
	RedirectURI   string         `json:"redirect_uri"`
	AuthURL       string         `json:"auth_url"`
	TokenResponse *TokenResponse `json:"token_response"`
	Claims        map[string]any `json:"claims"`
}

type AuthnClientSessionStore interface {
	GetAuthnClientSessionByID(id string) (*AuthnClientSession, error)
	GetAuthnClientSessionByState(state string) (*AuthnClientSession, error)
	SaveAuthnClientSession(session *AuthnClientSession) error
	DeleteAuthnClientSession(state string) error
}
