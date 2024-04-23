package oauth2

type AuthzClientSession struct {
	ID            string         `json:"id"`
	Issuer        string         `json:"issuer"`
	State         string         `json:"state"`
	Nonce         string         `json:"nonce"`
	Verifier      string         `json:"verifier"`
	RedirectURI   string         `json:"redirect_uri"`
	AuthURL       string         `json:"auth_url"`
	TokenResponse *TokenResponse `json:"token_response"`
	AccessToken   string         `json:"access_token"`
	RefreshToken  string         `json:"refresh_token"`
}

type AuthzClientSessionStore interface {
	GetAuthzClientSessionByID(id string) (*AuthzClientSession, error)
	GetAuthzClientSessionByState(state string) (*AuthzClientSession, error)
	SaveAuthzClientSession(session *AuthzClientSession) error
	DeleteAuthzClientSession(state string) error
}
