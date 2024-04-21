package oidc

import "github.com/gematik/zero-lab/pkg/oauth2"

type AuthnSession struct {
	ID            string
	Issuer        string
	State         string
	Nonce         string
	Verifier      string
	RedirectURI   string
	AuthURL       string
	TokenResponse *oauth2.TokenResponse
	Claims        map[string]interface{}
}

type AuthnSessionStore interface {
	GetAuthnSessionByID(id string) (*AuthnSession, error)
	GetAuthnSessionByState(state string) (*AuthnSession, error)
	SaveAuthnSession(session *AuthnSession) error
	DeleteAuthnSession(state string) error
}
