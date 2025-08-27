package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

type Client interface {
	Issuer() string
	ClientID() string
	Name() string
	LogoURI() string
	RedirectURI() string
	AuthenticationURL(state, nonce, verifier string, options ...Option) (string, error)
	ExchangeForIdentity(code, verifier string, options ...Option) (*TokenResponse, error)
}

type Option any

// Allows for setting an alternate redirect URI (redirect_uri) for the authorization request.
type WithAlternateRedirectURI string

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	RefreshToken string    `json:"refresh_token"`
	IDTokenRaw   string    `json:"id_token"`
	IDToken      jwt.Token `json:"-"`
}

func (t *TokenResponse) Claims(claims any) error {
	if t.IDTokenRaw == "" {
		return fmt.Errorf("ID token is empty")
	}
	claimsRaw := strings.Split(t.IDTokenRaw, ".")[1]

	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsRaw)
	if err != nil {
		return fmt.Errorf("decoding ID claims: %w", err)
	}

	if err := json.Unmarshal(claimsBytes, claims); err != nil {
		return fmt.Errorf("unmarshal claims: %w", err)
	}

	return nil
}
