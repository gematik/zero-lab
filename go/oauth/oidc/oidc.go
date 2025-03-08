package oidc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwt"
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
	asMap, err := t.IDToken.AsMap(context.Background())
	if err != nil {
		return fmt.Errorf("unable to convert ID token to map: %w", err)
	}

	// serialize to JSON and back to get the correct types
	// this is a bit of a hack, but it works
	asJSON, err := json.Marshal(asMap)
	if err != nil {
		return fmt.Errorf("unable to marshal claims: %w", err)
	}

	if err := json.Unmarshal(asJSON, claims); err != nil {
		return fmt.Errorf("unable to unmarshal claims: %w", err)
	}

	return nil
}
