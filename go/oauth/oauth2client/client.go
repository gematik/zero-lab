package oauth2client

import (
	"fmt"
	"strings"
)

type Option any

// redirect_uri
type WithAlternateRedirectURI string

// op_issuer
type WithOpenidProviderIssuer string

type Client struct {
}

type Config struct {
}

func New(cfg *Config) (*Client, error) {
	return &Client{}, nil
}

func buildMetadataURL(issuer string) string {
	url := strings.TrimRight(issuer, "/")
	return fmt.Sprintf("%s/.well-known/oauth-authorization-server", url)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}
