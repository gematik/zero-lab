package oauth2

import "net/url"

type ParameterOption func(params url.Values)

type Client interface {
	AuthCodeURL(state, nonce, verifier string, opts ...ParameterOption) (string, error)
	Exchange(code, verifier string, opts ...ParameterOption) (*TokenResponse, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}
