package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/gematik/zero-lab/pkg/util"
)

type AuthCodeOption func(params url.Values)

func WithRedirectURI(redirectUri string) AuthCodeOption {
	return func(params url.Values) {
		params.Set("redirect_uri", redirectUri)
	}
}

type Client interface {
	AuthCodeURL(state, nonce, verifier string, opts ...AuthCodeOption) (string, error)
	Exchange(code, verifier string) (*TokenResponse, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func GenerateCodeVerifier() string {
	return util.GenerateRandomString(128)
}

func S256ChallengeFromVerifier(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
