package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

type Option any

// redirect_uri
type WithAlternateRedirectURI string

// op_issuer
type WithOpenidProviderIssuer string

type Client interface {
	AuthCodeURL(state, nonce, verifier string, opts ...Option) (string, error)
	Exchange(code, verifier string, opts ...Option) (*TokenResponse, error)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type CodeChallengeMethod string

const (
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

func GenerateVerifier() string {
	n := 128
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic("Random number generation failed")
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret)
}

func S256ChallengeFromVerifier(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
