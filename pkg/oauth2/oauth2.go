package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/gematik/zero-lab/pkg/util"
)

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
