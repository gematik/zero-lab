package pep

import (
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jws"
)

var ContextKeySessionCookie = "session_cookie"

// Guard which checks if the session cookie is valid
type SessionCookieGuard struct {
	// Name of the cookie
	CookieName  string
	DecryptFunc func([]byte) ([]byte, error)
	VerifyFunc  func([]byte) ([]byte, error)
}

func DecryptWithDirectKeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jwe.Decrypt(payload, jwe.WithKey(jwa.DIRECT, key))
	}
}

func VerifyWithHS256KeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jws.Verify(payload, jws.WithKey(jwa.HS256, key))
	}
}

func (c SessionCookieGuard) VerifyRequest(ctx *GuardContext, r *http.Request) error {
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return fmt.Errorf("cookie not found: %w", err)
	}

	decrypted, err := c.DecryptFunc([]byte(cookie.Value))
	if err != nil {
		return fmt.Errorf("cookie decryption failed: %w", err)
	}

	data, err := c.VerifyFunc(decrypted)
	if err != nil {
		return fmt.Errorf("cookie signature verification failed: %w", err)
	}

	ctx.SessionCookieRaw = data

	return nil
}
