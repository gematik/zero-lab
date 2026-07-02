package pep

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

// sessionCookieClaims is the encrypted snapshot payload. Its format (JWE dir+A256GCM, these json tags) is the
// contract between pep/proxy's minting and this validation; keep them in sync.
type sessionCookieClaims struct {
	SID      string         `json:"sid"`
	Identity map[string]any `json:"id"`
	IssuedAt int64          `json:"iat"`
	Expiry   int64          `json:"exp"`
}

// OpenSessionCookie decrypts a pep session snapshot (JWE dir+A256GCM) with any of the given 32-byte keys
// (primary first, optional previous for rotation) and returns the identity when it decrypts and is unexpired.
// This is the validation half of pep/proxy's stateless snapshot, kept in pep so the verifier — and zaddy in
// forward_auth — can gate on the session cookie without the kv.
func OpenSessionCookie(token string, keys [][]byte) (identity map[string]any, sid string, ok bool) {
	for _, k := range keys {
		payload, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.DIRECT(), k))
		if err != nil {
			continue
		}
		var c sessionCookieClaims
		if json.Unmarshal(payload, &c) != nil {
			return nil, "", false
		}
		if time.Now().Unix() >= c.Expiry {
			return nil, "", false
		}
		return c.Identity, c.SID, true
	}
	return nil, "", false
}

// EnforcerSessionCookie gates a request on a valid pep session cookie (the stateless snapshot) and populates
// the context's claims with the identity, so downstream policies (EnforcerScope) work. It is the BFF/gateway
// and forward_auth counterpart to the token-verifying enforcers.
type EnforcerSessionCookie struct {
	TypeVal     EnforcerType `json:"type" validate:"required"`
	CookieName  string       `json:"cookie_name" validate:"required"`
	KeyPath     string       `json:"key_path,omitempty"`
	PrevKeyPath string       `json:"previous_key_path,omitempty"`

	keys [][]byte
}

// NewEnforcerSessionCookie builds the enforcer with keys supplied directly — the gateway passes the keys its
// snapshotter already loaded, avoiding a second read.
func NewEnforcerSessionCookie(cookieName string, keys [][]byte) *EnforcerSessionCookie {
	return &EnforcerSessionCookie{TypeVal: EnforcerTypeSessionCookie, CookieName: cookieName, keys: keys}
}

func (e *EnforcerSessionCookie) Type() EnforcerType { return EnforcerTypeSessionCookie }

func (e *EnforcerSessionCookie) Apply(ctx Context, next HandlerFunc) {
	if err := e.ensureKeys(); err != nil {
		ctx.Slogger().Error("session cookie keys unavailable", "error", err)
		ctx.Deny(ErrSessionRequired)
		return
	}
	c, err := ctx.Request().Cookie(e.CookieName)
	if err != nil {
		ctx.Deny(ErrSessionRequired)
		return
	}
	identity, _, ok := OpenSessionCookie(c.Value, e.keys)
	if !ok {
		ctx.Deny(ErrSessionRequired)
		return
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		ctx.Deny(ErrSessionRequired)
		return
	}
	ctx.SetClaims(raw)
	next(ctx)
}

// ensureKeys lazily loads keys from the configured paths when none were injected (the JSON/Caddyfile path).
func (e *EnforcerSessionCookie) ensureKeys() error {
	if len(e.keys) > 0 {
		return nil
	}
	if e.KeyPath == "" {
		return fmt.Errorf("no session cookie key configured")
	}
	k, err := loadSessionCookieKey(e.KeyPath)
	if err != nil {
		return err
	}
	keys := [][]byte{k}
	if e.PrevKeyPath != "" {
		p, err := loadSessionCookieKey(e.PrevKeyPath)
		if err != nil {
			return err
		}
		keys = append(keys, p)
	}
	e.keys = keys
	return nil
}

func loadSessionCookieKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("base64-decode key in %q: %w", path, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key in %q must be 32 bytes (256-bit), got %d", path, len(key))
	}
	return key, nil
}
