// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package pep

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	sealed, err := jose.ParseEncryptedCompact(token, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, "", false
	}
	for _, k := range keys {
		payload, err := sealed.Decrypt(k)
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
	TypeVal     EnforcerType `json:"type"`
	CookieName  string       `json:"cookie_name"`
	KeyPath     string       `json:"key_path,omitempty"`
	PrevKeyPath string       `json:"previous_key_path,omitempty"`

	keysMu sync.Mutex
	keys   [][]byte
}

// NewEnforcerSessionCookie builds the enforcer with keys supplied directly — the gateway passes the keys its
// snapshotter already loaded, avoiding a second read.
func NewEnforcerSessionCookie(cookieName string, keys [][]byte) *EnforcerSessionCookie {
	return &EnforcerSessionCookie{TypeVal: EnforcerTypeSessionCookie, CookieName: cookieName, keys: keys}
}

// Type returns EnforcerTypeSessionCookie.
func (e *EnforcerSessionCookie) Type() EnforcerType { return EnforcerTypeSessionCookie }

// Apply denies with ErrSessionRequired whatever goes wrong, including unavailable keys, so a client learns
// nothing about the cause. Keys configured by path are read on the first request, not at start-up.
func (e *EnforcerSessionCookie) Apply(ctx Context, next HandlerFunc) {
	keys, err := e.ensureKeys()
	if err != nil {
		ctx.Slogger().Error("session cookie keys unavailable", "error", err)
		ctx.Deny(ErrSessionRequired)
		return
	}
	c, err := ctx.Request().Cookie(e.CookieName)
	if err != nil {
		ctx.Deny(ErrSessionRequired)
		return
	}
	identity, _, ok := OpenSessionCookie(c.Value, keys)
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

// ensureKeys loads the keys from the configured paths on the first request, when none were injected (the JSON and
// Caddyfile path). It is no sync.Once, which would keep a failed read for good: a key file mounted after the start is
// picked up by the next request.
func (e *EnforcerSessionCookie) ensureKeys() ([][]byte, error) {
	e.keysMu.Lock()
	defer e.keysMu.Unlock()
	if len(e.keys) > 0 {
		return e.keys, nil
	}
	if e.KeyPath == "" {
		return nil, errors.New("no session cookie key configured")
	}
	k, err := loadSessionCookieKey(e.KeyPath)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{k}
	if e.PrevKeyPath != "" {
		p, err := loadSessionCookieKey(e.PrevKeyPath)
		if err != nil {
			return nil, err
		}
		keys = append(keys, p)
	}
	e.keys = keys
	return keys, nil
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
