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
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
)

func mintTestCookie(t *testing.T, key []byte, identity map[string]any, exp int64) string {
	t.Helper()
	payload, err := json.Marshal(sessionCookieClaims{SID: "s1", Identity: identity, Expiry: exp})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT(), key), jwe.WithContentEncryption(jwa.A256GCM()))
	if err != nil {
		t.Fatal(err)
	}
	return string(enc)
}

func TestOpenSessionCookie(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	tok := mintTestCookie(t, key, map[string]any{"sub": "u1"}, time.Now().Add(time.Hour).Unix())

	id, sid, ok := OpenSessionCookie(tok, [][]byte{key})
	if !ok || id["sub"] != "u1" || sid != "s1" {
		t.Fatalf("open failed: id=%v sid=%q ok=%v", id, sid, ok)
	}
	if _, _, ok := OpenSessionCookie(tok, [][]byte{bytes.Repeat([]byte{9}, 32)}); ok {
		t.Error("opened with the wrong key")
	}
	expired := mintTestCookie(t, key, map[string]any{"sub": "u1"}, time.Now().Add(-time.Hour).Unix())
	if _, _, ok := OpenSessionCookie(expired, [][]byte{key}); ok {
		t.Error("opened an expired cookie")
	}
}

// testContext is a minimal pep.Context for exercising enforcers.
type testContext struct {
	r         *http.Request
	claimsRaw []byte
	denied    bool
	denyErr   Error
}

func (c *testContext) Writer() http.ResponseWriter           { return httptest.NewRecorder() }
func (c *testContext) Request() *http.Request                { return c.r }
func (c *testContext) Deny(err Error)                        { c.denied = true; c.denyErr = err }
func (c *testContext) WithDeny(func(Context, Error)) Context { return c }
func (c *testContext) Slogger() *slog.Logger                 { return slog.Default() }
func (c *testContext) UnmarshalClaims(v any) error           { return json.Unmarshal(c.claimsRaw, v) }
func (c *testContext) SetClaims(raw []byte)                  { c.claimsRaw = raw }

func TestEnforcerSessionCookie(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	tok := mintTestCookie(t, key, map[string]any{"sub": "u1", "scope": "read"}, time.Now().Add(time.Hour).Unix())
	enf := NewEnforcerSessionCookie("SID", [][]byte{key})

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "SID", Value: tok})
	ctx := &testContext{r: req}
	called := false
	enf.Apply(ctx, func(c Context) {
		called = true
		var claims struct {
			Sub string `json:"sub"`
		}
		if err := c.UnmarshalClaims(&claims); err != nil || claims.Sub != "u1" {
			t.Errorf("claims from cookie: sub=%q err=%v", claims.Sub, err)
		}
	})
	if !called || ctx.denied {
		t.Fatalf("valid cookie: called=%v denied=%v", called, ctx.denied)
	}

	// scope check composes on top — EnforcerScope reads the identity the cookie set.
	enf.Apply(&testContext{r: req}, func(c Context) {
		(&EnforcerScope{Scope: "read"}).Apply(c, func(Context) {})
	})

	ctx2 := &testContext{r: httptest.NewRequest("GET", "/", nil)}
	enf.Apply(ctx2, func(Context) { t.Error("next ran without a cookie") })
	if !ctx2.denied || ctx2.denyErr.HttpStatus != 401 {
		t.Errorf("missing cookie: denied=%v status=%d", ctx2.denied, ctx2.denyErr.HttpStatus)
	}
}
