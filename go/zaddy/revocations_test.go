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

package zaddy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/pep"
)

// sessionKey writes a fresh snapshot key where a SessionCookie enforcer reads it and returns it.
func sessionKey(t *testing.T) ([]byte, string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return key, path
}

// snapshot seals a session snapshot of sid the way zero-pep-proxy does (JWE dir+A256GCM).
func snapshot(t *testing.T, key []byte, sid string) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(map[string]any{"sid": sid, "id": map[string]any{"sub": "u1"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := encrypter.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sealed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// startedApp starts the app with its revocations on store and bus and stops it when the test ends.
func startedApp(t *testing.T, store kv.Store, bus kv.Bus) *App {
	t.Helper()
	a := &App{
		Resource:               "https://rs.example",
		JWKSPath:               "test_jwks.json",
		RevocationsDatabaseURL: "postgres://revocations.example/kv",
		logger:                 slog.New(slog.DiscardHandler),
		openRevocations: func(context.Context, string) (kv.Store, kv.Bus, error) {
			return store, bus, nil
		},
	}
	if err := a.loadNonceKeys(); err != nil {
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Stop(); err != nil {
			t.Error(err)
		}
	})
	return a
}

// sessionCookiePolicy is an enforce_policy handler with a SessionCookie enforcer, decoded from JSON as Caddy
// does, inside an any_of.
func sessionCookiePolicy(t *testing.T, keyPath string, app *App) EnforcePolicyMiddleware {
	t.Helper()
	var holder pep.EnforcerHolder
	raw := `{"type":"AnyOf","enforcers":[{"type":"SessionCookie","cookie_name":"SID","key_path":` + jsonString(t, keyPath) + `}]}`
	if err := holder.UnmarshalJSON([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	return EnforcePolicyMiddleware{Enforcer: &holder, logger: slog.New(slog.DiscardHandler), app: app}
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// admits reports whether the policy lets a request with the snapshot of sid through.
func admits(t *testing.T, m EnforcePolicyMiddleware, key []byte, sid string) bool {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://rs.example/app", http.NoBody)
	r.AddCookie(&http.Cookie{Name: "SID", Value: snapshot(t, key, sid)}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	reached := ""
	if err := m.ServeHTTP(httptest.NewRecorder(), r, nextRecorder{&reached}); err != nil {
		t.Fatal(err)
	}
	return reached != ""
}

// Server rule 11 (TASK-313): a session zero-pep-proxy signed out, before zaddy started or while it runs, is
// refused by zaddy's SessionCookie enforcer though its snapshot has not expired; a live session passes.
func TestServerRule11_ZaddyRefusesASignedOutSessionsSnapshot(t *testing.T) {
	store, bus := kv.NewMemory(), kv.NewMemBus()
	if err := store.Set(t.Context(), pep.SessionRevocationsKeyPrefix+"signed-out", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	key, keyPath := sessionKey(t)
	m := sessionCookiePolicy(t, keyPath, startedApp(t, store, bus))

	if !admits(t, m, key, "live") {
		t.Fatal("a live session was refused")
	}
	if admits(t, m, key, "signed-out") {
		t.Error("a session revoked before the start was admitted")
	}
	if err := bus.Publish(t.Context(), pep.SessionRevocationsChannel, "live"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for admits(t, m, key, "live") {
		if time.Now().After(deadline) {
			t.Fatal("a session revoked on the bus was still admitted")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Server rule 17: a policy with a SessionCookie enforcer, at any depth, is refused without
// revocations_database_url; with it, or without such an enforcer, it is accepted.
func TestServerRule17_ZaddyRefusesASessionCookiePolicyWithoutRevocations(t *testing.T) {
	_, keyPath := sessionKey(t)
	m := sessionCookiePolicy(t, keyPath, nil)
	if err := requireRevocations(m.Enforcer, &App{}); err == nil || !strings.Contains(err.Error(), "revocations_database_url") {
		t.Errorf("without revocations: err = %v", err)
	}
	if err := requireRevocations(m.Enforcer, &App{RevocationsDatabaseURL: "postgres://revocations.example/kv"}); err != nil {
		t.Errorf("with revocations: %v", err)
	}
	bearer := &pep.EnforcerHolder{Enforcer: &pep.EnforcerAllOf{EnforcerHolders: []pep.EnforcerHolder{{Enforcer: &pep.EnforcerAuthorizationBearer{}}}}}
	if err := requireRevocations(bearer, &App{}); err != nil {
		t.Errorf("a bearer policy: %v", err)
	}
	if err := requireRevocations((*pep.EnforcerHolder)(nil), &App{}); err != nil {
		t.Errorf("no policy: %v", err)
	}

	value, err := parseCaddyfilePEP(caddyfile.NewTestDispenser("pep {\n resource https://api.example.com\n jwks_path jwks.json\n revocations_database_url postgres://revocations.example/kv\n}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var a App
	if err := json.Unmarshal(value.(httpcaddyfile.App).Value, &a); err != nil {
		t.Fatal(err)
	}
	if a.RevocationsDatabaseURL != "postgres://revocations.example/kv" {
		t.Errorf("revocations_database_url %q", a.RevocationsDatabaseURL)
	}
	if _, err := parseCaddyfilePEP(caddyfile.NewTestDispenser("pep {\n revocations_database_url\n}"), nil); err == nil {
		t.Error("revocations_database_url without a value was accepted")
	}
}

type keylessStore struct{ kv.Store }

func (keylessStore) Keys(context.Context, string) ([]string, error) {
	return nil, errors.New("no store")
}

// Server rule 17: zaddy does not start when it cannot reach or read zero-pep-proxy's revocations, as it would
// admit sessions signed out elsewhere.
func TestServerRule17_ZaddyDoesNotStartWithoutItsRevocations(t *testing.T) {
	for name, open := range map[string]openRevocationsFunc{
		"unreachable": func(context.Context, string) (kv.Store, kv.Bus, error) {
			return nil, nil, errors.New("connection refused")
		},
		"unreadable": func(context.Context, string) (kv.Store, kv.Bus, error) {
			return keylessStore{kv.NewMemory()}, kv.NewMemBus(), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := &App{
				Resource:               "https://rs.example",
				JWKSPath:               "test_jwks.json",
				RevocationsDatabaseURL: "postgres://revocations.example/kv",
				logger:                 slog.New(slog.DiscardHandler),
				openRevocations:        open,
			}
			if err := a.loadNonceKeys(); err != nil {
				t.Fatal(err)
			}
			if err := a.Start(); err == nil {
				_ = a.Stop()
				t.Fatal("started without its revocations")
			}
		})
	}
}
