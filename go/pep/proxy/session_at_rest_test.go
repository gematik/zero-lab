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

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func testRing(t *testing.T, b byte) *kv.Keyring {
	t.Helper()
	line := "k1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) + "\n"
	ring, err := kv.ParseKeyring([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// sealedSessions is a session store on a sealed store, with the store beneath it, where a rogue storage admin
// reads and writes.
func sealedSessions(t *testing.T) (*sessionStore, kv.Store) {
	t.Helper()
	raw := kv.NewMemory()
	return newSessionStore(kv.NewSealed(raw, testRing(t, 3), "pep/session"), time.Hour), raw
}

func TestSessionStoreEncryptsAtRest(t *testing.T) {
	m, raw := sealedSessions(t)
	sess := m.create()
	sess.Identity = map[string]any{"sub": "u1"}
	sess.RefreshToken = "rt-super-secret"
	if err := m.save(sess); err != nil {
		t.Fatal(err)
	}

	// What a rogue storage admin sees must be ciphertext, not plaintext JSON.
	stored, found, _ := raw.Get(context.Background(), sessionKey(sess.ID))
	if !found {
		t.Fatal("record not stored")
	}
	if bytes.Contains(stored, []byte("rt-super-secret")) {
		t.Fatal("kv record contains plaintext (not encrypted at rest)")
	}

	got, err := m.byID(sess.ID)
	if err != nil {
		t.Fatalf("byID round-trip: %v", err)
	}
	if got.RefreshToken != "rt-super-secret" || got.Identity["sub"] != "u1" {
		t.Errorf("round-trip lost data: %+v", got)
	}

	// A tampered record is rejected as an integrity failure, not silently decoded.
	stored[len(stored)-1] ^= 0xff
	if err := raw.Set(context.Background(), sessionKey(sess.ID), stored, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.byID(sess.ID); !errors.Is(err, kv.ErrIntegrity) {
		t.Errorf("tampered record not rejected with ErrIntegrity: %v", err)
	}
}

// A rogue storage admin copies session A's record onto session B's key.
func TestSessionStoreRejectsARecordCopiedOntoAnotherSession(t *testing.T) {
	m, raw := sealedSessions(t)
	a := m.create()
	a.Identity = map[string]any{"sub": "victim"}
	if err := m.save(a); err != nil {
		t.Fatal(err)
	}
	stored, _, _ := raw.Get(context.Background(), sessionKey(a.ID))
	if err := raw.Set(context.Background(), sessionKey("session-b"), stored, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.byID("session-b"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSessionStoreRejectsARecordUnderTheWrongKey(t *testing.T) {
	m, raw := sealedSessions(t)
	sess := m.create()
	if err := m.save(sess); err != nil {
		t.Fatal(err)
	}
	other := newSessionStore(kv.NewSealed(raw, testRing(t, 9), "pep/session"), time.Hour)
	if _, err := other.byID(sess.ID); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// The state index is sealed as well, so a storage admin cannot repoint a login state to another session.
func TestSessionStoreRejectsARepointedLoginState(t *testing.T) {
	m, raw := sealedSessions(t)
	a := m.create()
	a.State = "state-a"
	if err := m.save(a); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(context.Background(), stateKey("state-a"), []byte(`"session-b"`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.byState("state-a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// A record that opens but names another session is refused too, as the distinct integrity failure.
func TestSessionStoreRejectsARecordNamingAnotherSession(t *testing.T) {
	store := kv.NewMemory()
	m := newSessionStore(store, time.Hour)
	if err := store.Set(context.Background(), sessionKey("slot"), []byte(`{"id":"other"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.byID("slot"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

func TestSessionStoreTokenHashing(t *testing.T) {
	m := newSessionStore(kv.NewMemory(), time.Hour)
	sess := m.create()
	if sess.token == "" {
		t.Fatal("no cookie token generated")
	}
	if sess.ID == sess.token {
		t.Fatal("kv id equals the cookie token — a kv reader would learn live cookies")
	}
	if sess.ID != hashToken(sess.token) {
		t.Fatal("id is not hashToken(token)")
	}
	if err := m.save(sess); err != nil {
		t.Fatal(err)
	}
	// currentSession resolves via the token; the raw token must not be usable as a kv key.
	got, err := m.byToken(sess.token)
	if err != nil || got.ID != sess.ID {
		t.Fatalf("byToken: %v", err)
	}
	if _, found, _ := m.store.Get(context.Background(), sessionKey(sess.token)); found {
		t.Fatal("record is reachable using the raw token as the kv key")
	}
}

// A record that no longer opens (after the upgrade to sealed records, or after tampering) is an invalid session
// for the user, who can log in again, and an error-level event for the operator.
func TestAnIntegrityFailureIsAnInvalidSessionAndLoggedAtErrorLevel(t *testing.T) {
	raw := kv.NewMemory()
	s, err := New(Config{Backend: &fakeBackend{}, Store: kv.NewSealed(raw, testRing(t, 3), "pep/session")})
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.create()
	sess.Identity = map[string]any{"sub": "u1"}
	if err := s.sessions.save(sess); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(context.Background(), sessionKey(sess.ID), []byte(`{"id":"`+sess.ID+`","identity":{"sub":"forged"}}`), time.Hour); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/oauth2/auth", "/oauth2/userinfo", "/oauth2/poll"} {
		var logs bytes.Buffer
		previous := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		slog.SetDefault(previous)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "forged") {
			t.Errorf("%s: served the unsealed record", path)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("%s: not logged at error level: %q", path, logs.String())
		}
	}
}

// The revocation set recovers a sid from its key, which a sealed store leaves in the clear.
func TestBusRevokerOnASealedStoreRecoversTheSidFromItsKey(t *testing.T) {
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testRing(t, 3), "pep/session")
	r := newBusRevoker(kv.NewMemBus(), sealed, time.Hour, time.Now)
	r.Revoke("sid-x")

	stored, found, _ := raw.Get(context.Background(), revokedPrefix+"sid-x")
	if !found || bytes.Equal(stored, []byte{'1'}) {
		t.Fatalf("stored %q found=%v, want a sealed record", stored, found)
	}
	fresh := newBusRevoker(kv.NewMemBus(), sealed, time.Hour, time.Now)
	if !fresh.IsRevoked("sid-x") {
		t.Fatal("a fresh replica did not load the revocation")
	}
}

// Revocation records from before the upgrade hold a bare '1' and must still count: nothing reads their value.
func TestBusRevokerOnASealedStoreLoadsUnsealedRecordsFromBeforeTheUpgrade(t *testing.T) {
	raw := kv.NewMemory()
	if err := raw.Set(context.Background(), revokedPrefix+"sid-old", []byte{'1'}, time.Hour); err != nil {
		t.Fatal(err)
	}
	r := newBusRevoker(kv.NewMemBus(), kv.NewSealed(raw, testRing(t, 3), "pep/session"), time.Hour, time.Now)
	if !r.IsRevoked("sid-old") {
		t.Fatal("a revocation from before the upgrade was lost")
	}
}
