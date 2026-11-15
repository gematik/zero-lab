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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionTokenSet(t *testing.T) {
	s := &Session{ID: "x"}
	if _, ok := s.GetTokens("https://as"); ok {
		t.Fatal("empty session should have no tokens")
	}
	s.SetTokens("https://as", &TokenEntry{AccessToken: "at", RefreshToken: "rt", ExpiresAt: time.Unix(100, 0)})
	got, ok := s.GetTokens("https://as")
	if !ok || got.AccessToken != "at" || got.RefreshToken != "rt" {
		t.Fatalf("got %+v, ok=%v", got, ok)
	}
}

func TestSessionRotate(t *testing.T) {
	store := newSessionManager(newMemorySessions(), time.Hour, nil)
	sess := store.create()
	sess.Identity = map[string]any{"sub": "u1"}
	if err := store.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	oldID, createdAt := sess.ID, sess.CreatedAt

	if err := store.rotate(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	if sess.ID == oldID {
		t.Fatal("rotate did not change the id")
	}
	if !sess.CreatedAt.Equal(createdAt) {
		t.Error("rotate changed CreatedAt (absolute cap would reset)")
	}
	if _, err := store.byID(t.Context(), oldID); err == nil {
		t.Error("old id still resolves after rotate (fixation not closed)")
	}
	got, err := store.byID(t.Context(), sess.ID)
	if err != nil {
		t.Fatalf("new id does not resolve: %v", err)
	}
	if got.Identity["sub"] != "u1" {
		t.Error("rotated session lost its identity")
	}
}

func TestSessionAbsoluteTimeout(t *testing.T) {
	store := newSessionManager(newMemorySessions(), time.Hour, nil)
	store.maxLifetime = time.Hour
	sess := store.create()
	sess.CreatedAt = time.Now().Add(-2 * time.Hour) // past the absolute cap, idle TTL notwithstanding
	if err := store.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	if _, err := store.byID(t.Context(), sess.ID); err == nil {
		t.Fatal("session past max lifetime still resolves")
	}
	if store.store.(*memorySessions).holds(sess.ID) {
		t.Error("expired session not garbage-collected on access")
	}
}

// RFC 9700 Section 2.1: the state is a one-time use CSRF token.
func TestRFC9700_2_1_SessionStateSingleUse(t *testing.T) {
	store := newSessionManager(newMemorySessions(), time.Hour, nil)
	sess := store.create()
	sess.State = "s-123"
	if err := store.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	if _, err := store.byState(t.Context(), "s-123"); err != nil {
		t.Fatalf("state should resolve before consumption: %v", err)
	}
	store.deleteState(t.Context(), "s-123")
	if _, err := store.byState(t.Context(), "s-123"); err == nil {
		t.Error("state still resolves after deleteState (replayable)")
	}
	if _, err := store.byID(t.Context(), sess.ID); err != nil {
		t.Errorf("session itself lost after state consumption: %v", err)
	}
}

func TestSessionStoreTokenHashing(t *testing.T) {
	m := newSessionManager(newMemorySessions(), time.Hour, nil)
	sess := m.create()
	if sess.token == "" {
		t.Fatal("no cookie token generated")
	}
	if sess.ID == sess.token {
		t.Fatal("stored id equals the cookie token — a store reader would learn live cookies")
	}
	if sess.ID != hashToken(sess.token) {
		t.Fatal("id is not hashToken(token)")
	}
	if err := m.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	got, err := m.byToken(t.Context(), sess.token)
	if err != nil || got.ID != sess.ID {
		t.Fatalf("byToken: %v", err)
	}
	if m.store.(*memorySessions).holds(sess.token) {
		t.Fatal("record is reachable using the raw token as the key")
	}
}

// Server rules 5 and 14: a record that opens but names another session is refused, and logged at error level, as
// it can mean tampering with the store.
func TestServerRule5_ARecordNamingAnotherSessionIsRefusedAndLoggedAtErrorLevel(t *testing.T) {
	var logs bytes.Buffer
	store := newMemorySessions()
	store.put("slot", []byte(`{"id":"other"}`))
	m := newSessionManager(store, time.Hour, slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := m.byID(t.Context(), "slot"); !errors.Is(err, errSessionMismatch) {
		t.Fatalf("got %v, want errSessionMismatch", err)
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("not logged at error level: %q", logs.String())
	}
}

// unopenableSessions holds records that do not open, as a sealed store whose records were tampered with.
type unopenableSessions struct{ *memorySessions }

func (unopenableSessions) Load(context.Context, string) (*Session, error) {
	return nil, errors.New("record failed its integrity check")
}

// Server rule 14: a record that does not open is an invalid session for the user, who can log in again.
func TestServerRule14_ASessionThatDoesNotLoadIsAnInvalidSession(t *testing.T) {
	cfg := testConfig(&fakeBackend{})
	store := unopenableSessions{newMemorySessions()}
	cfg.Sessions = store
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.create()
	sess.Identity = map[string]any{"sub": "u1"}
	if err := s.sessions.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/oauth2/auth", "/oauth2/userinfo", "/oauth2/poll"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", path, rec.Code)
		}
	}
}
