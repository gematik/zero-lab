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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/pep/proxy"
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

// sealedSessions are sessions on a sealed store, with the store beneath it, where a rogue storage admin reads
// and writes.
func sealedSessions(t *testing.T) (kvSessions, kv.Store) {
	t.Helper()
	raw := kv.NewMemory()
	return newKVSessions(kv.NewSealed(raw, testRing(t, 3), sessionStorePurpose)), raw
}

// Server rule 5: the store sees ciphertext only, and records cannot be swapped into another context.
func TestServerRule5_SessionStoreEncryptsAtRest(t *testing.T) {
	m, raw := sealedSessions(t)
	sess := &proxy.Session{ID: "session-a", Identity: map[string]any{"sub": "u1"}, RefreshToken: "rt-super-secret"}
	if err := m.Save(t.Context(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	stored, found, _ := raw.Get(t.Context(), sessionKey(sess.ID))
	if !found {
		t.Fatal("record not stored")
	}
	if bytes.Contains(stored, []byte("rt-super-secret")) {
		t.Fatal("kv record contains plaintext (not encrypted at rest)")
	}

	got, err := m.Load(t.Context(), sess.ID)
	if err != nil {
		t.Fatalf("Load round-trip: %v", err)
	}
	if got.RefreshToken != "rt-super-secret" || got.Identity["sub"] != "u1" {
		t.Errorf("round-trip lost data: %+v", got)
	}

	stored[len(stored)-1] ^= 0xff
	if err := raw.Set(t.Context(), sessionKey(sess.ID), stored, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(t.Context(), sess.ID); !errors.Is(err, kv.ErrIntegrity) {
		t.Errorf("tampered record not rejected with ErrIntegrity: %v", err)
	}
}

// A rogue storage admin copies session A's record onto session B's key.
func TestServerRule5_SessionStoreRejectsARecordCopiedOntoAnotherSession(t *testing.T) {
	m, raw := sealedSessions(t)
	if err := m.Save(t.Context(), &proxy.Session{ID: "session-a", Identity: map[string]any{"sub": "victim"}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	stored, _, _ := raw.Get(t.Context(), sessionKey("session-a"))
	if err := raw.Set(t.Context(), sessionKey("session-b"), stored, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(t.Context(), "session-b"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// Server rule 5: a record sealed under another key does not open.
func TestServerRule5_SessionStoreRejectsARecordUnderTheWrongKey(t *testing.T) {
	m, raw := sealedSessions(t)
	if err := m.Save(t.Context(), &proxy.Session{ID: "session-a"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	other := newKVSessions(kv.NewSealed(raw, testRing(t, 9), sessionStorePurpose))
	if _, err := other.Load(t.Context(), "session-a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// The state index is sealed as well, so a storage admin cannot repoint a login state to another session.
func TestServerRule5_SessionStoreRejectsARepointedLoginState(t *testing.T) {
	m, raw := sealedSessions(t)
	if err := m.Save(t.Context(), &proxy.Session{ID: "session-a", State: "state-a"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(t.Context(), stateKey("state-a"), []byte(`"session-b"`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SessionID(t.Context(), "state-a"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// Server rule 14: a record that no longer opens (after the upgrade to sealed records, or after tampering) is
// an error-level event for the operator; the proxy treats it as an invalid session.
func TestServerRule14_AnIntegrityFailureIsLoggedAtErrorLevel(t *testing.T) {
	m, raw := sealedSessions(t)
	if err := raw.Set(t.Context(), sessionKey("session-a"), []byte(`{"id":"session-a","identity":{"sub":"forged"}}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	if s, err := m.Load(t.Context(), "session-a"); err == nil {
		t.Fatalf("served the unsealed record: %+v", s)
	}
	if !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("not logged at error level: %q", logs.String())
	}
}

// Server rule 10: a kv key is in clear even in a sealed store, so it holds a hash of the login state.
func TestServerRule10_AStateKeyHoldsNoState(t *testing.T) {
	memory := kv.NewMemory()
	m := newKVSessions(memory)
	sess := &proxy.Session{ID: "session-a", State: "login-state-value"}
	if err := m.Save(t.Context(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	keys, err := memory.Keys(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 2 {
		t.Fatalf("keys = %v", keys)
	}
	for _, key := range keys {
		if strings.Contains(key, sess.State) {
			t.Errorf("key %q holds the state", key)
		}
	}
	if id, err := m.SessionID(t.Context(), sess.State); err != nil || id != sess.ID {
		t.Errorf("not found again: %q %v", id, err)
	}
}

// The keys stay those of before, so sessions stored by an earlier release are found.
func TestKVSessions_KeepTheirKeys(t *testing.T) {
	memory := kv.NewMemory()
	if err := newKVSessions(memory).Save(t.Context(), &proxy.Session{ID: "id-1", State: "st"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"pep:session:id-1", "pep:state:" + base64.RawURLEncoding.EncodeToString(sha256Of("st"))} {
		if _, found, _ := memory.Get(t.Context(), key); !found {
			t.Errorf("no %s", key)
		}
	}
}

// A store's error text reaches pages and logs, so the lookups' errors name neither the ID nor the state.
func TestServerRule14_SessionLookupErrorsNameNeitherIDNorState(t *testing.T) {
	m := newKVSessions(kv.NewMemory())
	if _, err := m.Load(context.Background(), "session-id-value"); !errors.Is(err, proxy.ErrSessionNotFound) || strings.Contains(err.Error(), "session-id-value") {
		t.Errorf("err = %v", err)
	}
	if _, err := m.SessionID(context.Background(), "state-value"); !errors.Is(err, proxy.ErrSessionNotFound) || strings.Contains(err.Error(), "state-value") {
		t.Errorf("err = %v", err)
	}
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
