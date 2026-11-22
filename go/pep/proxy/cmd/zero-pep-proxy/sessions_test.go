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
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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
	if _, err := m.TakeSessionID(t.Context(), "state-a"); !errors.Is(err, kv.ErrIntegrity) {
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
	if id, err := m.TakeSessionID(t.Context(), sess.State); err != nil || id != sess.ID {
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
	if _, err := m.TakeSessionID(context.Background(), "state-value"); !errors.Is(err, proxy.ErrSessionNotFound) || strings.Contains(err.Error(), "state-value") {
		t.Errorf("err = %v", err)
	}
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// sessionRecordBeforeV2 is a record as encoding/json v1 wrote it, with every member set; sessions in a running store
// look like this after an upgrade.
const sessionRecordBeforeV2 = `{"id":"session-a","idp_iss":"https://idp.example","state":"st","nonce":"n","code_verifier":"cv","code_challenge_method":"S256","access_token":"at","refresh_token":"rt","access_token_expires_at":"2026-11-01T12:00:00Z","identity":{"acr":"x\u0026y","n":1.5,"sub":"u1"},"return_to":"/r","created_at":"2026-11-01T12:00:00Z","tokens":{"https://as.example":{"access_token":"a","refresh_token":"r","expires_at":"2026-11-01T12:00:00Z"}},"dpop_key_jwk":"eyJrdHkiOiJFQyJ9"}`

func TestSessionRecordWrittenBeforeV2StillOpens(t *testing.T) {
	m := newKVSessions(kv.NewMemory())
	for id, record := range map[string]string{
		"session-a": sessionRecordBeforeV2,
		"session-b": `{"id":"session-b","state":"","nonce":"","code_verifier":"","code_challenge_method":"","access_token_expires_at":"0001-01-01T00:00:00Z","created_at":"2026-11-01T12:00:00Z"}`,
	} {
		if err := m.store.SetMany(t.Context(), kv.Entry{Key: sessionKey(id), Value: []byte(record), TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
		got, err := m.Load(t.Context(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got.ID != id {
			t.Fatalf("%s: id = %q", id, got.ID)
		}
	}
	got, err := m.Load(t.Context(), "session-a")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := got.GetTokens("https://as.example")
	if got.Identity["acr"] != "x&y" || got.RefreshToken != "rt" || string(got.DPoPKeyJWK) != `{"kty":"EC"}` || !ok || entry.AccessToken != "a" {
		t.Fatalf("session = %+v", got)
	}
}

// A record written now holds the members and values v1 wrote, so a replica not yet upgraded opens it.
func TestSessionRecordIsWrittenAsBeforeV2(t *testing.T) {
	s, err := decodeSession([]byte(sessionRecordBeforeV2))
	if err != nil {
		t.Fatal(err)
	}
	m := newKVSessions(kv.NewMemory())
	if err := m.Save(t.Context(), s, time.Hour); err != nil {
		t.Fatal(err)
	}
	record, found, err := m.store.Get(t.Context(), sessionKey(s.ID))
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(record, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(sessionRecordBeforeV2), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record = %s\nwant     %s", record, sessionRecordBeforeV2)
	}
}

func TestServerRule28_SessionRecordIsReadExactly(t *testing.T) {
	for name, c := range map[string]struct {
		record string
		want   error
	}{
		"member twice":         {`{"id":"a","id":"b"}`, jsontext.ErrDuplicateName},
		"name in another case": {`{"ID":"a"}`, json.ErrUnknownName},
		"unknown member":       {`{"id":"a","admin":true}`, json.ErrUnknownName},
		"nested member twice":  {`{"id":"a","identity":{"sub":"u","sub":"v"}}`, jsontext.ErrDuplicateName},
	} {
		if _, err := decodeSession([]byte(c.record)); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	if _, err := decodeSession([]byte("{\"id\":\"a\",\"identity\":{\"sub\":\"\xff\"}}")); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("not UTF-8: err = %v", err)
	}
}

func FuzzDecodeSession(f *testing.F) {
	f.Add([]byte(sessionRecordBeforeV2))
	f.Add([]byte(`{"id":"a","id":"b"}`))
	f.Add([]byte(`{"ID":"a"}`))
	f.Add([]byte("{\"id\":\"a\",\"identity\":{\"sub\":\"\xff\"}}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := decodeSession(data)
		if err != nil {
			return
		}
		record, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeSession(record); err != nil {
			t.Fatalf("an accepted record does not read back: %v", err)
		}
	})
}

// Server rule 11: over the kv store, two replicas that take the same login state at once get the session ID once.
func TestServerRule11_TwoReplicasTakeALoginStateOnceOverTheKVStore(t *testing.T) {
	shared := kv.NewMemory()
	first, second := newKVSessions(shared), newKVSessions(shared)
	if err := first.Save(t.Context(), &proxy.Session{ID: "session-a", State: "login-state"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	var taken atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		replica := first
		if i%2 == 1 {
			replica = second
		}
		wg.Go(func() {
			if id, err := replica.TakeSessionID(t.Context(), "login-state"); err == nil && id == "session-a" {
				taken.Add(1)
			}
		})
	}
	wg.Wait()
	if got := taken.Load(); got != 1 {
		t.Errorf("taken %d times, want 1", got)
	}
}
