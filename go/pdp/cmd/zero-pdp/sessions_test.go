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
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/openid"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

func testKeyring(t *testing.T) *kv.Keyring {
	t.Helper()
	ring, err := kv.ParseKeyring([]byte("k1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// After the upgrade an old record does not open, and it may also mean tampering: the client sees a session that
// does not exist, not a server error, and the log has it at error level.
func TestSessionLookup_ARecordThatDoesNotOpenIsAnInvalidSessionAndLogged(t *testing.T) {
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testKeyring(t), "test")
	sessions := newKVSessionStore(sealed, time.Hour)
	ctx := t.Context()
	if err := sessions.SaveAutzhServerSession(&authzserver.Session{
		ID: "s1", Code: "c1", RequestURI: "r1", RefreshToken: "t1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(ctx, asSessionKey("s1"), []byte(`{"id":"s1"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(ctx, asRefreshKey("t2"), []byte(`"s1"`), time.Hour); err != nil {
		t.Fatal(err)
	}

	lookups := map[string]func() (*authzserver.Session, error){
		"record by id":          func() (*authzserver.Session, error) { return sessions.GetAuthzServerSessionByID("s1") },
		"record behind a code":  func() (*authzserver.Session, error) { return sessions.GetAuthzServerSessionByCode("c1") },
		"record behind a uri":   func() (*authzserver.Session, error) { return sessions.GetAutzhServerSessionByRequestURI("r1") },
		"index in the clear":    func() (*authzserver.Session, error) { return sessions.GetAuthzServerSessionByRefreshToken("t2") },
		"index behind a secret": func() (*authzserver.Session, error) { return sessions.GetAuthzServerSessionByRefreshToken("t1") },
	}
	for name, lookup := range lookups {
		logs := captureLogs(t)
		if _, err := lookup(); !errors.Is(err, authzserver.ErrSessionNotFound) {
			t.Errorf("%s: got %v", name, err)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("%s: not logged at error level: %q", name, logs)
		}
	}
}

// Server rule 5: the store sees ciphertext only.
func TestServerRule5_SessionRecordsReachASealedStoreAsCiphertext(t *testing.T) {
	raw := kv.NewMemory()
	sessions := newKVSessionStore(kv.NewSealed(raw, testKeyring(t), "test"), time.Hour)
	if err := sessions.SaveAutzhServerSession(&authzserver.Session{ID: "s1", RefreshToken: "refresh-secret", Code: "code-secret"}); err != nil {
		t.Fatal(err)
	}
	stored, found, err := raw.Get(t.Context(), asSessionKey("s1"))
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if bytes.Contains(stored, []byte("refresh-secret")) || bytes.Contains(stored, []byte("code-secret")) {
		t.Fatal("the store holds the session in the clear")
	}
	got, err := sessions.GetAuthzServerSessionByID("s1")
	if err != nil || got.RefreshToken != "refresh-secret" {
		t.Fatalf("%+v %v", got, err)
	}
}

// Server rule 10: a kv key is in clear even in a sealed store, so it holds a hash of a secret.
func TestServerRule10_AKVKeyHoldsNoSecretOfALogin(t *testing.T) {
	memory := kv.NewMemory()
	sessions := newKVSessionStore(memory, time.Hour)
	secrets := map[string]string{"code": "client-code-value", "state": "op-state-value", "request_uri": "urn:ietf:params:oauth:request_uri:value"}
	if err := sessions.SaveAutzhServerSession(&authzserver.Session{
		ID:                 "s1",
		Code:               secrets["code"],
		RequestURI:         secrets["request_uri"],
		AuthnClientSession: &openid.AuthnClientSession{State: secrets["state"]},
	}); err != nil {
		t.Fatal(err)
	}
	keys, err := memory.Keys(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("keys = %v", keys)
	}
	for _, key := range keys {
		for name, secret := range secrets {
			if strings.Contains(key, secret) {
				t.Errorf("key %q holds the %s", key, name)
			}
		}
	}
	if _, err := sessions.GetAuthzServerSessionByCode(secrets["code"]); err != nil {
		t.Fatalf("the code does not find its session: %v", err)
	}
}
