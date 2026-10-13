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
	"context"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
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
	store := newSessionStore(kv.NewMemory(), time.Hour)
	sess := store.create()
	sess.Identity = map[string]any{"sub": "u1"}
	if err := store.save(sess); err != nil {
		t.Fatal(err)
	}
	oldID, createdAt := sess.ID, sess.CreatedAt

	if err := store.rotate(sess); err != nil {
		t.Fatal(err)
	}
	if sess.ID == oldID {
		t.Fatal("rotate did not change the id")
	}
	if !sess.CreatedAt.Equal(createdAt) {
		t.Error("rotate changed CreatedAt (absolute cap would reset)")
	}
	if _, err := store.byID(oldID); err == nil {
		t.Error("old id still resolves after rotate (fixation not closed)")
	}
	got, err := store.byID(sess.ID)
	if err != nil {
		t.Fatalf("new id does not resolve: %v", err)
	}
	if got.Identity["sub"] != "u1" {
		t.Error("rotated session lost its identity")
	}
}

func TestSessionAbsoluteTimeout(t *testing.T) {
	store := newSessionStore(kv.NewMemory(), time.Hour)
	store.maxLifetime = time.Hour
	sess := store.create()
	sess.CreatedAt = time.Now().Add(-2 * time.Hour) // past the absolute cap, idle TTL notwithstanding
	if err := store.save(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := store.byID(sess.ID); err == nil {
		t.Fatal("session past max lifetime still resolves")
	}
	if _, found, _ := store.store.Get(context.Background(), sessionKey(sess.ID)); found {
		t.Error("expired session not garbage-collected on access")
	}
}

func TestSessionStateSingleUse(t *testing.T) {
	store := newSessionStore(kv.NewMemory(), time.Hour)
	sess := store.create()
	sess.State = "s-123"
	if err := store.save(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := store.byState("s-123"); err != nil {
		t.Fatalf("state should resolve before consumption: %v", err)
	}
	store.deleteState("s-123")
	if _, err := store.byState("s-123"); err == nil {
		t.Error("state still resolves after deleteState (replayable)")
	}
	if _, err := store.byID(sess.ID); err != nil {
		t.Errorf("session itself lost after state consumption: %v", err)
	}
}
