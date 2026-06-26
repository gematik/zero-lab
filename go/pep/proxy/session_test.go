package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

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
