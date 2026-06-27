package proxy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestSessionStoreEncryptsAtRest(t *testing.T) {
	store := kv.NewMemory()
	m := newSessionStore(store, time.Hour)
	c, _ := newAESRecordCrypter(testKey(3))
	m.crypter = c

	sess := m.create()
	sess.Identity = map[string]any{"sub": "u1"}
	sess.RefreshToken = "rt-super-secret"
	if err := m.save(sess); err != nil {
		t.Fatal(err)
	}

	// What a rogue storage admin sees must be ciphertext, not plaintext JSON.
	raw, found, _ := store.Get(context.Background(), sessionKey(sess.ID))
	if !found {
		t.Fatal("record not stored")
	}
	if bytes.Contains(raw, []byte("rt-super-secret")) {
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
	raw[len(raw)-1] ^= 0xff
	if err := store.SetMany(context.Background(), kv.Entry{Key: sessionKey(sess.ID), Value: raw, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.byID(sess.ID); !errors.Is(err, errRecordIntegrity) {
		t.Errorf("tampered record not rejected with errRecordIntegrity: %v", err)
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
