package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func writeKeyFile(t *testing.T, name string) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSnapshotMintOpen(t *testing.T) {
	snap, err := newSnapshotter(writeKeyFile(t, "key"), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := snap.mint("sid-1", map[string]any{"sub": "u1", "email": "u@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := snap.open(tok)
	if !ok {
		t.Fatal("open failed for a valid snapshot")
	}
	if c.SID != "sid-1" || c.Identity["email"] != "u@example.com" {
		t.Errorf("claims = %+v", c)
	}
}

func TestSnapshotExpired(t *testing.T) {
	snap, _ := newSnapshotter(writeKeyFile(t, "key"), "", -time.Minute) // already expired
	tok, _ := snap.mint("sid", map[string]any{"sub": "u"})
	if _, ok := snap.open(tok); ok {
		t.Error("expired snapshot opened")
	}
}

func TestSnapshotWrongKeyAndTamper(t *testing.T) {
	a, _ := newSnapshotter(writeKeyFile(t, "a"), "", time.Hour)
	b, _ := newSnapshotter(writeKeyFile(t, "b"), "", time.Hour)
	tok, _ := a.mint("sid", map[string]any{"sub": "u"})
	if _, ok := b.open(tok); ok {
		t.Error("snapshot opened with the wrong key")
	}
	if _, ok := a.open(tok[:len(tok)-2] + "xy"); ok {
		t.Error("tampered snapshot opened (AEAD should reject)")
	}
}

func TestSnapshotRotationPreviousKey(t *testing.T) {
	oldPath, newPath := writeKeyFile(t, "old"), writeKeyFile(t, "new")
	oldSnap, _ := newSnapshotter(oldPath, "", time.Hour)
	tok, _ := oldSnap.mint("sid", map[string]any{"sub": "u"})
	// After rotation: primary = new, previous = old → a token minted with the old key still opens.
	rotated, _ := newSnapshotter(newPath, oldPath, time.Hour)
	if _, ok := rotated.open(tok); !ok {
		t.Error("snapshot minted with the previous key should still open during rotation")
	}
}

func TestSnapshotDisabledWhenNoKey(t *testing.T) {
	snap, err := newSnapshotter("", "", time.Hour)
	if err != nil || snap != nil {
		t.Errorf("no key path should yield a nil snapshotter, got snap=%v err=%v", snap, err)
	}
}

func TestMemRevoker(t *testing.T) {
	r := newMemRevoker(time.Hour)
	if r.IsRevoked("a") {
		t.Error("not revoked yet")
	}
	r.Revoke("a")
	if !r.IsRevoked("a") {
		t.Error("should be revoked")
	}
	expired := newMemRevoker(-time.Minute)
	expired.Revoke("b")
	if expired.IsRevoked("b") {
		t.Error("expired revocation entry should self-evict")
	}
}

// TestForwardAuth_SnapshotFastPath proves /oauth2/auth authenticates from the snapshot cookie alone — there
// is NO session in kv — so the fast path never touches the store; and that revocation flips it to 401.
func TestForwardAuth_SnapshotFastPath(t *testing.T) {
	s, err := New(Config{
		Backend:         &fakeBackend{},
		Store:           kv.NewMemory(),
		CookieName:      "TEST-SID",
		SnapshotKeyPath: writeKeyFile(t, "key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.snap.mint("sid-x", map[string]any{"sub": "user-1", "email": "u@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	newReq := func() *http.Request {
		req := httptest.NewRequest("GET", "/oauth2/auth", nil)
		req.AddCookie(&http.Cookie{Name: s.snapCookie.Name, Value: tok})
		return req
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, newReq())
	if rec.Code != http.StatusAccepted {
		t.Fatalf("snapshot fast path = %d, want 202 (no kv session exists)", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Request-User"); got != "user-1" {
		t.Errorf("X-Auth-Request-User = %q, want user-1", got)
	}

	s.revoker.Revoke("sid-x")
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, newReq())
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("revoked snapshot = %d, want 401", rec2.Code)
	}
}
