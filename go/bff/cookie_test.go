package bff_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/gematik/zero-lab/go/kv"
)

// Protect treats the cookie value as an opaque session id and looks it up in the SessionManager; the
// session is authorized only once it carries an access token.
func TestGuardSessionCookie(t *testing.T) {
	sm := bff.NewSessionManager(kv.NewMemory(), 0)
	session, err := sm.CreateSession("state", "verifier", "S256")
	if err != nil {
		t.Fatal(err)
	}
	session.AccessToken = "an-access-token"
	if err := sm.UpdateSession(session); err != nil {
		t.Fatal(err)
	}

	b := newTestBFF(t, sm)
	protected := b.Protect(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("You are in"))
	})

	do := func(cookieValue string) int {
		req := httptest.NewRequest("GET", "/protected", nil)
		if cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: "test-cookie", Value: cookieValue})
		}
		rec := httptest.NewRecorder()
		protected(rec, req)
		return rec.Code
	}

	if code := do(session.ID); code != http.StatusOK {
		t.Fatalf("valid session: expected %d, got %d", http.StatusOK, code)
	}
	if code := do("nonexistent-session-id"); code != http.StatusUnauthorized {
		t.Fatalf("unknown session: expected %d, got %d", http.StatusUnauthorized, code)
	}
}
