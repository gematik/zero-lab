package bff_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
)

// Protect treats the cookie value as an opaque session ID and looks it up in the SessionManager;
// a session is authorized only once it carries an access token. (The cookie is not a self-contained
// encrypted/signed blob — that earlier design was replaced by the server-side SessionManager.)
func TestGuardSessionCookie(t *testing.T) {
	sm := bff.NewSessionManagerMock()
	session, err := sm.CreateSession("state", "verifier", "S256")
	if err != nil {
		t.Fatal(err)
	}
	session.AccessToken = "an-access-token"
	if err := sm.UpdateSession(session); err != nil {
		t.Fatal(err)
	}

	b, err := bff.New(bff.Config{
		EncryptKeyString: base64.StdEncoding.EncodeToString(bff.GenerateRandomKey(256)),
		SignKeyString:    base64.StdEncoding.EncodeToString(bff.GenerateRandomKey(256)),
		CookieName:       "test-cookie",
		SessionManager:   sm,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(b.Protect(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("You are in"))
	}))
	defer server.Close()

	do := func(cookieValue string) int {
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: "test-cookie", Value: cookieValue})
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	// valid, authorized session id → allowed
	if code := do(session.ID); code != http.StatusOK {
		t.Fatalf("valid session: expected %d, got %d", http.StatusOK, code)
	}
	// unknown session id → rejected
	if code := do("nonexistent-session-id"); code != http.StatusUnauthorized {
		t.Fatalf("unknown session: expected %d, got %d", http.StatusUnauthorized, code)
	}
}
