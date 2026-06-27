package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type fakeBackend struct{ identity map[string]any }

func (f *fakeBackend) Providers(ctx context.Context) ([]Provider, error) {
	return []Provider{{Issuer: "https://idp.example", Name: "Test IdP", Type: "oidc"}}, nil
}
func (f *fakeBackend) DefaultIssuer() string { return "https://idp.example" }
func (f *fakeBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	sess.IDPIss = "https://idp.example"
	sess.State = "test-state"
	sess.CodeVerifier = "verifier"
	return LoginStart{AuthURL: "https://idp.example/authorize?state=test-state", Mode: "redirect"}, nil
}
func (f *fakeBackend) Complete(ctx context.Context, sess *Session, code string) error {
	sess.Identity = f.identity
	return nil
}
func (f *fakeBackend) FreshAccessToken(ctx context.Context, sess *Session) (string, error) {
	return "", nil
}
func (f *fakeBackend) DPoPKey() jwk.Key { return nil }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{
		Backend: &fakeBackend{identity: map[string]any{
			"sub": "user-1", "email": "u@example.com", "groups": []any{"admin", "dev"},
		}},
		Store:      kv.NewMemory(),
		CookieName: "TEST-SID",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestForwardAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/auth", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/oauth2/auth no cookie = %d, want 401", rec.Code)
	}
}

func TestForwardAuth_Authenticated(t *testing.T) {
	s := newTestServer(t)
	sess := s.sessions.create()
	sess.Identity = map[string]any{"sub": "user-1", "email": "u@example.com", "groups": []any{"admin", "dev"}}
	if err := s.sessions.save(sess); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/oauth2/auth", nil)
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("/oauth2/auth authed = %d, want 202", rec.Code)
	}
	if got := rec.Header().Get("X-Auth-Request-User"); got != "user-1" {
		t.Errorf("X-Auth-Request-User = %q, want user-1", got)
	}
	if got := rec.Header().Get("X-Auth-Request-Email"); got != "u@example.com" {
		t.Errorf("X-Auth-Request-Email = %q", got)
	}
	if got := rec.Header().Get("X-Auth-Request-Groups"); got != "admin,dev" {
		t.Errorf("X-Auth-Request-Groups = %q, want admin,dev", got)
	}
	if rec.Header().Get("X-Auth-Request-Identity") == "" {
		t.Error("X-Auth-Request-Identity not set")
	}
}

func TestStart_RedirectsAndBindsCookie(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/oauth2/start?rd=%2Fdashboard", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("/oauth2/start = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://idp.example/authorize?state=test-state" {
		t.Errorf("Location = %q", loc)
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == s.cookie.Name {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie set")
	}
	sess, err := s.sessions.byState("test-state")
	if err != nil {
		t.Fatalf("session not persisted by state: %v", err)
	}
	// The cookie carries the token; the kv record is stored under hashToken(token).
	if sess.ID != hashToken(sid) || sess.ReturnTo != "/dashboard" {
		t.Errorf("session id/return-to mismatch: id=%s cookie=%s rd=%q", sess.ID, sid, sess.ReturnTo)
	}
}

func TestSignOut_ClearsSession(t *testing.T) {
	s := newTestServer(t)
	sess := s.sessions.create()
	sess.Identity = map[string]any{"sub": "x"}
	_ = s.sessions.save(sess)

	req := httptest.NewRequest("POST", "/oauth2/sign_out", nil)
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("sign_out = %d, want 204", rec.Code)
	}
	if _, err := s.sessions.byID(sess.ID); err == nil {
		t.Error("session not deleted on sign_out")
	}
	if rec.Header().Get("X-Requested-With") == "" { // sanity that header path was taken
	}
}

func TestSignOut_POSTRequiresCSRF(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/oauth2/sign_out", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sign_out POST without X-Requested-With = %d, want 403", rec.Code)
	}
}

func TestSanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/dashboard": "/dashboard", "/a?b=c": "/a?b=c",
		"//evil.example": "", "https://evil.example": "", "/\\evil": "", "": "",
		// returns into pep's own auth endpoints are rejected — they are how the rd loop grows
		"/oauth2/start?rd=/oauth2/start?rd=/": "", "/oauth2/start": "", "/oauth2": "",
		"/oauth2callback": "/oauth2callback", "/foo/../oauth2/start": "",
	}
	for in, want := range cases {
		if got := sanitizeReturnTo(in); got != want {
			t.Errorf("sanitizeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
