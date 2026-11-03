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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

type fakeBackend struct{ identity map[string]any }

func (f *fakeBackend) Providers(_ context.Context) ([]Provider, error) {
	return []Provider{{Issuer: "https://idp.example", Name: "Test IdP", Type: "oidc"}}, nil
}
func (f *fakeBackend) DefaultIssuer() string { return "https://idp.example" }
func (f *fakeBackend) StartLogin(_ context.Context, sess *Session, _, _ string) (LoginStart, error) {
	sess.IDPIss = "https://idp.example"
	sess.State = "test-state"
	sess.CodeVerifier = "verifier"
	return LoginStart{AuthURL: "https://idp.example/authorize?state=test-state", Mode: "redirect"}, nil
}

func (f *fakeBackend) Complete(_ context.Context, sess *Session, _ string) error {
	sess.Identity = f.identity
	return nil
}

func (f *fakeBackend) FreshAccessToken(_ context.Context, _ *Session) (string, error) {
	return "", nil
}

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
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil))
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
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
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
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=%2Fdashboard", nil))

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

	req := httptest.NewRequest(http.MethodPost, "/oauth2/sign_out", nil)
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("sign_out = %d, want 204", rec.Code)
	}
	if _, err := s.sessions.byID(sess.ID); err == nil {
		t.Error("session not deleted on sign_out")
	}
}

func TestSignOut_POSTRequiresCSRF(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth2/sign_out", nil))
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

func captureDebugLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// Server rules 5 and 14. A session's ID is the hash of its cookie, and it names the session's record, the revocation
// entry and the snapshot's sid, so it stays out of the log as well as the cookie does.
func TestALoginLogsNoSessionIDNorCookieNorStateAtDebug(t *testing.T) {
	logs := captureDebugLogs(t)
	s := newTestServer(t)

	start := httptest.NewRecorder()
	s.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oauth2/start?idp_iss=https://idp.example", nil))
	var started *http.Cookie
	for _, c := range start.Result().Cookies() {
		if strings.Contains(c.Name, "TEST-SID") {
			started = c
		}
	}
	if started == nil {
		t.Fatalf("no session cookie: %d", start.Code)
	}

	callback := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&code=code-value", nil)
	callback.AddCookie(&http.Cookie{Name: started.Name, Value: started.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	done := httptest.NewRecorder()
	s.Handler().ServeHTTP(done, callback)
	if done.Code != http.StatusFound {
		t.Fatalf("callback = %d: %s", done.Code, done.Body)
	}
	secrets := []string{started.Value, hashToken(started.Value), "test-state", "code-value", "verifier"}
	for _, c := range done.Result().Cookies() {
		if strings.Contains(c.Name, "TEST-SID") {
			secrets = append(secrets, c.Value, hashToken(c.Value))
		}
	}
	for _, value := range secrets {
		if strings.Contains(logs.String(), value) {
			t.Errorf("the log holds %q:\n%s", value, logs)
		}
	}
	if !strings.Contains(logs.String(), "login complete") {
		t.Errorf("the login went unlogged:\n%s", logs)
	}
}

// failingBus and failingStore make the revoker log why a revocation did not get out.
type failingBus struct{ kv.Bus }

func (failingBus) Subscribe(context.Context, string) (<-chan string, error) {
	return nil, errors.New("no bus")
}
func (failingBus) Publish(context.Context, string, string) error { return errors.New("no bus") }

type failingStore struct{ kv.Store }

func (failingStore) Set(context.Context, string, []byte, time.Duration) error {
	return errors.New("no store")
}

func TestARevocationThatFailsLogsNoSid(t *testing.T) {
	logs := captureDebugLogs(t)
	r := &busRevoker{local: newMemRevoker(time.Hour), bus: failingBus{}, store: failingStore{kv.NewMemory()}, ttl: time.Hour}
	const sid = "sid-token-hash-value"
	r.Revoke(sid)
	if !strings.Contains(logs.String(), "revocation") {
		t.Fatalf("the failure went unlogged: %s", logs)
	}
	if strings.Contains(logs.String(), sid) {
		t.Errorf("the log holds the sid: %s", logs)
	}
}

func TestLogRefCorrelatesAndRevealsNoPartOfTheID(t *testing.T) {
	id := hashToken("cookie-token")
	ref := logRef(id)
	if again := logRef(id); again != ref {
		t.Errorf("not stable: %q, %q", ref, again)
	}
	if ref == logRef(hashToken("another-token")) {
		t.Error("the same for two sessions")
	}
	if len(ref) > 16 || strings.Contains(id, ref) {
		t.Errorf("ref %q of %q", ref, id)
	}
	if logRef("") != "" {
		t.Errorf("a ref of nothing: %q", logRef(""))
	}
}

// A forwarded URI's query can carry a code, or anything else of the application behind the gate.
func TestAForwardAuthDenialLogsNoQuery(t *testing.T) {
	logs := captureDebugLogs(t)
	s := newTestServer(t)
	request := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	request.Header.Set("X-Forwarded-Uri", "/app/callback?code=code-value")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, request)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(logs.String(), "code-value") {
		t.Errorf("the log holds the query: %s", logs)
	}
	if !strings.Contains(logs.String(), "/app/callback") {
		t.Errorf("the path is gone too: %s", logs)
	}
}

// A store's error text reaches pages and logs, so a session's own lookup errors name neither the ID nor the state.
func TestSessionLookupErrorsNameNeitherIDNorState(t *testing.T) {
	store := newSessionStore(kv.NewMemory(), time.Hour)
	if _, err := store.byID("session-id-value"); err == nil || strings.Contains(err.Error(), "session-id-value") {
		t.Errorf("err = %v", err)
	}
	if _, err := store.byState("state-value"); err == nil || strings.Contains(err.Error(), "state-value") {
		t.Errorf("err = %v", err)
	}
}
