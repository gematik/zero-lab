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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	return newLoggingTestServer(t, nil)
}

func newLoggingTestServer(t *testing.T, log *slog.Logger) *Server {
	t.Helper()
	cfg := testConfig(&fakeBackend{identity: map[string]any{
		"sub": "user-1", "email": "u@example.com", "groups": []any{"admin", "dev"},
	}})
	cfg.Logger = log
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// failingBackend fails with what no browser may read.
type failingBackend struct{ fakeBackend }

const backendInternals = "as-response-body-value"

func (f *failingBackend) Providers(context.Context) ([]Provider, error) {
	return nil, errors.New(backendInternals)
}

func (f *failingBackend) StartLogin(context.Context, *Session, string, string) (LoginStart, error) {
	return LoginStart{}, errors.New(backendInternals)
}

func (f *failingBackend) Complete(_ context.Context, _ *Session, code string) error {
	return fmt.Errorf("%s, code %s", backendInternals, code)
}

// Server rule 2: uniform error responses that leak no internals.
func TestServerRule2_AFailedLoginShowsTheBrowserGenericText(t *testing.T) {
	var logs bytes.Buffer
	cfg := testConfig(&failingBackend{})
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.create()
	sess.State = "test-state"
	if err := s.sessions.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"the provider list":   "/oauth2/sign_in",
		"the login's start":   "/oauth2/start?idp_iss=https%3A%2F%2Fidp.example",
		"the code's exchange": "/oauth2/callback?state=test-state&code=code-value",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if strings.Contains(rec.Body.String(), backendInternals) || !strings.Contains(rec.Body.String(), "could") && !strings.Contains(rec.Body.String(), "not available") {
				t.Errorf("page = %d: %s", rec.Code, rec.Body)
			}
		})
	}
	if !strings.Contains(logs.String(), backendInternals) {
		t.Errorf("the detail is gone from the log:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "code-value") {
		t.Errorf("the code reached the log:\n%s", logs.String())
	}
}

// Server rule 2: output encoding by context; the provider's text never reaches the page.
func TestServerRule2_AnIdentityProvidersErrorIsNotReflected(t *testing.T) {
	s := newTestServer(t)
	sess := s.sessions.create()
	sess.State = "test-state"
	if err := s.sessions.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}
	const planted = "planted-text-value"
	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&error="+planted+"&error_description="+planted, nil)
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), planted) {
		t.Errorf("reflected: %s", rec.Body)
	}
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
	if err := s.sessions.save(t.Context(), sess); err != nil {
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
	sess, err := s.sessions.byState(t.Context(), "test-state")
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
	_ = s.sessions.save(t.Context(), sess)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/sign_out", nil)
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("sign_out = %d, want 204", rec.Code)
	}
	if _, err := s.sessions.byID(t.Context(), sess.ID); err == nil {
		t.Error("session not deleted on sign_out")
	}
}

// A sign-out the browser abandons mid-request still ends the session everywhere: SPAs fire it and navigate on.
func TestSignOut_EndsTheSessionWhenTheBrowserGoesAway(t *testing.T) {
	cfg := testConfig(&fakeBackend{})
	cfg.Sessions = cancelAwareSessions{newMemorySessions()}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess := s.sessions.create()
	sess.Identity = map[string]any{"sub": "x"}
	if err := s.sessions.save(t.Context(), sess); err != nil {
		t.Fatal(err)
	}

	gone, cancel := context.WithCancel(t.Context())
	cancel()
	req := httptest.NewRequestWithContext(gone, http.MethodPost, "/oauth2/sign_out", nil)
	req.Header.Set("X-Requested-With", "fetch")
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)

	if _, err := s.sessions.byID(t.Context(), sess.ID); err == nil {
		t.Error("the session survived a sign-out the browser abandoned")
	}
	if revoked, err := cfg.Revocations.Revoked(t.Context(), sess.ID); err != nil || !revoked {
		t.Errorf("the session was not revoked: revoked=%v err=%v", revoked, err)
	}
}

// cancelAwareSessions fails every call under a cancelled context, as a network store does.
type cancelAwareSessions struct{ *memorySessions }

func (c cancelAwareSessions) Load(ctx context.Context, id string) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.memorySessions.Load(ctx, id)
}

func (c cancelAwareSessions) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.memorySessions.Delete(ctx, id)
}

// Server rule 2: CSRF protection for cookie flows.
func TestServerRule2_SignOutByPOSTRequiresCSRFProtection(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth2/sign_out", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sign_out POST without X-Requested-With = %d, want 403", rec.Code)
	}
}

// RFC 9700 Section 4.11.1: the client exposes no open redirector.
func TestRFC9700_4_11_1_SanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/dashboard": "/dashboard", "/a?b=c": "/a?b=c",
		"//evil.example": "", "https://evil.example": "", "/\\evil": "", "": "",
		// returns into pep's own auth endpoints are rejected — they are how the rd loop grows
		"/oauth2/start?rd=/oauth2/start?rd=/": "", "/oauth2/start": "", "/oauth2": "",
		"/oauth2callback": "/oauth2callback", "/foo/../oauth2/start": "",
		// a return-to that is not UTF-8 cannot be kept in the JSON session record
		"/\xff": "", "/a\xe4b": "", "/%FF": "/%FF",
	}
	for in, want := range cases {
		if got := sanitizeReturnTo(in); got != want {
			t.Errorf("sanitizeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}

	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/start?rd=%2F%FF", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/oauth2/start?rd=%%2F%%FF = %d, want 302", rec.Code)
	}
	sess, err := s.sessions.byState(t.Context(), "test-state")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ReturnTo != "" {
		t.Errorf("rd=%%2F%%FF kept as %q", sess.ReturnTo)
	}
}

// go/docs/design.md §2: a library logs only through the logger it was given, so a proxy without one is silent, even
// where it fails.
func TestProxyWithoutLoggerLogsNothing(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	cfg := testConfig(&failingBackend{})
	cfg.Revocations = failingRevocations{}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth2/start?idp_iss=https%3A%2F%2Fidp.example", nil))
	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil))
	s.revoke(t.Context(), "sid")
	if logs.Len() != 0 {
		t.Errorf("the default logger was used: %s", logs.String())
	}
}

func debugLogger() (*slog.Logger, *bytes.Buffer) {
	var logs bytes.Buffer
	return slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), &logs
}

// Server rules 5 and 14. A session's ID is the hash of its cookie, and it names the session's record, the revocation
// entry and the snapshot's sid, so it stays out of the log as well as the cookie does.
func TestServerRule14_ALoginLogsNoSessionIDNorCookieNorStateAtDebug(t *testing.T) {
	log, logs := debugLogger()
	s := newLoggingTestServer(t, log)

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

// failingRevocations cannot tell, nor reach the other replicas.
type failingRevocations struct{}

func (failingRevocations) Revoke(context.Context, string, time.Time) error {
	return errors.New("no bus, no store")
}

func (failingRevocations) Revoked(context.Context, string) (bool, error) {
	return false, errors.New("no store")
}

func (failingRevocations) Follow(context.Context) error { return nil }

// Server rule 14: telemetry carries no secrets and only pseudonymised identifiers.
func TestServerRule14_ARevocationThatFailsLogsNoSid(t *testing.T) {
	log, logs := debugLogger()
	cfg := testConfig(&fakeBackend{})
	cfg.Revocations = failingRevocations{}
	cfg.Logger = log
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sid = "sid-token-hash-value"
	s.revoke(t.Context(), sid)
	if !strings.Contains(logs.String(), "revocation") {
		t.Fatalf("the failure went unlogged: %s", logs)
	}
	if strings.Contains(logs.String(), sid) {
		t.Errorf("the log holds the sid: %s", logs)
	}
}

// Server rule 16, fail closed: a snapshot whose revocation cannot be checked is denied.
func TestServerRule16_ARevocationCheckThatFailsDenies(t *testing.T) {
	cfg := testConfig(&fakeBackend{})
	cfg.Revocations = failingRevocations{}
	cfg.SnapshotKeyPath = writeKeyFile(t, "key")
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.snap.mint("sid-x", map[string]any{"sub": "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
	req.AddCookie(&http.Cookie{Name: s.snapCookie.Name, Value: tok}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// Server rule 17: New refuses to keep the state replicas share in its own memory.
func TestServerRule17_NewRefusesAConfigWithoutSessionsOrRevocations(t *testing.T) {
	without := map[string]func(*Config){
		"Sessions":    func(c *Config) { c.Sessions = nil },
		"Revocations": func(c *Config) { c.Revocations = nil },
	}
	for name, drop := range without {
		cfg := testConfig(&fakeBackend{})
		drop(&cfg)
		if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("without %s: %v", name, err)
		}
	}
}

// Server rule 14: identifiers in telemetry are pseudonymised.
func TestServerRule14_LogRefCorrelatesAndRevealsNoPartOfTheID(t *testing.T) {
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
func TestServerRule14_AForwardAuthDenialLogsNoQuery(t *testing.T) {
	log, logs := debugLogger()
	s := newLoggingTestServer(t, log)
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
func TestServerRule14_SessionLookupErrorsNameNeitherIDNorState(t *testing.T) {
	store := newSessionManager(newMemorySessions(), time.Hour, slog.New(slog.DiscardHandler))
	if _, err := store.byID(t.Context(), "session-id-value"); err == nil || strings.Contains(err.Error(), "session-id-value") {
		t.Errorf("err = %v", err)
	}
	if _, err := store.byState(t.Context(), "state-value"); err == nil || strings.Contains(err.Error(), "state-value") {
		t.Errorf("err = %v", err)
	}
}

// modeBackend starts its logins in one mode and counts the codes it redeems.
type modeBackend struct {
	fakeBackend
	mode     string
	redeemed int
}

func (b *modeBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	start, err := b.fakeBackend.StartLogin(ctx, sess, idpIss, scope)
	start.Mode = b.mode
	return start, err
}

func (b *modeBackend) Complete(ctx context.Context, sess *Session, code string) error {
	b.redeemed++
	return b.fakeBackend.Complete(ctx, sess, code)
}

// startLogin starts a login on s and returns the session cookie the starting browser holds.
func startLogin(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	start := httptest.NewRecorder()
	s.Handler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oauth2/start?idp_iss=https://idp.example", nil))
	for _, c := range start.Result().Cookies() {
		if strings.Contains(c.Name, "TEST-SID") {
			return c
		}
	}
	t.Fatalf("no session cookie: %d", start.Code)
	return nil
}

// RFC 9700 section 2.1.1: the code of a redirect login is redeemed only for the browser that started it. A
// callback without that browser's cookie is refused before the code is redeemed, and its state is gone.
func TestRFC9700_2_1_1_ARedirectLoginCompletesOnlyInTheBrowserThatStartedIt(t *testing.T) {
	backend := &modeBackend{identity: map[string]any{"sub": "victim"}, mode: "redirect"}
	s, err := New(testConfig(backend))
	if err != nil {
		t.Fatal(err)
	}
	started := startLogin(t, s)

	for name, cookie := range map[string]*http.Cookie{
		"no cookie":              nil,
		"another session cookie": {Name: started.Name, Value: "another-session"}, //nolint:gosec // request cookie in a test: only name and value go on the wire
	} {
		t.Run(name, func(t *testing.T) {
			callback := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&code=code-value", nil)
			if cookie != nil {
				callback.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, callback)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("callback = %d", rec.Code)
			}
		})
	}
	if backend.redeemed != 0 {
		t.Errorf("redeemed %d codes", backend.redeemed)
	}

	// The state is consumed: the starting browser cannot complete the login either.
	callback := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&code=code-value", nil)
	callback.AddCookie(&http.Cookie{Name: started.Name, Value: started.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, callback)
	if rec.Code != http.StatusBadRequest || backend.redeemed != 0 {
		t.Errorf("after a refused callback, the starter's = %d, redeemed %d", rec.Code, backend.redeemed)
	}
}

// The decoupled and the authenticator login complete on another device or in an app, without the cookie; the
// starting browser then takes the session over by polling.
func TestRFC9700_2_1_1_ACrossDeviceLoginCompletesWithoutTheCookie(t *testing.T) {
	for _, mode := range []string{"decoupled", "authenticator"} {
		t.Run(mode, func(t *testing.T) {
			backend := &modeBackend{identity: map[string]any{"sub": "user-1"}, mode: mode}
			s, err := New(testConfig(backend))
			if err != nil {
				t.Fatal(err)
			}
			started := startLogin(t, s)

			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&code=code-value", nil))
			if rec.Code != http.StatusOK || backend.redeemed != 1 {
				t.Fatalf("callback = %d, redeemed %d", rec.Code, backend.redeemed)
			}
			poll := httptest.NewRequest(http.MethodGet, "/oauth2/poll", nil)
			poll.AddCookie(&http.Cookie{Name: started.Name, Value: started.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
			polled := httptest.NewRecorder()
			s.Handler().ServeHTTP(polled, poll)
			if polled.Code != http.StatusOK {
				t.Errorf("poll = %d", polled.Code)
			}
		})
	}
}

// refusingBackend is a modeBackend that counts the codes it is given and redeems none.
type refusingBackend struct{ modeBackend }

func (b *refusingBackend) Complete(_ context.Context, _ *Session, _ string) error {
	b.redeemed++
	return errors.New("the token endpoint refused the code")
}

// callback sends the callback with query to s, with cookie when it is not nil.
func callback(s *Server, query string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/oauth2/callback?"+query, nil)
	if cookie != nil {
		r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	return rec
}

// RFC 9700 section 4.2.4: the callback is answered at the URL that carries code and state. Whatever the answer
// is, it is not kept by a cache and its URL is not sent on as a Referer.
func TestRFC9700_4_2_4_NoCallbackResponseIsCachedOrNamedInAReferer(t *testing.T) {
	const good = "state=test-state&code=code-value"
	for name, c := range map[string]struct {
		backend    Backend
		query      string
		withCookie bool
		status     int
	}{
		"completed in the starting browser": {&modeBackend{mode: "redirect"}, good, true, http.StatusFound},
		"completed on another device":       {&modeBackend{mode: "decoupled"}, good, false, http.StatusOK},
		"refused in another browser":        {&modeBackend{mode: "redirect"}, good, false, http.StatusBadRequest},
		"an unknown state":                  {&modeBackend{mode: "redirect"}, "state=unknown&code=code-value", true, http.StatusBadRequest},
		"no parameters":                     {&modeBackend{mode: "redirect"}, "", true, http.StatusBadRequest},
		"refused by the identity provider":  {&modeBackend{mode: "redirect"}, "state=test-state&error=access_denied", true, 0},
		"a code that is not redeemed":       {&refusingBackend{modeBackend{mode: "redirect"}}, good, true, 0},
	} {
		t.Run(name, func(t *testing.T) {
			s, err := New(testConfig(c.backend))
			if err != nil {
				t.Fatal(err)
			}
			cookie := startLogin(t, s)
			if !c.withCookie {
				cookie = nil
			}
			rec := callback(s, c.query, cookie)
			if c.status != 0 && rec.Code != c.status {
				t.Errorf("status = %d, want %d", rec.Code, c.status)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q", got)
			}
			if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q", got)
			}
		})
	}
}

// RFC 9700 section 4.2.4: the state is used once. The first callback that names it consumes it, whether the code
// is redeemed, the exchange fails or the identity provider refused the login; a second callback with the same
// state finds none, and nothing the starting browser does afterwards brings it back.
func TestRFC9700_4_2_4_TheStateIsUsedOnceWhateverBecomesOfTheCallback(t *testing.T) {
	for name, c := range map[string]struct {
		backend  func() (Backend, *int)
		first    string
		redeemed int
	}{
		"the exchange fails": {
			func() (Backend, *int) {
				b := &refusingBackend{modeBackend{mode: "redirect"}}
				return b, &b.redeemed
			}, "state=test-state&code=first", 1,
		},
		"the identity provider refused": {
			func() (Backend, *int) {
				b := &modeBackend{mode: "redirect"}
				return b, &b.redeemed
			}, "state=test-state&error=access_denied", 0,
		},
		"the login completes": {
			func() (Backend, *int) {
				b := &modeBackend{mode: "redirect"}
				return b, &b.redeemed
			}, "state=test-state&code=first", 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			backend, redeemed := c.backend()
			s, err := New(testConfig(backend))
			if err != nil {
				t.Fatal(err)
			}
			cookie := startLogin(t, s)
			callback(s, c.first, cookie)
			if *redeemed != c.redeemed {
				t.Fatalf("the first callback redeemed %d codes, want %d", *redeemed, c.redeemed)
			}

			// A request of the starting browser saves its session again; the state must not come back with it.
			poll := httptest.NewRequest(http.MethodGet, "/oauth2/poll", nil)
			poll.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
			s.Handler().ServeHTTP(httptest.NewRecorder(), poll)

			second := callback(s, "state=test-state&code=second", cookie)
			if second.Code != http.StatusBadRequest {
				t.Errorf("the second callback = %d, want 400", second.Code)
			}
			if *redeemed != c.redeemed {
				t.Errorf("the second callback redeemed a code: %d in all", *redeemed)
			}
		})
	}
}
