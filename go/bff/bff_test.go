package bff_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
)

// newMockAS spins up an authorization server stub serving just what the BFF talks to: RFC 8414
// metadata, the token endpoint, introspection, and the openid-providers list.
func newMockAS(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		writeJSON(w, map[string]string{
			"issuer":                    base,
			"authorization_endpoint":    base + "/auth",
			"token_endpoint":            base + "/token",
			"introspection_endpoint":    base + "/introspect",
			"openid_providers_endpoint": base + "/openid-providers",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"access_token":  "mock-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "mock-refresh-token",
		})
	})
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{
			"active":   true,
			"identity": map[string]any{"sub": "user-123", "name": "Test User"},
		})
	})
	mux.HandleFunc("GET /openid-providers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, []map[string]string{
			{"iss": "https://oidf.example", "name": "OIDF IdP", "type": "oidf"},
			{"iss": "https://std.example", "name": "Standard IdP", "type": "oidc"},
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newTestBFF(t *testing.T, sm bff.SessionManager) *bff.BackendForFrontend {
	t.Helper()
	as := newMockAS(t)
	if sm == nil {
		sm = bff.NewSessionManagerMock()
	}
	b, err := bff.New(bff.Config{
		AuthorizationServer: bff.AuthorizationServerConfig{
			Issuer:       as.URL,
			ClientId:     "bff-client",
			ClientSecret: "secret",
			RedirectUri:  "http://bff.example/bff/auth/callback",
		},
		CookieName:          "test-cookie",
		FrontendRedirectUri: "http://bff.example/",
		SessionManager:      sm,
	})
	if err != nil {
		t.Fatalf("bff.New: %v", err)
	}
	return b
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "test-cookie" {
			return c
		}
	}
	t.Fatal("no session cookie was set")
	return nil
}

func queryParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestLogin_ModeByProviderType(t *testing.T) {
	b := newTestBFF(t, nil)

	for _, tc := range []struct{ opIssuer, wantMode string }{
		{"https://std.example", "redirect"},
		{"https://oidf.example", "decoupled"},
	} {
		rec := httptest.NewRecorder()
		b.LoginEndpoint(rec, httptest.NewRequest("GET", "/bff/auth/login?op_issuer="+url.QueryEscape(tc.opIssuer), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: login status %d", tc.opIssuer, rec.Code)
		}
		var lr struct {
			AuthUrl string `json:"auth_url"`
			Mode    string `json:"mode"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
			t.Fatal(err)
		}
		if lr.Mode != tc.wantMode {
			t.Errorf("%s: mode = %q, want %q", tc.opIssuer, lr.Mode, tc.wantMode)
		}
		if lr.AuthUrl == "" {
			t.Errorf("%s: empty auth_url", tc.opIssuer)
		}
		if queryParam(t, lr.AuthUrl, "op_issuer") != tc.opIssuer {
			t.Errorf("%s: auth_url missing op_issuer", tc.opIssuer)
		}
		_ = sessionCookie(t, rec) // login binds the browser to the pending session
	}
}

func TestCallbackThenSession(t *testing.T) {
	sm := bff.NewSessionManagerMock()
	b := newTestBFF(t, sm)

	// Start login → pending session + cookie + auth_url carrying the state.
	loginRec := httptest.NewRecorder()
	b.LoginEndpoint(loginRec, httptest.NewRequest("GET", "/bff/auth/login?op_issuer=https://std.example", nil))
	cookie := sessionCookie(t, loginRec)
	var lr struct {
		AuthUrl string `json:"auth_url"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &lr)
	state := queryParam(t, lr.AuthUrl, "state")

	// Callback exchanges the code, introspects, caches the identity.
	cbRec := httptest.NewRecorder()
	b.CallbackEndpoint(cbRec, httptest.NewRequest("GET", "/bff/auth/callback?state="+state+"&code=abc", nil))
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback status %d, want 302; body=%s", cbRec.Code, cbRec.Body)
	}

	// Session returns the upstream identity from introspection.
	sessReq := httptest.NewRequest("GET", "/bff/auth/session", nil)
	sessReq.AddCookie(cookie)
	sessRec := httptest.NewRecorder()
	b.SessionEndpoint(sessRec, sessReq)
	if sessRec.Code != http.StatusOK {
		t.Fatalf("session status %d, want 200; body=%s", sessRec.Code, sessRec.Body)
	}
	var sr struct {
		Authenticated bool           `json:"authenticated"`
		UserInfo      map[string]any `json:"userinfo"`
	}
	_ = json.Unmarshal(sessRec.Body.Bytes(), &sr)
	if !sr.Authenticated {
		t.Fatal("session: not authenticated")
	}
	if sr.UserInfo["sub"] != "user-123" {
		t.Errorf("session: userinfo sub = %v, want user-123", sr.UserInfo["sub"])
	}
}

func TestPoll_PendingThenDone(t *testing.T) {
	sm := bff.NewSessionManagerMock()
	b := newTestBFF(t, sm)

	loginRec := httptest.NewRecorder()
	b.LoginEndpoint(loginRec, httptest.NewRequest("GET", "/bff/auth/login", nil))
	cookie := sessionCookie(t, loginRec)

	poll := func() int {
		req := httptest.NewRequest("GET", "/bff/auth/poll", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		b.PollEndpoint(rec, req)
		return rec.Code
	}

	if code := poll(); code != http.StatusAccepted {
		t.Fatalf("pending poll = %d, want 202", code)
	}

	session, err := sm.GetSessionById(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	session.AccessToken = "tok"
	_ = sm.UpdateSession(session)

	if code := poll(); code != http.StatusOK {
		t.Fatalf("completed poll = %d, want 200", code)
	}
}

func TestLogout_CSRFAndClear(t *testing.T) {
	sm := bff.NewSessionManagerMock()
	b := newTestBFF(t, sm)
	session, _ := sm.CreateSession("s", "v", "S256")
	session.AccessToken = "tok"
	_ = sm.UpdateSession(session)
	cookie := &http.Cookie{Name: "test-cookie", Value: session.Id}

	// Missing the custom header → rejected (CSRF defense).
	noCSRF := httptest.NewRequest("POST", "/bff/auth/logout", nil)
	noCSRF.AddCookie(cookie)
	rec := httptest.NewRecorder()
	b.LogoutEndpoint(rec, noCSRF)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout without X-Requested-With = %d, want 403", rec.Code)
	}

	// With the header → session cleared.
	ok := httptest.NewRequest("POST", "/bff/auth/logout", nil)
	ok.AddCookie(cookie)
	ok.Header.Set("X-Requested-With", "fetch")
	rec = httptest.NewRecorder()
	b.LogoutEndpoint(rec, ok)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", rec.Code)
	}
	if _, err := sm.GetSessionById(session.Id); err == nil {
		t.Error("session was not deleted on logout")
	}
}

func TestProviders(t *testing.T) {
	b := newTestBFF(t, nil)
	rec := httptest.NewRecorder()
	b.ProvidersEndpoint(rec, httptest.NewRequest("GET", "/bff/auth/providers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("providers status %d", rec.Code)
	}
	var providers []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &providers); err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(providers))
	}
}

func TestPanicRecovery(t *testing.T) {
	h := bff.RecoverMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panicking handler → %d, want 500", rec.Code)
	}
}
