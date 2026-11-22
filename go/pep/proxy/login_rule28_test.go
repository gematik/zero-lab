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
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strings"
	"testing"
)

// scopedBackend is a backend with two listed providers and configured scopes, as the PDP backend is. It
// records what a login start handed it.
type scopedBackend struct {
	fakeBackend
	scopes        []string
	started       int
	idpIss, scope string
	redeemed      int
}

func (b *scopedBackend) Providers(context.Context) ([]Provider, error) {
	return []Provider{
		{Issuer: "https://idp.example", Name: "One", Type: "oidc"},
		{Issuer: "https://other-idp.example", Name: "Two", Type: "oidc"},
	}, nil
}

func (b *scopedBackend) DefaultIssuer() string { return "" }

func (b *scopedBackend) loginScopes() []string { return b.scopes }

func (b *scopedBackend) StartLogin(ctx context.Context, sess *Session, idpIss, scope string) (LoginStart, error) {
	b.started++
	b.idpIss, b.scope = idpIss, scope
	return b.fakeBackend.StartLogin(ctx, sess, idpIss, scope)
}

func (b *scopedBackend) Complete(ctx context.Context, sess *Session, code string) error {
	b.redeemed++
	return b.fakeBackend.Complete(ctx, sess, code)
}

func scopedServer(tb testing.TB) (*Server, *scopedBackend) {
	tb.Helper()
	backend := &scopedBackend{identity: map[string]any{"sub": "u"}, scopes: []string{"openid", "protected"}}
	s, err := New(testConfig(backend))
	if err != nil {
		tb.Fatal(err)
	}
	return s, backend
}

// get sends GET target?rawQuery to s. The query goes in as it is, also where it would not parse.
func get(s *Server, target, rawQuery string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.URL.RawQuery = rawQuery
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // request cookie in a test: only name and value go on the wire
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, r)
	return rec
}

// Server rule 28, parameters: /oauth2/start and /oauth2/sign_in declare their parameters. One that occurs
// twice, one they do not know, an rd outside its grammar, an idp_iss the chooser does not list and a scope the
// backend was not configured with are refused with 400. Nothing is started, no cookie is set, and the answer is
// the same whatever was sent.
func TestServerRule28_TheLoginEndpointsRefuseWhatTheyDoNotDeclare(t *testing.T) {
	s, backend := scopedServer(t)
	reference := get(s, "/oauth2/start", "unknown=1")
	if reference.Code != http.StatusBadRequest {
		t.Fatalf("reference = %d", reference.Code)
	}
	for name, c := range map[string]struct{ target, query string }{
		"start: rd twice":                     {"/oauth2/start", "rd=/a&rd=/b"},
		"start: idp_iss twice":                {"/oauth2/start", "idp_iss=https://idp.example&idp_iss=https://other-idp.example"},
		"start: scope twice":                  {"/oauth2/start", "idp_iss=https://idp.example&scope=openid&scope=protected"},
		"start: an unknown parameter":         {"/oauth2/start", "idp_iss=https://idp.example&prompt=none"},
		"start: a name in another case":       {"/oauth2/start", "IDP_ISS=https://idp.example"},
		"start: a query that does not decode": {"/oauth2/start", "rd=%zz"},
		"start: rd to another host":           {"/oauth2/start", "rd=//evil.example"},
		"start: rd with a tab":                {"/oauth2/start", "rd=/%09/evil.example"},
		"start: rd with a backslash":          {"/oauth2/start", "rd=/%5Cevil.example"},
		"start: rd into /oauth2":              {"/oauth2/start", "rd=/oauth2/start"},
		"start: rd that is not UTF-8":         {"/oauth2/start", "rd=%2F%FF"},
		"start: an issuer not listed":         {"/oauth2/start", "idp_iss=https://evil.example"},
		"start: an issuer in another case":    {"/oauth2/start", "idp_iss=https://IDP.example"},
		"start: a scope not configured":       {"/oauth2/start", "idp_iss=https://idp.example&scope=admin"},
		"start: one scope not configured":     {"/oauth2/start", "idp_iss=https://idp.example&scope=openid+admin"},
		"start: two spaces between scopes":    {"/oauth2/start", "idp_iss=https://idp.example&scope=openid++protected"},
		"sign_in: rd twice":                   {"/oauth2/sign_in", "rd=/a&rd=/b"},
		"sign_in: an unknown parameter":       {"/oauth2/sign_in", "idp_iss=https://idp.example"},
		"sign_in: rd to another host":         {"/oauth2/sign_in", "rd=https://evil.example"},
	} {
		rec := get(s, c.target, c.query)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		if rec.Body.String() != reference.Body.String() {
			t.Errorf("%s: the answer differs from that to any other refused request", name)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Errorf("%s: a cookie was set", name)
		}
	}
	if backend.started != 0 {
		t.Errorf("%d logins were started", backend.started)
	}

	// What they declare, they take.
	if rec := get(s, "/oauth2/sign_in", "rd=/app%3Fx%3D1"); rec.Code != http.StatusOK {
		t.Errorf("sign_in = %d", rec.Code)
	}
	if rec := get(s, "/oauth2/start", "rd=/app"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/oauth2/sign_in?rd=%2Fapp" {
		t.Errorf("start without issuer = %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	rec := get(s, "/oauth2/start", "rd=/app%3Fidp_iss%3Dhttps://evil.example%26scope%3Dadmin&idp_iss=https://other-idp.example&scope=protected+openid")
	if rec.Code != http.StatusFound || backend.started != 1 {
		t.Fatalf("start = %d, started %d", rec.Code, backend.started)
	}
	if backend.idpIss != "https://other-idp.example" || backend.scope != "protected openid" {
		t.Errorf("the backend got issuer %q and scope %q", backend.idpIss, backend.scope)
	}
	sess, err := s.sessions.takeByState(t.Context(), "test-state")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ReturnTo != "/app?idp_iss=https://evil.example&scope=admin" {
		t.Errorf("return-to = %q: an encoded rd keeps its own query to itself", sess.ReturnTo)
	}
}

// A backend that takes no scope from the request has none configured, so a login start that asks for one is
// refused.
func TestServerRule28_AScopeIsRefusedWhereTheBackendTakesNone(t *testing.T) {
	s := newTestServer(t)
	if rec := get(s, "/oauth2/start", "idp_iss=https://idp.example&scope=openid"); rec.Code != http.StatusBadRequest {
		t.Errorf("status %d", rec.Code)
	}
	if rec := get(s, "/oauth2/start", "idp_iss=https://idp.example"); rec.Code != http.StatusFound {
		t.Errorf("without scope: status %d", rec.Code)
	}
}

// RFC 6749 section 3.1: the authorization response is the identity provider's. A parameter that occurs twice is
// refused before the state is looked at or a code redeemed; one this server does not know is ignored.
func TestRFC6749_3_1_TheCallbackRefusesARepeatedParameterAndIgnoresAnUnknownOne(t *testing.T) {
	for name, query := range map[string]string{
		"state twice":                  "state=test-state&state=other&code=c",
		"code twice":                   "state=test-state&code=c&code=d",
		"error twice":                  "state=test-state&error=a&error=b",
		"an unknown one twice":         "state=test-state&code=c&x=1&x=2",
		"a query that does not decode": "state=test-state&code=%zz",
	} {
		s, backend := scopedServer(t)
		cookie := startLogin(t, s)
		if rec := get(s, "/oauth2/callback", query, cookie); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, rec.Code)
		}
		if backend.redeemed != 0 {
			t.Errorf("%s: a code was redeemed", name)
		}
		// The refused request did not use the state up: the provider's own response still completes.
		if rec := get(s, "/oauth2/callback", "state=test-state&code=c&iss=https://idp.example&session_state=x", cookie); rec.Code != http.StatusFound || backend.redeemed != 1 {
			t.Errorf("%s: the provider's response afterwards = %d, redeemed %d", name, rec.Code, backend.redeemed)
		}
	}
}

// FuzzCheckReturnTo asserts what an accepted return-to is: empty, or a path of this origin that a browser
// cannot read as another host and that does not lead into /oauth2. A refusal is the one fixed error.
func FuzzCheckReturnTo(f *testing.F) {
	for _, seed := range []string{
		"", "/", "/app?x=1", "//evil.example", "/\\evil.example", "/\t/evil.example", "/\r\n/evil.example",
		"https://evil.example", "/oauth2/start", "/a/../oauth2/start", "/%2e%2e/oauth2", "/\xff", "/a\x00b",
		"/\u202eevil", "/%09/evil.example", "/a%0d%0aSet-Cookie:x=1", "javascript:alert(1)", "/a#//evil.example",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, rd string) {
		err := checkReturnTo(rd)
		if err != nil {
			if !errors.Is(err, errReturnTo) {
				t.Fatalf("a refusal other than the fixed one: %v", err)
			}
			return
		}
		assertReturnTo(t, rd)
	})
}

func assertReturnTo(t *testing.T, rd string) {
	t.Helper()
	if rd == "" {
		return
	}
	if len(rd) > maxReturnToBytes || rd[0] != '/' || strings.HasPrefix(rd, "//") {
		t.Fatalf("accepted %q: not a path of this origin", rd)
	}
	if strings.ContainsFunc(rd, func(c rune) bool { return c < 0x20 || c == 0x7f || c == '\\' }) {
		t.Fatalf("accepted %q: a control character or a backslash", rd)
	}
	rawPath, _, _ := strings.Cut(rd, "?")
	rawPath, _, _ = strings.Cut(rawPath, "#")
	if p := path.Clean(rawPath); p == "/oauth2" || strings.HasPrefix(p, "/oauth2/") {
		t.Fatalf("accepted %q: it leads into /oauth2", rd)
	}
}

// FuzzLoginStart sends arbitrary queries to /oauth2/start. A refusal is the same answer whatever was sent, so it
// holds nothing of the input, and it starts no login. A login that is started got an issuer the chooser lists,
// scopes the backend was configured with, and a return-to of the application.
func FuzzLoginStart(f *testing.F) {
	for _, seed := range []string{
		"idp_iss=https://idp.example", "idp_iss=https://idp.example&rd=/app&scope=openid+protected",
		"rd=/app", "rd=/a&rd=/b", "rd=//evil.example", "rd=/%09/evil.example", "rd=%zz", "x=1",
		"idp_iss=https://evil.example", "idp_iss=https://idp.example&scope=admin",
		"idp_iss=https://idp.example&scope=openid%0d%0a", "idp_iss=https://idp.example&rd=/app%3Fidp_iss%3Dx",
		"idp_iss=https://idp.example;rd=/app", "idp_iss=https://idp.example&rd=/\xff", "rd=/" + strings.Repeat("a", maxReturnToBytes),
	} {
		f.Add(seed)
	}
	s, backend := scopedServer(f)
	refused := get(s, "/oauth2/start", "unknown=1").Body.String()
	providers, _ := backend.Providers(f.Context())
	f.Fuzz(func(t *testing.T, rawQuery string) {
		before := backend.started
		rec := get(s, "/oauth2/start", rawQuery)
		switch rec.Code {
		case http.StatusBadRequest:
			if rec.Body.String() != refused {
				t.Fatalf("a refusal that differs from the others")
			}
			if backend.started != before || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("a refused request started a login or set a cookie")
			}
		case http.StatusFound:
			if backend.started == before {
				// No issuer was named: the browser goes to the chooser with its return-to.
				location := rec.Header().Get("Location")
				if location != "/oauth2/sign_in" && !strings.HasPrefix(location, "/oauth2/sign_in?rd=") {
					t.Fatalf("redirected to %q", location)
				}
				return
			}
			if !slices.ContainsFunc(providers, func(p Provider) bool { return p.Issuer == backend.idpIss }) {
				t.Fatalf("a login was started at an issuer that is not listed")
			}
			if backend.scope != "" {
				for token := range strings.SplitSeq(backend.scope, " ") {
					if !slices.Contains(backend.scopes, token) {
						t.Fatalf("a login was started with a scope that is not configured")
					}
				}
			}
			sess, err := s.sessions.takeByState(t.Context(), "test-state")
			if err != nil {
				t.Fatal(err)
			}
			assertReturnTo(t, sess.ReturnTo)
		default:
			t.Fatalf("status %d", rec.Code)
		}
	})
}
