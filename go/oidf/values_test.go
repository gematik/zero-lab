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

package oidf

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gematik/zero-lab/go/openid"
)

// withPAR makes the stub provider's PAR endpoint count the requests reaching it and keep the last form.
func (s *loginStub) withPAR(t *testing.T) (pushed *atomic.Int64, form *atomic.Pointer[url.Values]) {
	t.Helper()
	pushed, form = new(atomic.Int64), new(atomic.Pointer[url.Values])
	s.endpoints = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed.Add(1)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		form.Store(&r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"request_uri":"urn:r","expires_in":60}`)
	})
	return pushed, form
}

func validLogin() openid.Login {
	return openid.Login{State: "state_0-Z", Nonce: "nonce_0-Z", Verifier: testVerifier}
}

// The bounds sektorale IDPs hold state and nonce to, and RFC 7636 section 4.1's code_verifier: a value outside them is
// refused before the IDP is asked.
func TestOWASP_InputValidation_LoginValuesAreRefusedBeforePAR(t *testing.T) {
	stub := newLoginStub(t)
	pushed, _ := stub.withPAR(t)
	for name, c := range map[string]struct {
		change func(*openid.Login)
		want   error
	}{
		"empty state":          {func(l *openid.Login) { l.State = "" }, ErrState},
		"state of 513":         {func(l *openid.Login) { l.State = strings.Repeat("s", 513) }, ErrState},
		"state with CRLF":      {func(l *openid.Login) { l.State = "s\r\nX: y" }, ErrState},
		"state with a dot":     {func(l *openid.Login) { l.State = "s.t" }, ErrState},
		"state with NUL":       {func(l *openid.Login) { l.State = "s\x00" }, ErrState},
		"empty nonce":          {func(l *openid.Login) { l.Nonce = "" }, ErrNonce},
		"nonce of 513":         {func(l *openid.Login) { l.Nonce = strings.Repeat("n", 513) }, ErrNonce},
		"nonce non-ASCII":      {func(l *openid.Login) { l.Nonce = "nönce" }, ErrNonce},
		"verifier of 42":       {func(l *openid.Login) { l.Verifier = testVerifier[:42] }, ErrCodeVerifier},
		"verifier of 129":      {func(l *openid.Login) { l.Verifier = strings.Repeat("v", 129) }, ErrCodeVerifier},
		"verifier with a plus": {func(l *openid.Login) { l.Verifier = testVerifier[:42] + "+" }, ErrCodeVerifier},
	} {
		login := validLogin()
		c.change(&login)
		_, err := stub.client.AuthenticationURL(t.Context(), login)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "X: y") {
			t.Errorf("%s: the error holds the value", name)
		}
	}
	if n := pushed.Load(); n != 0 {
		t.Fatalf("%d requests reached the IDP", n)
	}
	for name, change := range map[string]func(*openid.Login){
		"state of 512":       func(l *openid.Login) { l.State = strings.Repeat("s", 512) },
		"state of 1":         func(l *openid.Login) { l.State = "s" },
		"verifier of 128":    func(l *openid.Login) { l.Verifier = strings.Repeat("v", 128) },
		"verifier with .~":   func(l *openid.Login) { l.Verifier = testVerifier[:41] + ".~" },
		"a UUID as nonce":    func(l *openid.Login) { l.Nonce = "8a3c1f1e-8f9c-4c3e-9d6a-0b1e2f3a4b5c" },
		"a generated verify": func(l *openid.Login) { l.Verifier = openid.GenerateVerifier() },
	} {
		login := validLogin()
		change(&login)
		if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// gemSpec_IDP_Sek compares the scopes of a request with the scope the relying party registered: a scope outside it is
// refused here, before PAR.
func TestA_23034_02_AScopeThatIsNotRegisteredIsNotAskedFor(t *testing.T) {
	stub := newLoginStub(t)
	pushed, form := stub.withPAR(t)
	login := validLogin()
	login.Scopes = []string{"openid", "urn:telematik:email"}
	if _, err := stub.client.AuthenticationURL(t.Context(), login); !errors.Is(err, ErrScopeNotRegistered) {
		t.Fatalf("err = %v", err)
	}
	if pushed.Load() != 0 {
		t.Fatal("the request reached the IDP")
	}
	login.Scopes = []string{"openid", "urn:telematik:display_name"}
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if got := form.Load().Get("scope"); got != "openid urn:telematik:display_name" {
		t.Errorf("scope = %q", got)
	}
}

// Servers rule 17: configured scopes that the relying party does not register would fail every login, so they stop
// the start.
func TestServerRule17_AConfiguredScopeThatIsNotRegisteredIsRefused(t *testing.T) {
	cfg := testRelyingPartyConfig(t, newFederationStub(t))
	cfg.Scopes = []string{"openid", "urn:telematik:email"}
	if _, err := New(t.Context(), cfg, newTestKeys(t)); !errors.Is(err, ErrScopeNotRegistered) {
		t.Fatalf("configured: %v", err)
	}
	cfg.Scopes = nil
	cfg.RelyingParty.Scope = "openid urn:telematik:display_name"
	if _, err := New(t.Context(), cfg, newTestKeys(t)); !errors.Is(err, ErrScopeNotRegistered) {
		t.Fatalf("the default scopes: %v", err)
	}
}

// gemSpec_IDP_Sek A_24403: the IDP lists the claims it supports, and a claim it does not list is not asked for.
func TestA_24403_AClaimTheIDPDoesNotSupportIsNotAskedFor(t *testing.T) {
	stub := newLoginStub(t)
	pushed, form := stub.withPAR(t)
	stub.publish(t, func(metadata map[string]any) {
		metadata["claims_supported"] = []string{"urn:telematik:claims:id", "amr"}
	}, keySetOf(stub.sigKey, "k"))
	login := validLogin()
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:email":{"essential":true}}}`)
	if _, err := stub.client.AuthenticationURL(t.Context(), login); !errors.Is(err, ErrClaimNotSupported) {
		t.Fatalf("err = %v", err)
	}
	login.Claims = json.RawMessage(`{"userinfo":{"urn:telematik:claims:email":null}}`)
	if _, err := stub.client.AuthenticationURL(t.Context(), login); !errors.Is(err, ErrClaimNotSupported) {
		t.Fatalf("userinfo: %v", err)
	}
	if pushed.Load() != 0 {
		t.Fatal("the request reached the IDP")
	}
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:id":{"essential":true},"amr":{"values":["urn:telematik:auth:eGK"]}}}`)
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatal(err)
	}
	if got := form.Load().Get("claims"); got != string(login.Claims) {
		t.Errorf("claims = %q", got)
	}
	stub.publish(t, nil, keySetOf(stub.sigKey, "k"))
	login.Claims = json.RawMessage(`{"id_token":{"urn:telematik:claims:email":null}}`)
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Errorf("an IDP that lists none: %v", err)
	}
}

// OIDC Core 5.5.1: a claim is requested by null or by an object whose essential is a boolean.
func TestOIDCCore_5_5_1_TheClaimsRequestIsReadAsSpecified(t *testing.T) {
	for _, request := range []string{
		`{"id_token":[]}`,
		`{"id_token":{"amr":"x"}}`,
		`{"id_token":{"amr":{"essential":"true"}}}`,
		`{"userinfo":1}`,
	} {
		if _, err := parseClaimsRequest(json.RawMessage(request)); !errors.Is(err, ErrClaimsRequest) {
			t.Errorf("%s: %v", request, err)
		}
	}
	request, err := parseClaimsRequest(json.RawMessage(`{"id_token":{"a":{"essential":true},"b":null,"c":{"essential":false},"d":{"ESSENTIAL":true}},"other":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"a": true, "b": false, "c": false, "d": false} {
		if got, ok := request.idToken[name]; !ok || got != want {
			t.Errorf("%s: essential %v, %v", name, got, ok)
		}
	}
}

func FuzzClaimsRequest(f *testing.F) {
	f.Add([]byte(`{"id_token":{"urn:telematik:claims:id":{"essential":true},"amr":{"values":["urn:telematik:auth:eGK"]}}}`))
	f.Add([]byte(`{"id_token":{"a":null},"userinfo":{"b":{"essential":false}}}`))
	f.Add([]byte(`{"id_token":{"a":{"essential":1e999}}}`))
	f.Add([]byte(`{"id_token":{"a":{"essential":true,"essential":false}},"id_token":null}`))
	f.Add([]byte(`{"id_token":{"\u0000":{}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		request, err := parseClaimsRequest(raw)
		if err != nil {
			if !errors.Is(err, ErrClaimsRequest) {
				t.Fatalf("an error without its sentinel: %v", err)
			}
			return
		}
		if len(raw) > openid.MaxClaimsBytes {
			t.Fatalf("accepted %d bytes", len(raw))
		}
		if len(request.names()) != len(request.idToken)+len(request.userinfo) {
			t.Fatal("names lost a claim")
		}
	})
}

// countingTransport counts the requests that leave through it.
type countingTransport struct {
	requests atomic.Int64
	next     http.RoundTripper
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return c.next.RoundTrip(r)
}

// answering makes handler answer the stub provider's PAR and token endpoints and counts every request the client
// sends them.
func (s *loginStub) answering(t testing.TB, handler http.HandlerFunc) *countingTransport {
	t.Helper()
	s.endpoints = handler
	counting := &countingTransport{next: s.transport}
	s.client.rp.httpClient = &http.Client{Transport: counting, CheckRedirect: refuseRedirect}
	return counting
}

// answer writes body with status and content type.
func answer(status int, contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func TestOWASP_InputValidation_AuthorizationCode(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	counting := stub.answering(t, answer(http.StatusOK, "application/json", `{}`))
	for name, code := range map[string]string{
		"empty": "", "overlong": strings.Repeat("c", 2049), "CRLF": "c\r\nX: y", "LF": "c\nX: y", "NUL": "c\x00",
		"tab": "c\td", "non-ASCII": "cöde", "invalid UTF-8": "c\xff", "overlong UTF-8": "c\xc0\xaf", "bidi": "c\u202ed",
		"zero-width": "c\u200bd",
	} {
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), nLogin(), code); !errors.Is(err, openid.ErrAuthorizationCode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := counting.requests.Load(); n != 0 {
		t.Fatalf("%d refused codes reached the IDP", n)
	}
}

// RFC 9700 section 4.1.3: "the authorization server MUST ensure that the redirect URI [...] exactly matches one of the
// registered redirect URIs". The IDP compares; the relying party sends nothing it would have to refuse, so a code is
// never sent toward a URI nobody registered.
func TestRFC9700_4_1_3_TheRedirectURIIsComparedExactly(t *testing.T) {
	stub := newLoginStub(t)
	stub.idToken = stub.nestedToken(t, validIDTokenClaims())
	counting := stub.answering(t, answer(http.StatusCreated, "application/json", `{"request_uri":"urn:r","expires_in":60}`))
	for name, uri := range map[string]string{
		"a trailing slash":     "https://rp.example/cb/",
		"another case":         "https://RP.example/cb",
		"a prefix":             "https://rp.example/c",
		"an extension":         "https://rp.example/cb/evil",
		"a query":              "https://rp.example/cb?x=1",
		"a fragment":           "https://rp.example/cb#x",
		"percent-encoded":      "https://rp.example/%63b",
		"a dot segment":        "https://rp.example/x/../cb",
		"a port":               "https://rp.example:443/cb",
		"http":                 "http://rp.example/cb",
		"user info":            "https://rp.example@evil.example/cb",
		"javascript":           "javascript:alert(1)",
		"data":                 "data:text/html,x",
		"CRLF":                 "https://rp.example/cb\r\n",
		"trailing NUL":         "https://rp.example/cb\x00",
		"zero-width":           "https://rp.example/cb\u200b",
		"another registration": "https://other.example/cb",
	} {
		login := validLogin()
		login.RedirectURI = uri
		if _, err := stub.client.AuthenticationURL(t.Context(), login); !errors.Is(err, ErrRedirectURINotRegistered) {
			t.Errorf("PAR, %s: %v", name, err)
		}
		if _, _, err := stub.client.ExchangeIdentity(t.Context(), login, "code"); !errors.Is(err, ErrRedirectURINotRegistered) {
			t.Errorf("token request, %s: %v", name, err)
		}
	}
	if n := counting.requests.Load(); n != 0 {
		t.Fatalf("%d requests with an unregistered redirect URI reached the IDP", n)
	}
	login := validLogin()
	login.RedirectURI = "https://rp.example/cb"
	if _, err := stub.client.AuthenticationURL(t.Context(), login); err != nil {
		t.Fatalf("the registered URI: %v", err)
	}
}

// The redirect URIs a host's hook adds to the statement at signing are registered as soon as the statement carrying
// them is served, and only then: the IDP fetches the served one.
func TestRFC9700_4_1_3_TheRedirectURIsAreThoseOfTheServedStatement(t *testing.T) {
	stub := newFederationStub(t)
	rp, err := New(t.Context(), testRelyingPartyConfig(t, stub), newTestKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	const product = "https://product.example/cb"
	configured := rp.registered().redirectURIs
	if checkRedirectURI(configured[0], configured) != nil || checkRedirectURI(product, configured) == nil {
		t.Fatalf("before the hook: %v", configured)
	}
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		es.Metadata.OpenidRelyingParty.RedirectURIs = append(es.Metadata.OpenidRelyingParty.RedirectURIs, product)
		return nil
	})
	if checkRedirectURI(product, rp.registered().redirectURIs) == nil {
		t.Fatal("registered before a statement carrying it is served")
	}
	if err := rp.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := checkRedirectURI(product, rp.registered().redirectURIs); err != nil {
		t.Fatalf("after signing: %v", err)
	}
}

func TestOWASP_InputValidation_EntityIdentifier(t *testing.T) {
	for name, iss := range map[string]string{
		"empty":                     "",
		"overlong":                  "https://op.example/" + strings.Repeat("a", 2048),
		"http":                      "http://op.example",
		"no host":                   "https:///x",
		"an upper-case scheme":      "HTTPS://op.example",
		"an upper-case host":        "https://OP.example",
		"user info":                 "https://user@op.example",
		"a query":                   "https://op.example?x",
		"a fragment":                "https://op.example#x",
		"a dot-dot segment":         "https://op.example/a/../b",
		"a dot segment":             "https://op.example/./b",
		"a trailing dot-dot":        "https://op.example/..",
		"percent-encoded slash":     "https://op.example/a%2fb",
		"percent-encoded backslash": "https://op.example/a%5Cb",
		"percent-encoded at":        "https://op.example%40evil.example",
		"percent-encoded hash":      "https://op.example/a%23b",
		"double encoding":           "https://op.example/a%252fb",
		"a backslash":               "https://op.example\\@evil.example",
		"CRLF":                      "https://op.example\r\nX: y",
		"NUL":                       "https://op.example\x00",
		"a space":                   "https://op .example",
		"non-ASCII host":            "https://öp.example",
		"invalid UTF-8":             "https://op.example/\xff",
		"bidi":                      "https://op.example/\u202e",
		"zero-width":                "https://op\u200b.example",
		"javascript":                "javascript:alert(1)",
		"data":                      "data:text/html,x",
		"file":                      "file:///etc/passwd",
		"an empty port":             "https://op.example:",
		"a port of letters":         "https://op.example:ab",
		"an IPv6 literal":           "https://[::1]",
		"a host of a dot":           "https://.",
		"an empty label":            "https://op..example",
		"a trailing dot":            "https://op.example.",
		"a label with a hyphen end": "https://op-.example",
		"a label of 64":             "https://" + strings.Repeat("a", 64) + ".example",
		"markup in the path":        "https://op.example/<script>",
		"an empty segment":          "https://op.example//x",
		"a trailing slash":          "https://op.example/",
		"port 0":                    "https://op.example:0",
		"port 99999":                "https://op.example:99999",
		"port 65536":                "https://op.example:65536",
		"a port with a leading 0":   "https://op.example:0443",
		"a quote in the path":       "https://op.example/a\"b",
	} {
		if err := checkEntityIdentifier(iss); !errors.Is(err, ErrEntityIdentifier) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, iss := range []string{"https://op.example", "https://op.example/tenant", "https://op.example:8443/a-b_c~d", "https://127.0.0.1:4443/op", "https://op.example:65535/a:b;c=d"} {
		if err := checkEntityIdentifier(iss); err != nil {
			t.Errorf("%q: %v", iss, err)
		}
	}
}

func TestOWASP_InputValidation_PARResponse(t *testing.T) {
	for name, body := range map[string]string{
		"no request_uri":            `{"expires_in":60}`,
		"empty request_uri":         `{"request_uri":"","expires_in":60}`,
		"overlong request_uri":      `{"request_uri":"urn:` + strings.Repeat("r", 509) + `","expires_in":60}`,
		"request_uri with CRLF":     `{"request_uri":"urn:r\r\nX: y","expires_in":60}`,
		"request_uri with a space":  `{"request_uri":"urn:r s","expires_in":60}`,
		"request_uri with bidi":     `{"request_uri":"urn:r\u202e","expires_in":60}`,
		"request_uri http":          `{"request_uri":"http://op.example/r","expires_in":60}`,
		"request_uri javascript":    `{"request_uri":"javascript:alert(1)","expires_in":60}`,
		"request_uri data":          `{"request_uri":"data:text/html,x","expires_in":60}`,
		"request_uri file":          `{"request_uri":"file:///etc/passwd","expires_in":60}`,
		"request_uri in upper case": `{"request_uri":"URN:r","expires_in":60}`,
		"request_uri a number":      `{"request_uri":1,"expires_in":60}`,
		"https with user info":      `{"request_uri":"https://u@op.example/r","expires_in":60}`,
		"https with a fragment":     `{"request_uri":"https://op.example/r#x","expires_in":60}`,
		"no expires_in":             `{"request_uri":"urn:r"}`,
		"expires_in zero":           `{"request_uri":"urn:r","expires_in":0}`,
		"expires_in of 601":         `{"request_uri":"urn:r","expires_in":601}`,
		"expires_in negative":       `{"request_uri":"urn:r","expires_in":-1}`,
		"expires_in an exponent":    `{"request_uri":"urn:r","expires_in":6e1}`,
		"expires_in a fraction":     `{"request_uri":"urn:r","expires_in":60.5}`,
		"expires_in huge":           `{"request_uri":"urn:r","expires_in":1e400}`,
		"expires_in a string":       `{"request_uri":"urn:r","expires_in":"60"}`,
		"request_uri named twice":   `{"request_uri":"urn:r","request_uri":"urn:s","expires_in":60}`,
		"request_uri in other case": `{"REQUEST_URI":"urn:r","expires_in":60}`,
		"deeply nested":             `{"request_uri":"urn:r","expires_in":60,"x":` + strings.Repeat("[", 9) + strings.Repeat("]", 9) + `}`,
		"not UTF-8":                 "{\"request_uri\":\"urn:r\",\"expires_in\":60,\"x\":\"\xff\"}",
	} {
		if _, err := parsePARResponse([]byte(body)); !errors.Is(err, ErrPARResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, body := range []string{
		`{"request_uri":"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c","expires_in":60}`,
		`{"request_uri":"https://op.example/r/1","expires_in":600,"unknown":{"x":1}}`,
	} {
		if _, err := parsePARResponse([]byte(body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// RFC 9126 section 2.2 answers a PAR with 201 and a JSON body; RFC 6749 section 5.1 a token request with 200 and one.
// Anything else is refused before the body is read, and the ID token has to be a JWE before go-jose parses it.
func TestServerRule28_AResponseIsCheckedBeforeItIsRead(t *testing.T) {
	for name, c := range map[string]struct {
		par  bool
		h    http.HandlerFunc
		want error
	}{
		"PAR with 200":             {true, answer(http.StatusOK, "application/json", `{"request_uri":"urn:r","expires_in":60}`), openid.ErrErrorResponse},
		"PAR as HTML":              {true, answer(http.StatusCreated, "text/html", `{"request_uri":"urn:r","expires_in":60}`), openid.ErrResponseContentType},
		"PAR without a type":       {true, answer(http.StatusCreated, "", `{"request_uri":"urn:r","expires_in":60}`), openid.ErrResponseContentType},
		"token with 201":           {false, answer(http.StatusCreated, "application/json", `{"token_type":"Bearer"}`), openid.ErrErrorResponse},
		"token as text":            {false, answer(http.StatusOK, "text/plain", `{"token_type":"Bearer"}`), openid.ErrResponseContentType},
		"token in Latin-1":         {false, answer(http.StatusOK, "application/json; charset=iso-8859-1", `{"token_type":"Bearer"}`), openid.ErrResponseContentType},
		"token without id_token":   {false, answer(http.StatusOK, "application/json", `{"token_type":"Bearer"}`), openid.ErrTokenResponse},
		"token with a JWS":         {false, answer(http.StatusOK, "application/json", `{"token_type":"Bearer","id_token":"eyJhbGciOiJub25lIn0.e30."}`), openid.ErrTokenResponse},
		"token with six parts":     {false, answer(http.StatusOK, "application/json", `{"token_type":"Bearer","id_token":"a.b.c.d.e.f"}`), openid.ErrTokenResponse},
		"token type mac":           {false, answer(http.StatusOK, "application/json", `{"token_type":"mac","id_token":"a.b.c.d.e"}`), openid.ErrTokenResponse},
		"error as HTML":            {false, answer(http.StatusBadRequest, "text/html", `<h1>no</h1>`), openid.ErrResponseContentType},
		"an error without error":   {false, answer(http.StatusBadRequest, "application/json", `{"error_description":"x"}`), openid.ErrErrorResponse},
		"a JWE header named twice": {false, answer(http.StatusOK, "application/json", `{"token_type":"Bearer","id_token":"eyJhbGciOiJFQ0RILUVTIiwiYWxnIjoiZGlyIn0..aXY.Y2lwaGVy.dGFn"}`), openid.ErrProtectedHeader},
	} {
		stub := newLoginStub(t)
		stub.answering(t, c.h)
		var err error
		if c.par {
			_, err = stub.client.AuthenticationURL(t.Context(), validLogin())
		} else {
			_, _, err = stub.client.ExchangeIdentity(t.Context(), nLogin(), "code")
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOWASP_InputValidation_ErrorResponse(t *testing.T) {
	refusal := func(body string) *Error {
		t.Helper()
		var oidcErr *Error
		if err := parseErrorResponse(&openid.Response{Status: 400, ContentType: "application/json", Body: []byte(body)}); !errors.As(err, &oidcErr) {
			t.Fatalf("%s: %v", body, err)
		}
		return oidcErr
	}
	got := refusal(`{"error":"invalid_request","error_description":"bad <b>state</b>","error_uri":"javascript:alert(1)","gematik_code":"2004","gematik_uuid":"u-1","gematik_timestamp":1700000000,"operation":"AUTHORIZE"}`)
	if *got != (Error{ErrorCode: "invalid_request", Description: "bad <b>state</b>", GematikCode: "2004", GematikUUID: "u-1", GematikTimestamp: 1700000000, Operation: "AUTHORIZE"}) {
		t.Errorf("%+v", got)
	}
	if got := refusal(`{"error":"invalid_request","errorDescription":"camel"}`); got.Description != "camel" {
		t.Errorf("errorDescription stands in for a missing error_description: %+v", got)
	}
	for name, member := range map[string]string{
		"CRLF": `"a\r\nb"`, "NUL": `"a\u0000b"`, "bidi": `"a\u202eb"`, "non-ASCII": `"ä"`, "a quote": `"a\"b"`,
		"overlong": `"` + strings.Repeat("a", 257) + `"`, "a number": `1`, "an object": `{}`,
	} {
		got := refusal(`{"error":"x","error_description":` + member + `,"errorDescription":` + member + `,"gematik_code":` + member + `,"gematik_uuid":` + member + `,"operation":` + member + `,"gematik_timestamp":"1"}`)
		if *got != (Error{ErrorCode: "x"}) {
			t.Errorf("%s: kept %+v, dropped is right", name, got)
		}
	}
	for name, body := range map[string]string{
		"no error": `{"error_description":"x"}`, "error with CRLF": `{"error":"a\r\nb"}`, "error overlong": `{"error":"` + strings.Repeat("e", 65) + `"}`,
		"error named twice": `{"error":"a","error":"b"}`, "not JSON": `invalid_request`, "error in other case": `{"Error":"a"}`,
	} {
		if err := parseErrorResponse(&openid.Response{Status: 400, ContentType: "application/json", Body: []byte(body)}); !errors.Is(err, openid.ErrErrorResponse) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Server rule 14 and servers.md rule 28: an error names the field and the reason, never the value refused, which may
// come from a request or a response and must not reach a log line.
func TestServerRule14_ARefusedValueIsNotInTheError(t *testing.T) {
	const marker = "MARKER-0123456789"
	stub := newLoginStub(t)
	counting := stub.answering(t, answer(http.StatusOK, "application/json", `{}`))
	login := validLogin()
	errs := map[string]error{}
	_, _, errs["code"] = stub.client.ExchangeIdentity(t.Context(), nLogin(), marker+"\r\n")
	login.RedirectURI = "https://" + marker + ".example/cb"
	_, errs["redirect_uri"] = stub.client.AuthenticationURL(t.Context(), login)
	login = validLogin()
	login.State = marker + "."
	_, errs["state"] = stub.client.AuthenticationURL(t.Context(), login)
	login = validLogin()
	login.Scopes = []string{"openid", marker}
	_, errs["scope"] = stub.client.AuthenticationURL(t.Context(), login)
	errs["entity identifier"] = checkEntityIdentifier("https://" + marker + ".example/%2f")
	errs["federation URL"] = checkFederationURL("http://" + marker + ".example")
	rp := &RelyingParty{}
	_, errs["idp_iss"] = rp.Client(t.Context(), "https://"+marker+".example/..")
	_, errs["PAR response"] = parsePARResponse([]byte(`{"request_uri":"javascript:` + marker + `","expires_in":60}`))
	_, errs["token response"] = openid.ParseTokenResponse([]byte(`{"token_type":"` + marker + `"}`))
	errs["error response"] = parseErrorResponse(&openid.Response{Status: 400, ContentType: "application/json", Body: []byte(`{"error":"` + marker + `\n"}`)})
	_, errs["duplicate member"] = parsePARResponse([]byte(`{"` + marker + `":1,"` + marker + `":2}`))
	for field, err := range errs {
		if err == nil {
			t.Errorf("%s: accepted", field)
			continue
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the error holds the value: %v", field, err)
		}
	}
	if n := counting.requests.Load(); n != 0 {
		t.Fatalf("%d refused requests reached the IDP", n)
	}
}
