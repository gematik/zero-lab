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
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gematik/zero-lab/go/openid"
)

// withPAR points the stub provider's PAR endpoint at a server that counts the requests reaching it and keeps the last
// form.
func (s *loginStub) withPAR(t *testing.T) (pushed *atomic.Int64, form *atomic.Pointer[url.Values]) {
	t.Helper()
	pushed, form = new(atomic.Int64), new(atomic.Pointer[url.Values])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed.Add(1)
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		form.Store(&r.PostForm)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"request_uri":"urn:r","expires_in":60}`)
	}))
	t.Cleanup(server.Close)
	s.client.rp.httpClient = server.Client()
	s.metadata().PushedAuthorizationRequestEndpoint = server.URL
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
		t.Fatalf("err = %v", err)
	}
}

// gemSpec_IDP_Sek A_24403: the IDP lists the claims it supports, and a claim it does not list is not asked for.
func TestA_24403_AClaimTheIDPDoesNotSupportIsNotAskedFor(t *testing.T) {
	stub := newLoginStub(t)
	pushed, form := stub.withPAR(t)
	stub.metadata().ClaimsSupported = []string{"urn:telematik:claims:id", "amr"}
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
	stub.metadata().ClaimsSupported = nil
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
