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

//go:build mockidp

package mockidp

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth"
	"github.com/gematik/zero-lab/go/oauth/oidc"
)

type hostFunc struct {
	issuer, opCallback string
	add                func(oidc.Client)
}

func (h hostFunc) IssuerBaseURL() string     { return h.issuer }
func (h hostFunc) OPCallbackURL() string     { return h.opCallback }
func (h hostFunc) AddProvider(c oidc.Client) { h.add(c) }

func TestMockOPRunsAuthCodeFlow(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var captured oidc.Client
	host := hostFunc{issuer: srv.URL, opCallback: srv.URL + "/op-callback", add: func(c oidc.Client) { captured = c }}
	if err := Register(host, mux, Identity{Subject: "X110000001", Claims: map[string]any{"name": "Test User"}}); err != nil {
		t.Fatal(err)
	}
	if captured == nil {
		t.Fatal("provider was not registered")
	}
	if captured.Issuer() != srv.URL+"/mock-idp" {
		t.Fatalf("issuer = %q", captured.Issuer())
	}

	verifier := oauth.GenerateVerifier()
	authURL, err := captured.AuthenticationURL(t.Context(), oidc.Login{State: "st-1", Nonce: "nonce-1", Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}

	// The login page renders the auth params as a form; submit them (POST /mock-idp/auth).
	au, _ := url.Parse(authURL)
	form := url.Values{}
	for _, k := range []string{"client_id", "redirect_uri", "state", "nonce", "code_challenge"} {
		form.Set(k, au.Query().Get(k))
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pr, err := noRedirect.PostForm(srv.URL+"/mock-idp/auth", form)
	if err != nil {
		t.Fatal(err)
	}
	if pr.StatusCode != http.StatusFound {
		t.Fatalf("auth submit status = %d, want 302", pr.StatusCode)
	}
	cu, _ := url.Parse(pr.Header.Get("Location"))
	if cu.Path != "/op-callback" || cu.Query().Get("state") != "st-1" {
		t.Fatalf("redirected to %q, want the op-callback with state", pr.Header.Get("Location"))
	}
	code := cu.Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code in op-callback redirect")
	}

	// This is exactly what OPCallbackEndpoint does: real /token round-trip + id_token validation.
	tr, err := captured.Exchange(t.Context(), oidc.Login{Nonce: "nonce-1", Verifier: verifier}, code)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	claims := map[string]any{}
	if err := tr.Claims(&claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "X110000001" {
		t.Errorf("sub = %v, want X110000001", claims["sub"])
	}
	if claims["name"] != "Test User" {
		t.Errorf("name = %v, want Test User", claims["name"])
	}
	if claims["nonce"] != "nonce-1" {
		t.Errorf("nonce = %v, want nonce-1", claims["nonce"])
	}
}

// mockClient has to refuse an id_token its provider did not sign or that does not name it, nonce and expiry included:
// the point of the mock is that login runs the same checks as with a real provider.
func TestMockClientRefusesAnIDTokenThatDoesNotHold(t *testing.T) {
	const issuer, clientID = "https://mock.example", "pdp-mock-client"
	exp := time.Now().Add(time.Minute).Unix()
	good := map[string]any{"iss": issuer, "aud": []string{clientID}, "nonce": "n", "exp": exp}
	signer, keys, err := newSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := newSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	with := func(name string, value any) map[string]any {
		claims := maps.Clone(good)
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
		return claims
	}
	sign := func(s jose.Signer, claims map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		object, err := s.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := object.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	for name, c := range map[string]struct {
		token string
		ok    bool
	}{
		"as issued":        {sign(signer, good), true},
		"another key":      {sign(other, good), false},
		"another issuer":   {sign(signer, with("iss", "https://evil.example")), false},
		"another audience": {sign(signer, with("aud", []string{"someone"})), false},
		"no nonce":         {sign(signer, with("nonce", nil)), false},
		"no exp":           {sign(signer, with("exp", nil)), false},
		"expired":          {sign(signer, with("exp", time.Now().Add(-time.Second).Unix())), false},
		"alg none":         {"eyJhbGciOiJub25lIn0." + strings.Split(sign(signer, good), ".")[1] + ".", false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": c.token})
			}))
			defer srv.Close()
			client := &mockClient{issuer: issuer, clientID: clientID, keys: keys, http: rewriteTo(srv)}
			if _, err := client.Exchange(t.Context(), oidc.Login{Nonce: "n", Verifier: "verifier"}, "code"); (err == nil) != c.ok {
				t.Fatalf("err = %v, want accepted %v", err, c.ok)
			}
		})
	}
}

// rewriteTo sends every request to srv, whatever issuer the client was given.
func rewriteTo(srv *httptest.Server) *http.Client {
	target, _ := url.Parse(srv.URL)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The mock's JWKS and id_tokens read as a provider's: kid and alg published, and the token names the key.
func TestMockOPPublishesItsKeyWithKidAndAlg(t *testing.T) {
	_, keys, err := newSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID == "" || keys.Keys[0].Algorithm != "ES256" || !keys.Keys[0].IsPublic() {
		t.Fatalf("keys = %+v", keys.Keys)
	}
}

func TestMockOPRefusesARedirectURIOrClientItDidNotRegister(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host := hostFunc{issuer: srv.URL, opCallback: srv.URL + "/op-callback", add: func(oidc.Client) {}}
	if err := Register(host, mux, Identity{Subject: "X110000001"}); err != nil {
		t.Fatal(err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for name, form := range map[string]url.Values{
		"another host":         {"client_id": {mockClientID}, "redirect_uri": {"https://evil.example/cb"}, "state": {"s"}},
		"below the registered": {"client_id": {mockClientID}, "redirect_uri": {srv.URL + "/op-callback/more"}, "state": {"s"}},
		"none":                 {"client_id": {mockClientID}, "state": {"s"}},
		"another client":       {"client_id": {"someone"}, "redirect_uri": {srv.URL + "/op-callback"}, "state": {"s"}},
	} {
		t.Run(name, func(t *testing.T) {
			page, err := noRedirect.Get(srv.URL + "/mock-idp/auth?" + form.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer page.Body.Close()
			if page.StatusCode != http.StatusBadRequest {
				t.Errorf("page = %d", page.StatusCode)
			}
			submit, err := noRedirect.PostForm(srv.URL+"/mock-idp/auth", form)
			if err != nil {
				t.Fatal(err)
			}
			defer submit.Body.Close()
			if submit.StatusCode != http.StatusBadRequest || submit.Header.Get("Location") != "" {
				t.Errorf("submit = %d to %q", submit.StatusCode, submit.Header.Get("Location"))
			}
		})
	}
}
