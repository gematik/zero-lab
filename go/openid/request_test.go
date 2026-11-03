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

package openid

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestALoginRepeatsItsRedirectURIInBothRequests(t *testing.T) {
	login := Login{State: "s", Nonce: "n", Verifier: "v", RedirectURI: "https://rp/own"}
	if got := AuthorizationQuery("c", "https://rp/configured", []string{"openid"}, login).Get("redirect_uri"); got != "https://rp/own" {
		t.Errorf("authorization request: %s", got)
	}
	if got := login.RedirectFor("https://rp/configured"); got != "https://rp/own" {
		t.Errorf("token request: %s", got)
	}
	if got := (Login{}).RedirectFor("https://rp/configured"); got != "https://rp/configured" {
		t.Errorf("no override: %s", got)
	}
}

func TestAuthorizationQuerySendsPKCEAndNeverTheVerifier(t *testing.T) {
	query := AuthorizationQuery("c", "https://rp/cb", []string{"openid", "email"}, Login{State: "s", Nonce: "n", Verifier: "secret"})
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("scope") != "openid email" {
		t.Errorf("%v", query)
	}
	for key, values := range query {
		for _, value := range values {
			if value == "secret" {
				t.Errorf("the verifier is in %s", key)
			}
		}
	}
}

func TestPostFormRefusesAnOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1))
	}))
	defer server.Close()
	if _, err := PostForm(t.Context(), server.Client(), server.URL, url.Values{}); err == nil {
		t.Error("a response over the limit")
	}
}

func TestPostFormReturnsStatusAndBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.FormValue("a") != "b" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	response, err := PostForm(t.Context(), server.Client(), server.URL, url.Values{"a": {"b"}})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusCreated || string(response.Body) != "ok" {
		t.Errorf("%d %s", response.Status, response.Body)
	}
}

func TestParseTokenResponseToleratesExpiresInAsAString(t *testing.T) {
	for _, body := range []string{`{"access_token":"a","expires_in":3600}`, `{"access_token":"a","expires_in":"3600"}`} {
		response, err := ParseTokenResponse([]byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if response.AccessToken != "a" || response.ExpiresIn != 3600 {
			t.Errorf("%s: %+v", body, response)
		}
	}
	if _, err := ParseTokenResponse([]byte("not json")); err == nil {
		t.Error("not JSON")
	}
}
