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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRFC6749_4_1_3_ALoginRepeatsItsRedirectURIInBothRequests(t *testing.T) {
	login := Login{State: "s", Nonce: "n", Verifier: "v", RedirectURI: "https://rp/own"}
	query, err := AuthorizationQuery("c", "https://rp/configured", []string{"openid"}, login)
	if err != nil {
		t.Fatal(err)
	}
	if got := query.Get("redirect_uri"); got != "https://rp/own" {
		t.Errorf("authorization request: %s", got)
	}
	if got := login.RedirectFor("https://rp/configured"); got != "https://rp/own" {
		t.Errorf("token request: %s", got)
	}
	if got := (Login{}).RedirectFor("https://rp/configured"); got != "https://rp/configured" {
		t.Errorf("no override: %s", got)
	}
}

func TestRFC7636_4_3_AuthorizationQuerySendsPKCEAndNeverTheVerifier(t *testing.T) {
	query, err := AuthorizationQuery("c", "https://rp/cb", []string{"openid", "email"}, Login{State: "s", Nonce: "n", Verifier: "secret"})
	if err != nil {
		t.Fatal(err)
	}
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

func TestOIDCCore_5_5_TheClaimsParameterIsAJSONObject(t *testing.T) {
	claims := `{"id_token":{"acr":{"essential":true}}}`
	query, err := AuthorizationQuery("c", "https://rp/cb", []string{"openid"}, Login{Claims: json.RawMessage(claims)})
	if err != nil {
		t.Fatal(err)
	}
	if got := query.Get("claims"); got != claims {
		t.Errorf("claims sent: %q", got)
	}
	query, err = AuthorizationQuery("c", "https://rp/cb", []string{"openid"}, Login{})
	if err != nil || query.Has("claims") {
		t.Errorf("no claims asked for, sent %q (%v)", query.Get("claims"), err)
	}

	tooLarge := `{"id_token":{"x":"` + strings.Repeat("a", MaxClaimsBytes) + `"}}`
	for name, claims := range map[string]string{
		"array":          `[]`,
		"string":         `"id_token"`,
		"null":           `null`,
		"number":         `1`,
		"trailing data":  `{} {}`,
		"not json":       `{id_token}`,
		"larger than 4K": tooLarge,
	} {
		_, err := AuthorizationQuery("c", "https://rp/cb", []string{"openid"}, Login{Claims: json.RawMessage(claims)})
		if !errors.Is(err, ErrClaimsParameter) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && len(claims) > 2 && strings.Contains(err.Error(), claims) {
			t.Errorf("%s: the error holds the refused value: %v", name, err)
		}
	}
}

func TestOIDCCore_3_1_2_1_ScopesAndACRValuesArePerLogin(t *testing.T) {
	login := Login{Scopes: []string{"openid", "urn:telematik:versicherter"}, ACRValues: []string{"gematik-ehealth-loa-high", "gematik-ehealth-loa-substantial"}}
	query, err := AuthorizationQuery("c", "https://rp/cb", []string{"openid", "email"}, login)
	if err != nil {
		t.Fatal(err)
	}
	if got := query.Get("scope"); got != "openid urn:telematik:versicherter" {
		t.Errorf("scope: %q", got)
	}
	if got := query.Get("acr_values"); got != "gematik-ehealth-loa-high gematik-ehealth-loa-substantial" {
		t.Errorf("acr_values: %q", got)
	}

	query, err = AuthorizationQuery("c", "https://rp/cb", []string{"openid", "email"}, Login{})
	if err != nil {
		t.Fatal(err)
	}
	if query.Get("scope") != "openid email" || query.Has("acr_values") {
		t.Errorf("without per-login values: %v", query)
	}

	for name, tc := range map[string]struct {
		login Login
		want  error
	}{
		"scope with a space":    {Login{Scopes: []string{"openid email"}}, ErrScope},
		"empty scope":           {Login{Scopes: []string{"openid", ""}}, ErrScope},
		"scope with a quote":    {Login{Scopes: []string{`a"b`}}, ErrScope},
		"acr with a space":      {Login{ACRValues: []string{"loa high"}}, ErrACRValue},
		"empty acr":             {Login{ACRValues: []string{""}}, ErrACRValue},
		"acr with a backslash":  {Login{ACRValues: []string{`a\b`}}, ErrACRValue},
		"acr outside ASCII":     {Login{ACRValues: []string{"stufe-hoch-ü"}}, ErrACRValue},
		"acr with a line break": {Login{ACRValues: []string{"a\nb"}}, ErrACRValue},
	} {
		_, err := AuthorizationQuery("c", "https://rp/cb", []string{"openid"}, tc.login)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
		for _, value := range append(tc.login.Scopes, tc.login.ACRValues...) {
			if value != "" && value != "openid" && err != nil && strings.Contains(err.Error(), value) {
				t.Errorf("%s: the error holds the refused value: %v", name, err)
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
