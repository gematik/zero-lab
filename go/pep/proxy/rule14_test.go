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
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// marker stands for the authorization server's or a browser's input; an error or a log line that holds it carries
// that input out of the workload (servers.md rule 14).
const marker = "PEER-INPUT-7f3a"

// rule14Backend is a PDP backend whose every endpoint answers status with body.
func rule14Backend(t *testing.T, status int, body string) (*pdpBackend, *Session) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	_, jwkJSON, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	return &pdpBackend{
		cfg: PDPConfig{ASIssuer: "https://as.example", ClientID: "c", SigningKey: testSigningKey(t)},
		meta: asMetadata{
			Issuer: "https://as.example", TokenEndpoint: server.URL + "/token", IntrospectionEndpoint: server.URL + "/introspect",
			OpenidProvidersEndpoint: server.URL + "/providers", PushedAuthorizationRequestEndpoint: server.URL + "/par",
		},
		http: server.Client(), signer: sessionKeySigner{},
	}, &Session{ID: "s1", DPoPKeyJWK: jwkJSON}
}

// Server rule 14: an authorization server's refusal is named by the endpoint, the status and a registered error
// code; its body, an unregistered code and error_description are not repeated.
func TestServerRule14_AnAuthorizationServersRefusalIsNotQuoted(t *testing.T) {
	for name, body := range map[string]string{
		"a registered code":   `{"error":"invalid_grant","error_description":"` + marker + `"}`,
		"an unregistered one": `{"error":"` + marker + `"}`,
		"text":                marker,
	} {
		t.Run(name, func(t *testing.T) {
			b, sess := rule14Backend(t, http.StatusBadRequest, body)
			_, parErr := b.pushAuthorizationRequest(t.Context(), sess, url.Values{})
			_, tokenErr := b.tokenRequest(t.Context(), sess, url.Values{})
			_, authErr := b.resolveDecoupledAuthURL(b.meta.TokenEndpoint)
			for _, err := range []error{parErr, tokenErr, authErr} {
				if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "400") {
					t.Errorf("got %v, want the status without the body", err)
				}
				if name == "a registered code" && !strings.Contains(err.Error(), "invalid_grant") {
					t.Errorf("got %v, want the registered code", err)
				}
			}
		})
	}
}

// Server rule 14: an authorization server's answer that does not decode is named, not quoted: the decoder's message
// would carry a member's name. The decoder's reason still unwraps.
func TestServerRule14_AnUndecodableAnswerIsNotQuoted(t *testing.T) {
	twice := `{"` + marker + `":1,"` + marker + `":2}`
	b, sess := rule14Backend(t, http.StatusOK, twice)
	_, tokenErr := b.tokenRequest(t.Context(), sess, url.Values{})
	_, introspectErr := b.introspectIdentity(t.Context(), sess, "at")
	b, _ = rule14Backend(t, http.StatusOK, "["+twice+"]")
	_, providersErr := b.fetchProviders()
	b, sess = rule14Backend(t, http.StatusCreated, twice)
	_, parErr := b.pushAuthorizationRequest(t.Context(), sess, url.Values{})
	for _, err := range []error{tokenErr, introspectErr, providersErr, parErr} {
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("got %v, want a refusal without the member's name", err)
		}
		if !errors.Is(err, jsontext.ErrDuplicateName) {
			t.Errorf("got %v, want a duplicate name to unwrap", err)
		}
	}
}

// Server rule 14: metadata naming another issuer or an endpoint that is no https URL is refused by the member's name,
// not by the URL the authorization server sent.
func TestServerRule14_RefusedMetadataIsNotQuoted(t *testing.T) {
	for name, set := range map[string]func(*asMetadata){
		"another issuer":   func(md *asMetadata) { md.Issuer = "https://" + marker },
		"a plain endpoint": func(md *asMetadata) { md.AuthorizationEndpoint = "http://" + marker },
		"no endpoint URL":  func(md *asMetadata) { md.TokenEndpoint = marker },
	} {
		md := fullMetadata("https://as.example")
		set(&md)
		err := checkMetadata(md, "https://as.example")
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Server rule 14: an identity provider's error on the callback is logged as a registered code at most; the browser
// brings it, so an unregistered code and error_description stay out of the log.
func TestServerRule14_AnIdentityProvidersErrorIsNotLogged(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/oauth2/callback?state=test-state&error="+marker+"&error_description="+marker, nil)
	req.AddCookie(&http.Cookie{Name: s.cookie.Name, Value: sess.token}) //nolint:gosec // request cookie in a test
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if !strings.Contains(logs.String(), "refused the login") || strings.Contains(logs.String(), marker) {
		t.Errorf("log:\n%s", logs.String())
	}
}
