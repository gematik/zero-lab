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

package dpop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// Section 7.1, Figure 15: a request without authentication gets a challenge with algs only.
func TestRFC9449_7_1_Figure15_ChallengeWithoutError(t *testing.T) {
	v := newTestVerifier(t, Config{Algorithms: []jose.SignatureAlgorithm{jose.ES256, jose.PS256}})
	w := httptest.NewRecorder()
	v.WriteChallenge(w, &Error{Description: "no access token"})
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `DPoP algs="ES256 PS256"` {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

// Section 7.1, Figure 16: a failed key binding is invalid_token with its description.
func TestRFC9449_7_1_Figure16_ChallengeForInvalidKeyBinding(t *testing.T) {
	v := newTestVerifier(t, Config{})
	w := httptest.NewRecorder()
	v.WriteChallenge(w, &Error{Code: CodeInvalidToken, Description: "Invalid DPoP key binding"})
	want := `DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"`
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}

// RFC 6750 Section 3.1: a malformed request is 400; every other refusal 401.
func TestRFC9449_7_1_MalformedRequestIs400(t *testing.T) {
	v := newTestVerifier(t, Config{})
	w := httptest.NewRecorder()
	v.WriteChallenge(w, &Error{Code: CodeInvalidRequest, Description: "x"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%d", w.Code)
	}
}

// Section 9: a resource server requiring a nonce answers use_dpop_nonce in the challenge,
// with the nonce in DPoP-Nonce.
func TestRFC9449_9_ResourceServerNonceChallenge(t *testing.T) {
	v := newTestVerifier(t, Config{})
	w := httptest.NewRecorder()
	v.WriteChallenge(w, &Error{Code: CodeUseNonce, Description: "Resource server requires nonce in DPoP proof", Nonce: "eyJ7S_zG.eyJH0-Z.HX4w-7v"})
	want := `DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof", algs="ES256"`
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w.Header().Get(NonceHeaderName) != "eyJ7S_zG.eyJH0-Z.HX4w-7v" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", w.Header())
	}
}

// Section 8: an authorization server requiring a nonce answers 400 with an RFC 6749
// Section 5.2 body of use_dpop_nonce, the nonce in exactly one DPoP-Nonce header, uncacheable
// (Section 8.2).
func TestRFC9449_8_AuthorizationServerNonceError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteTokenError(w, &Error{Code: CodeUseNonce, Description: "Authorization server requires nonce in DPoP proof", Nonce: "eyJ7S_zG.eyJH0-Z.HX4w-7v"})
	if w.Code != http.StatusBadRequest || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if got := w.Header().Values(NonceHeaderName); len(got) != 1 || got[0] != "eyJ7S_zG.eyJH0-Z.HX4w-7v" {
		t.Fatalf("DPoP-Nonce %v", got)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "use_dpop_nonce" || body["error_description"] != "Authorization server requires nonce in DPoP proof" || len(body) != 2 {
		t.Fatalf("body %v", body)
	}
}

// Section 5: an invalid proof at the token endpoint is invalid_dpop_proof, 400.
func TestRFC9449_5_InvalidProofTokenError(t *testing.T) {
	w := httptest.NewRecorder()
	WriteTokenError(w, proofError("DPoP proof is too old"))
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusBadRequest || body["error"] != CodeInvalidProof || w.Header().Get(NonceHeaderName) != "" {
		t.Fatalf("%d %v %v", w.Code, body, w.Header())
	}
}

// Auth-param values are quoted-strings (RFC 9110 Section 5.6.4): quotes and backslashes are
// escaped, control characters dropped, so no description can break the header.
func TestRFC9110_5_6_4_ChallengeValuesAreQuotedStrings(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:     `"plain"`,
		`say "hi"`:  `"say \"hi\""`,
		`a\b`:       `"a\\b"`,
		"a\r\nb\tc": `"abc"`,
		"ä":         `""`,
	} {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %s, want %s", in, got, want)
		}
	}
}
