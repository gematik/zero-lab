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
	"errors"
	"net/http"
	"testing"
	"time"
)

// FuzzVerify feeds arbitrary DPoP header values to the verifier. Invariants: it never panics,
// every refusal is an *Error with a code, and nothing but the RFC example is accepted at its
// request and time. The seeds include proofs for that request and time whose JSON names a
// member twice, is not UTF-8 or names a member in another case (servers.md rule 28).
func FuzzVerify(f *testing.F) {
	for _, seed := range []string{rfcFigure2Proof, rfcFigure7Proof, rfcFigure13Proof, "", "a.b.c", "e30.e30.", "=="} {
		f.Add(seed)
	}
	issued := time.Unix(1562262616, 0)
	req := Request{Method: "POST", URI: "https://server.example.com/token"}
	claims := map[string]any{"jti": "e1j3V_bKic8-LAEB", "htm": req.Method, "htu": req.URI, "iat": issued.Unix()}
	for _, p := range newTestKey(f).flawedProofs(f, claims) {
		f.Add(p.proof)
	}
	v, err := NewVerifier(Config{Clock: fixedClock(issued)})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		h := http.Header{}
		h.Set(HeaderName, value)
		proof, err := v.Verify(t.Context(), h, req)
		if err == nil {
			if value != rfcFigure2Proof && proof.Thumbprint != rfcJKT {
				t.Fatalf("accepted a proof not signed by the example key: %q", value)
			}
			return
		}
		var e *Error
		if !errors.As(err, &e) || e.Code == "" {
			t.Fatalf("refusal without a code: %v", err)
		}
	})
}

// FuzzNormalizeHTU checks that normalization never panics and is idempotent.
func FuzzNormalizeHTU(f *testing.F) {
	for _, seed := range []string{"https://a.test/b/../c", "HTTP://A.test:80/%7e?q#f", "https://[::1]:443/", "https://a.test/%2"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		once, err := normalizeHTU(raw)
		if err != nil {
			return
		}
		twice, err := normalizeHTU(once)
		if err != nil || twice != once {
			t.Fatalf("%q normalizes to %q, then to %q (%v)", raw, once, twice, err)
		}
	})
}

// FuzzAccessToken checks that credential parsing never panics and returns only token68.
func FuzzAccessToken(f *testing.F) {
	for _, seed := range []string{"DPoP " + rfcAccessToken, "Bearer x", "dpop  a=", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		token, err := AccessToken(http.Header{"Authorization": {value}})
		if err == nil && !IsToken68(token) {
			t.Fatalf("%q yields %q", value, token)
		}
	})
}
