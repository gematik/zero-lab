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
// request and time.
func FuzzVerify(f *testing.F) {
	for _, seed := range []string{rfcFigure2Proof, rfcFigure7Proof, rfcFigure13Proof, "", "a.b.c", "e30.e30.", "=="} {
		f.Add(seed)
	}
	v, err := NewVerifier(Config{Clock: fixedClock(time.Unix(1562262616, 0))})
	if err != nil {
		f.Fatal(err)
	}
	req := Request{Method: "POST", URI: "https://server.example.com/token"}
	f.Fuzz(func(t *testing.T, value string) {
		h := http.Header{}
		h.Set(HeaderName, value)
		proof, err := v.Verify(h, req)
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
		if err == nil && !isToken68(token) {
			t.Fatalf("%q yields %q", value, token)
		}
	})
}
