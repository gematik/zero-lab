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
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// FuzzParseKeySet feeds arbitrary documents to the key set parser. Invariants: it never panics, and every key it
// returns can be marshalled back.
func FuzzParseKeySet(f *testing.F) {
	for _, seed := range []string{
		`{"keys":[` + p256JWK + `]}`, p256JWK, `{"keys":[` + x25519JWK + `,` + offCurveJWK + `]}`,
		`{"keys":[]}`, `{"keys":null}`, `{"keys":{"keys":[]}}`, `null`, ``, `[]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := ParseKeySet(data)
		if err != nil {
			return
		}
		for i := range keys.Keys {
			if _, err := keys.Keys[i].MarshalJSON(); err != nil {
				t.Fatalf("parsed a key that does not marshal: %v", err)
			}
		}
	})
}

// FuzzVerifyJWS feeds arbitrary tokens to the verifier. Invariants: it never panics, and it accepts nothing but what
// the one trusted key signed, which only the seed is.
func FuzzVerifyJWS(f *testing.F) {
	key := newECKey(f, elliptic.P256())
	token := signToken(f, jose.ES256, key, "k", testPayload)
	f.Add(token)
	for _, seed := range []string{"", "a.b.c", "e30.e30.", "e30.e30.e30", "==", `{"payload":"e30"}`} {
		f.Add(seed)
	}
	keys := setOf(jose.JSONWebKey{Key: key.Public(), KeyID: "k"})
	f.Fuzz(func(t *testing.T, raw string) {
		payload, err := VerifyJWS([]byte(raw), keys, VerifyOptions{})
		if err == nil && string(payload) != string(testPayload) {
			t.Fatalf("accepted a payload nobody signed: %q", payload)
		}
	})
}

// FuzzValidateClaims feeds arbitrary payloads to the claim checks. Invariants: they never panic, and a payload that
// passes the ID token checks names the expected issuer and audience.
func FuzzValidateClaims(f *testing.F) {
	for _, seed := range []string{
		`{"iss":"i","aud":"c","nonce":"n","exp":2000000000}`, `{"aud":["c"],"exp":1.5}`, `{"exp":1e300}`, `{"iss":null}`, `null`, `[]`, ``,
	} {
		f.Add([]byte(seed))
	}
	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, payload []byte) {
		_ = ValidateLifetime(payload, now, time.Minute)
		_ = ValidateAudience(payload, "c")
		if err := (IDTokenChecks{Nonce: "n", Issuer: "i", ClientID: "c", Now: now, Skew: time.Minute}).Validate(payload); err != nil {
			return
		}
		claims, err := parseClaims(payload)
		if err != nil {
			t.Fatalf("passed the checks but does not parse: %v", err)
		}
		if claims.issuer == nil || *claims.issuer != "i" || claims.expiry == nil || claims.nonce == "" {
			t.Fatalf("passed without its required claims: %s", payload)
		}
	})
}

// A token from a provider reaches Claims after verification only by the callers' discipline, so it must not panic.
func FuzzTokenResponseClaims(f *testing.F) {
	for _, seed := range []string{"", "nodots", "one.dot", "a.b.c", "a.e30.c", "a.b.c.d"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, token string) {
		var claims map[string]any
		_ = (&TokenResponse{IDTokenRaw: token}).Claims(&claims)
	})
}
