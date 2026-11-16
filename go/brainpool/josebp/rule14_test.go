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

package josebp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// marker stands for the peer's input; an error that holds it would carry that input into a log (servers.md rule 14).
const marker = "PEER-INPUT-7f3a"

// requireRefusedFor asserts err refuses for its fixed reason and quotes none of the input.
func requireRefusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("the error quotes the input: %v", err)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("got %v, want %q", err, reason)
	}
}

// Server rule 14: a JWK is refused by naming what is wrong with it, never by quoting its kty, crv, a member's value
// or a member's name. A member named twice still unwraps to the decoder's reason. The decoder reads a whole value
// before it calls UnmarshalJSON, so a member named twice is the caller's json.Unmarshal to word, and is tried on
// UnmarshalJSON alone.
func TestServerRule14_ARefusedJWKIsNotQuoted(t *testing.T) {
	for name, test := range map[string]struct{ raw, reason string }{
		"kty":              {`{"kty":"` + marker + `","crv":"BP-256","x":"AA","y":"AA"}`, "unsupported key type"},
		"crv":              {`{"kty":"EC","crv":"` + marker + `","x":"AA","y":"AA"}`, "unsupported Brainpool curve"},
		"a mistyped value": {`{"kty":"EC","crv":"BP-256","x":"AA","y":"AA","kid":["` + marker + `"]}`, "JWK: does not decode"},
		"a member twice":   {`{"kty":"EC","` + marker + `":1,"` + marker + `":2}`, "JWK: does not decode"},
	} {
		t.Run(name, func(t *testing.T) {
			var jwk JSONWebKey
			err := jwk.UnmarshalJSON([]byte(test.raw))
			requireRefusedFor(t, err, test.reason)
			if name == "a member twice" {
				if !errors.Is(err, jsontext.ErrDuplicateName) {
					t.Fatalf("got %v, want a duplicate name to unwrap", err)
				}
				return
			}
			requireRefusedFor(t, json.Unmarshal([]byte(test.raw), &jwk), test.reason)
		})
	}
}

// Server rule 14: a token is refused by naming the header or claim that is wrong, never by quoting its alg or a
// member of its header or claims.
func TestServerRule14_ARefusedTokenIsNotQuoted(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	for name, parts := range map[string][3]string{
		"alg":                     {`{"alg":"` + marker + `"}`, `{}`, "unsupported signature algorithm"},
		"a header member twice":   {`{"alg":"BP256R1","` + marker + `":1,"` + marker + `":2}`, `{}`, "token header: does not decode"},
		"a claims member twice":   {`{"alg":"BP256R1"}`, `{"` + marker + `":1,"` + marker + `":2}`, "token claims: does not decode"},
		"a header value mistyped": {`["` + marker + `"]`, `{}`, "token header: does not decode"},
		"a claims value mistyped": {`{"alg":"BP256R1"}`, `"` + marker + `"`, "token claims: does not decode"},
	} {
		t.Run(name, func(t *testing.T) {
			token := enc([]byte(parts[0])) + "." + enc([]byte(parts[1])) + "." + enc(make([]byte, 64))
			_, err := ParseToken([]byte(token), withECDSAPublicKey(&key.PublicKey))
			requireRefusedFor(t, err, parts[2])
		})
	}
}
