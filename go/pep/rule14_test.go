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

package pep

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// marker and numberMarker stand for a token's content; an error that holds one carries the token into a log
// (servers.md rule 14). The decoder quotes a member's name and a number it cannot hold.
const (
	marker       = "PEER-INPUT-7f3a"
	numberMarker = "987654321987"
)

// requireRefusedFor asserts err refuses for its fixed reason and quotes none of the token.
func requireRefusedFor(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), numberMarker) {
		t.Fatalf("the error quotes the token: %v", err)
	}
	if err.Error() != reason {
		t.Fatalf("got %v, want %q", err, reason)
	}
}

// Server rule 14: a token is refused without its alg or its kid in the error.
func TestServerRule14_ARefusedTokensHeaderIsNotQuoted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1"}}}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", marker))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unknownKid, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = verifyJWS(unknownKid, keys)
	requireRefusedFor(t, err, "no key with the token's kid")

	enc := base64.RawURLEncoding.EncodeToString
	otherAlg := enc([]byte(`{"alg":"`+marker+`","kid":"k1"}`)) + "." + enc([]byte(`{}`)) + "." + enc([]byte("sig"))
	_, _, err = verifyJWS(otherAlg, keys)
	requireRefusedFor(t, err, "token is no compact JWS of an allowed algorithm")
}

// Server rule 14: a token's claims are refused by naming the claim, never by quoting a member's name or a value; a
// member named twice still unwraps to the decoder's reason.
func TestServerRule14_RefusedTokenClaimsAreNotQuoted(t *testing.T) {
	for name, test := range map[string]struct{ payload, reason string }{
		"a member twice": {`{"` + marker + `":1,"` + marker + `":2}`, "token claims: do not decode"},
		"a nested name":  {`{"x":{"` + marker + `":1 2}}`, "token claims: do not decode"},
		"exp":            {`{"exp":"` + marker + `"}`, "token claim exp: is no number"},
		"aud":            {`{"aud":[1,"` + marker + `"]}`, "token claim aud: is no string or array of strings"},
		"sub":            {`{"sub":` + numberMarker + `}`, "token claim sub: is no string"},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateClaims([]byte(test.payload), time.Unix(100, 0), 0, "")
			requireRefusedFor(t, err, test.reason)
			if name == "a member twice" && !errors.Is(err, jsontext.ErrDuplicateName) {
				t.Fatalf("got %v, want a duplicate name to unwrap", err)
			}
		})
	}
}

// Server rule 14: claims that do not fit the type a policy asks for are refused without the value.
func TestServerRule14_ClaimsOfAnotherTypeAreNotQuoted(t *testing.T) {
	c := &pepContext{claimsRaw: []byte(`{"n":` + numberMarker + `}`)}
	var claims struct {
		N uint8 `json:"n"`
	}
	requireRefusedFor(t, c.UnmarshalClaims(&claims), "token claims: do not decode into the type asked for")
}
