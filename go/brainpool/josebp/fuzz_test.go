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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// flawedJSON is JSON no encoder writes, named after its flaw.
type flawedJSON struct {
	name string
	data []byte
}

// flawedJWKs are JWKs of an otherwise valid brainpoolP256r1 point that name a member twice, are
// not UTF-8 or name a member in another case (servers.md rule 28).
func flawedJWKs() []flawedJSON {
	x, y := brainpool.P256r1().ScalarBaseMult([]byte{0x2a})
	members := `"crv":"BP-256","x":"` + b64(x.FillBytes(make([]byte, 32))) + `","y":"` + b64(y.FillBytes(make([]byte, 32))) + `"}`
	return []flawedJSON{
		{"member twice", []byte(`{"kty":"EC","kty":"EC",` + members)},
		{"not UTF-8", []byte(`{"kty":"EC","x5u":"` + "\xff" + `",` + members)},
		{"member in another case", []byte(`{"KTY":"EC",` + members)},
	}
}

// flawedTokens are tokens signed by key, otherwise valid, whose header or payload names a
// member twice, at the top or nested, is not UTF-8, or names a member in another case.
func flawedTokens(key *ecdsa.PrivateKey) []flawedJSON {
	sign := func(header, payload string) []byte {
		input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		digest := sha256.Sum256([]byte(input))
		signature, err := brainpool.SignFuncPrivateKey(key)(digest[:])
		if err != nil {
			panic(err)
		}
		return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
	}
	header := `{"alg":"BP256R1","typ":"JWT"}`
	payload := `{"iss":"https://idp.example.test","sub":"s"}`
	return []flawedJSON{
		{"header member twice", sign(`{"alg":"BP256R1",`+header[1:], payload)},
		{"payload member twice", sign(header, `{"iss":"x",`+payload[1:])},
		{"nested member twice", sign(header, `{"cnf":{"jkt":"a","jkt":"a"},`+payload[1:])},
		{"header not UTF-8", sign(`{"kid":"`+"\xff"+`",`+header[1:], payload)},
		{"payload not UTF-8", sign(header, `{"sub":"`+"\xff"+`",`+payload[1:])},
		{"header member in another case", sign(strings.Replace(header, `"alg"`, `"ALG"`, 1), payload)},
	}
}

// JWK unmarshalling must never panic on malformed JSON.
func FuzzJSONWebKeyUnmarshal(f *testing.F) {
	f.Add([]byte(`{"kty":"EC","crv":"BP-256","x":"AA","y":"AA"}`))
	f.Add([]byte(`{}`))
	for _, flawed := range flawedJWKs() {
		f.Add(flawed.data)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		var jwk JSONWebKey
		_ = json.Unmarshal(data, &jwk)
	})
}

// Token parsing/verification must never panic on malformed input.
func FuzzParseToken(f *testing.F) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("a.b.c"))
	f.Add([]byte(""))
	for _, flawed := range flawedTokens(key) {
		f.Add(flawed.data)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseToken(data, withECDSAPublicKey(&key.PublicKey))
	})
}
