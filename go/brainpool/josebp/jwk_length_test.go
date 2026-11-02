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
	"encoding/json"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// RFC 7518 6.2.1.2, 6.2.2.1: x, y and d have the curve's full length, leading zeros included. big.Int drops
// them, so this searches for a key that has one in each place.
func TestRFC7518JWKCoordinatesHaveTheFullLength(t *testing.T) {
	const encodedLength = 43 // 32 bytes in unpadded base64url
	seen := map[string]bool{}
	for i := 0; i < 20000 && len(seen) < 3; i++ {
		key, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		short := func(name string, n int) {
			if n < 32 {
				seen[name] = true
			}
		}
		short("x", len(key.X.Bytes()))
		short("y", len(key.Y.Bytes()))
		short("d", len(key.D.Bytes()))
		for _, jwk := range []*JSONWebKey{{Key: key}, {Key: &key.PublicKey}} {
			data, err := json.Marshal(jwk)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"x", "y", "d"} {
				value, ok := fields[name].(string)
				if !ok || value == "" {
					continue
				}
				if len(value) != encodedLength {
					t.Fatalf("%s is %d characters: %s", name, len(value), value)
				}
				if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
					t.Fatal(err)
				}
			}
		}
		var parsed JSONWebKey
		data, err := json.Marshal(&JSONWebKey{Key: &key.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		public, ok := parsed.Key.(*ecdsa.PublicKey)
		if !ok || !public.Equal(&key.PublicKey) {
			t.Fatal("the key did not survive the round trip")
		}
	}
	if len(seen) < 3 {
		t.Fatalf("no key with a short coordinate in each place: %v", seen)
	}
}
