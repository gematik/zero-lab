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
	"encoding/json"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// JWK unmarshalling must never panic on malformed JSON.
func FuzzJSONWebKeyUnmarshal(f *testing.F) {
	f.Add([]byte(`{"kty":"EC","crv":"BP-256","x":"AA","y":"AA"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
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
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseToken(data, withECDSAPublicKey(&key.PublicKey))
	})
}
