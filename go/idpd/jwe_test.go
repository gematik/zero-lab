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

package idpd_test

import (
	"bytes"
	"crypto/ecdsa"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// TestJWECross proves that what josebp encrypts on a NIST curve, which it does beside Brainpool, is a JWE another
// implementation decrypts.
func TestJWECross(t *testing.T) {
	jwkPrivateString := `{"crv":"P-256","d":"Pn9q2dmPV8y9VnWFycf7fQDrR-h5Uh-a8VWjamfZn58","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`

	prk, err := oidc.ParseKey([]byte(jwkPrivateString))
	if err != nil {
		t.Fatal(err)
	}
	private := prk.Key.(*ecdsa.PrivateKey)

	plaintext := []byte("Hello, World!")

	cipher, err := josebp.NewJWEBuilder().
		Plaintext(plaintext).
		EncryptECDHES(&private.PublicKey)
	if err != nil {
		t.Fatalf("Encrypt returned an error: %v", err)
	}

	encrypted, err := jose.ParseEncryptedCompact(string(cipher), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	decrypted, err := encrypted.Decrypt(private)
	if err != nil {
		t.Fatalf("Decrypt returned an error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted %q", decrypted)
	}
}
