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

package gemidp_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestJWECross(t *testing.T) {
	jwkPrivateString := `{"crv":"P-256","d":"Pn9q2dmPV8y9VnWFycf7fQDrR-h5Uh-a8VWjamfZn58","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`
	jwkPublicString := `{"crv":"P-256","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`

	prk, _ := jwk.ParseKey([]byte(jwkPrivateString))
	puk, _ := jwk.ParseKey([]byte(jwkPublicString))

	t.Logf("Private Key: %v", prk.KeyType())
	t.Logf("Public Key: %v", puk.KeyType())

	plaintext := []byte("Hello, World!")

	// josebp is Brainpool-only; get the NIST P-256 public key via jwx (not josebp.JSONWebKey).
	var pukEC ecdsa.PublicKey
	if err := jwk.Export(puk, &pukEC); err != nil {
		t.Fatalf("export public key: %v", err)
	}
	cipher, err := josebp.NewJWEBuilder().
		Plaintext(plaintext).
		EncryptECDHES(&pukEC)
	if err != nil {
		t.Fatalf("Encrypt returned an error: %v", err)
	}

	t.Logf("(2) Encrypted: %v", string(cipher))
	/*
		challengeResponseEncrypter, err := gjwe.NewEncrypter(pukBP.Key.(*ecdsa.PublicKey))
		if err != nil {
			t.Fatalf("creating challenge response encrypter: %v", err)
		}
		challengeResponseJwe, err := challengeResponseEncrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypting challenge response: %v", err)
		}

		cipherStr, err := challengeResponseJwe.CompactSerialize()
		if err != nil {
			t.Fatalf("serializing challenge response: %v", err)
		}

		cipher = []byte(cipherStr)

		t.Logf("(1) Encrypted: %v", string(cipher))
	*/
	decrypted, err := jwe.Decrypt(cipher, jwe.WithKey(jwa.ECDH_ES(), prk))
	if err != nil {
		t.Fatalf("Decrypt returned an error: %v", err)
	}

	t.Logf("Decrypted: %v", string(decrypted))

}
