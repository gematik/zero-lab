package gemidp_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWECross(t *testing.T) {
	jwkPrivateString := `{"crv":"P-256","d":"Pn9q2dmPV8y9VnWFycf7fQDrR-h5Uh-a8VWjamfZn58","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`
	jwkPublicString := `{"crv":"P-256","kty":"EC","x":"YDnAaDYvsBz6QKYOj0CUYSeydmD1QHL5pUl-aMu6cA0","y":"ovzYSeBnMCmZYWZZtKcGaABqaPs_ecWDXJ8H5bqHOVA"}`

	prk, _ := jwk.ParseKey([]byte(jwkPrivateString))
	puk, _ := jwk.ParseKey([]byte(jwkPublicString))

	t.Logf("Private Key: %v", prk.KeyType())
	t.Logf("Public Key: %v", puk.KeyType())

	plaintext := []byte("Hello, World!")

	pukBP := new(brainpool.JSONWebKey)
	if err := json.Unmarshal([]byte(jwkPublicString), pukBP); err != nil {
		t.Fatalf("Unmarshal returned an error: %v", err)
	}
	cipher, err := brainpool.NewJWEBuilder().
		Plaintext(plaintext).
		EncryptECDHES(pukBP.Key.(*ecdsa.PublicKey))

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
	decrypted, err := jwe.Decrypt(cipher, jwe.WithKey(jwa.ECDH_ES, prk))
	if err != nil {
		t.Fatalf("Decrypt returned an error: %v", err)
	}

	t.Logf("Decrypted: %v", string(decrypted))

}
