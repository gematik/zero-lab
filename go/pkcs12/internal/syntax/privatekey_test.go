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

package syntax

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

// oneAsymmetricKey builds a PrivateKeyInfo (RFC 5958 §2) from its parts;
// extra is appended inside the SEQUENCE after the private key.
func oneAsymmetricKey(t testing.TB, version int64, params []byte, privateKey []byte, extra ...[]byte) []byte {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidEd25519)
			b.AddBytes(params)
		})
		b.AddASN1OctetString(privateKey)
		for _, e := range extra {
			b.AddBytes(e)
		}
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pkcs8(t testing.TB, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestP12_041APrivateKeyInfoIsCheckedStrictly: what crypto/x509 writes and
// what RFC 5958 allows passes; anything else, including one octet more, is
// ErrParse.
func TestP12_041APrivateKeyInfoIsCheckedStrictly(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 34)
	attributes := []byte{0xA0, 0x00}
	publicKey := []byte{0x81, 0x02, 0x00, 0x01}
	null := []byte{0x05, 0x00}

	for name, der := range map[string][]byte{
		"RSA":                       pkcs8(t, rsaKey),
		"ECDSA":                     pkcs8(t, ecKey),
		"Ed25519":                   pkcs8(t, edKey),
		"v1 with attributes":        oneAsymmetricKey(t, 0, nil, seed, attributes),
		"v2 with public key":        oneAsymmetricKey(t, 1, nil, seed, publicKey),
		"v2 with both":              oneAsymmetricKey(t, 1, nil, seed, attributes, publicKey),
		"parameters of one element": oneAsymmetricKey(t, 0, null, seed),
	} {
		if err := CheckPrivateKeyInfo(der); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, der := range map[string][]byte{
		"empty":                        {},
		"trailing octet":               append(pkcs8(t, ecKey), 0),
		"version 2":                    oneAsymmetricKey(t, 2, nil, seed),
		"v1 with public key":           oneAsymmetricKey(t, 0, nil, seed, publicKey),
		"public key before attributes": oneAsymmetricKey(t, 1, nil, seed, publicKey, attributes),
		"unknown field":                oneAsymmetricKey(t, 1, nil, seed, null),
		"two parameters":               oneAsymmetricKey(t, 0, append(null, null...), seed),
		"empty private key":            oneAsymmetricKey(t, 0, nil, nil),
		"random octets":                []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"),
	} {
		if err := CheckPrivateKeyInfo(der); !errors.Is(err, ErrParse) {
			t.Errorf("%s: error = %v, want ErrParse", name, err)
		}
	}
}

func FuzzCheckPrivateKeyInfo(f *testing.F) {
	f.Add(oneAsymmetricKey(f, 1, []byte{0x05, 0x00}, make([]byte, 34), []byte{0xA0, 0x00}, []byte{0x81, 0x02, 0x00, 0x01}))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := CheckPrivateKeyInfo(data); err != nil && !errors.Is(err, ErrParse) {
			t.Fatalf("error outside ErrParse: %v", err)
		}
	})
}
