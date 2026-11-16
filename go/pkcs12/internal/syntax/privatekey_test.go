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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
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

// FuzzCheckPrivateKeyInfo: the check and the join of a keyBag's publicKey
// return ErrParse or nothing; the join leaves a key that passes the check
// unchanged, fails only on what the check refuses, and what it joins passes or
// fails the check without panicking. The shared vectors of spec/pkcs12 seed it.
func FuzzCheckPrivateKeyInfo(f *testing.F) {
	for _, seed := range sharedVectors(f) {
		f.Add(seed)
	}
	f.Add(oneAsymmetricKey(f, 1, []byte{0x05, 0x00}, make([]byte, 34), []byte{0xA0, 0x00}, []byte{0x81, 0x02, 0x00, 0x01}))
	f.Add(oneAsymmetricKey(f, 0, []byte{0xBF, 0x81, 0x00, 0x02, 0x05, 0x00}, make([]byte, 34)))
	f.Add(oneAsymmetricKey(f, 1, nil, make([]byte, 34), []byte{0xA1, 0x08, 0x03, 0x02, 0x00, 0xAA, 0x03, 0x02, 0x04, 0xB0}))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		err := CheckPrivateKeyInfo(data)
		if err != nil && !errors.Is(err, ErrParse) {
			t.Fatalf("error outside ErrParse: %v", err)
		}
		joined, joinErr := JoinPublicKey(data)
		if joinErr != nil && !errors.Is(joinErr, ErrParse) {
			t.Fatalf("join error outside ErrParse: %v", joinErr)
		}
		if err == nil && (joinErr != nil || !bytes.Equal(joined, data)) {
			t.Fatalf("the join changed a checked key: % X", data)
		}
		if joinErr != nil && err == nil {
			t.Fatalf("the join refused a checked key: % X", data)
		}
		if joinErr == nil {
			if err := CheckPrivateKeyInfo(joined); err != nil && !errors.Is(err, ErrParse) {
				t.Fatalf("error outside ErrParse on the joined key: %v", err)
			}
		}
	})
}

// sharedVectors returns the inputs of spec/pkcs12/testdata/private-key-info.json:
// the PrivateKeyInfo encodings of the check and the keyBag values. Package
// conformance reads them for the tests, but imports this package.
func sharedVectors(t testing.TB) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "spec", "pkcs12", "testdata", "private-key-info.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Check []struct {
			DER string `json:"der"`
		} `json:"check"`
		KeyBag []struct {
			Value string `json:"value"`
		} `json:"key_bag"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var seeds [][]byte
	add := func(h string) {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, b)
	}
	for _, v := range vectors.Check {
		add(v.DER)
	}
	for _, v := range vectors.KeyBag {
		add(v.Value)
	}
	if len(seeds) == 0 || len(seeds[0]) == 0 {
		t.Fatal("no shared vectors")
	}
	return seeds
}
