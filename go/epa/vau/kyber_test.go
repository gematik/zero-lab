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

package vau

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// kyberRounds is how many fresh key pairs each differential test tries; circl's kyber768 passes the Kyber
// v3.02 reference KATs, so agreeing with it on random keys both ways is agreeing with Kyber v3.02.
func kyberRounds(_ *testing.T) int {
	if testing.Short() {
		return 50
	}
	return 2000
}

// TestA_24425_KyberEncapsulatedByTheReferenceIsDecapsulatedHere shows the standard-library construction
// decapsulates what a Kyber v3.02 implementation encapsulates to its public key.
func TestA_24425_KyberEncapsulatedByTheReferenceIsDecapsulatedHere(t *testing.T) {
	scheme := kyber768.Scheme()
	for range kyberRounds(t) {
		ours, err := GenerateKEMKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := scheme.UnmarshalBinaryPublicKey(ours.PublicData)
		if err != nil {
			t.Fatalf("the reference does not read our public key: %v", err)
		}
		ciphertext, want, err := scheme.Encapsulate(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ours.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shared secrets differ:\n got %x\nwant %x", got, want)
		}
	}
}

// TestA_24425_KyberEncapsulatedHereIsDecapsulatedByTheReference shows a Kyber v3.02 implementation decapsulates
// what the standard-library construction encapsulates to its public key.
func TestA_24425_KyberEncapsulatedHereIsDecapsulatedByTheReference(t *testing.T) {
	scheme := kyber768.Scheme()
	for range kyberRounds(t) {
		publicKey, privateKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		publicData, err := publicKey.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		got, ciphertext, err := KEMData(publicData).Encapsulate()
		if err != nil {
			t.Fatal(err)
		}
		want, err := scheme.Decapsulate(privateKey, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shared secrets differ:\n got %x\nwant %x", got, want)
		}
	}
}

// TestA_24425_ACiphertextOfTheWrongSizeIsRefused is an internal invariant: decapsulation refuses what is not a
// Kyber768 ciphertext rather than deriving a key from it.
func TestA_24425_ACiphertextOfTheWrongSizeIsRefused(t *testing.T) {
	ours, err := GenerateKEMKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1087, 1089} {
		if _, err := ours.Decapsulate(make([]byte, size)); err == nil {
			t.Fatalf("a %d-byte ciphertext was decapsulated", size)
		}
	}
	if _, _, err := KEMData(make([]byte, 1183)).Encapsulate(); err == nil {
		t.Fatal("a 1183-byte public key was encapsulated to")
	}
}

// FuzzKyberDecapsulate feeds hostile ciphertexts: each is refused or yields a 32-byte secret, never a panic.
func FuzzKyberDecapsulate(f *testing.F) {
	ours, err := GenerateKEMKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	_, valid, err := ours.PublicData.Encapsulate()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(make([]byte, 1088))
	f.Add(bytes.Repeat([]byte{0xff}, 1088))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		secret, err := ours.Decapsulate(ciphertext)
		if err == nil && len(secret) != kyberSharedSecretSize {
			t.Fatalf("a %d-byte secret", len(secret))
		}
	})
}

// FuzzKyberEncapsulate feeds hostile public keys: each is refused or encapsulated to, never a panic.
func FuzzKyberEncapsulate(f *testing.F) {
	ours, err := GenerateKEMKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(ours.PublicData))
	f.Add(bytes.Repeat([]byte{0xff}, 1184))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, publicKey []byte) {
		secret, ciphertext, err := KEMData(publicKey).Encapsulate()
		if err == nil && (len(secret) != kyberSharedSecretSize || len(ciphertext) != 1088) {
			t.Fatalf("a %d-byte secret and a %d-byte ciphertext", len(secret), len(ciphertext))
		}
	})
}
