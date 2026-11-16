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
	"bufio"
	"bytes"
	"crypto/mlkem"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// kyberVectors reads testdata/kyber768-v302-circl.txt, made once with circl's Kyber768 v3.02, which passes the
// Kyber reference KATs: "decapsulate" lines hold an ML-KEM-768 decapsulation key (d‖z), a ciphertext circl
// encapsulated to its public key, and circl's shared secret; "publickey" lines hold public keys from circl's
// Kyber key generation. The generator is in the file's header; the vectors stand in for running circl here.
func kyberVectors(t *testing.T, kind string) [][][]byte {
	t.Helper()
	file, err := os.Open("testdata/kyber768-v302-circl.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out [][][]byte
	scanner := bufio.NewScanner(file)
	scanner.Buffer(nil, 1<<16)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != kind {
			continue
		}
		var row [][]byte
		for _, field := range fields[1:] {
			b, err := hex.DecodeString(field)
			if err != nil {
				t.Fatal(err)
			}
			row = append(row, b)
		}
		out = append(out, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no %s vectors", kind)
	}
	return out
}

// TestA_24425_KyberEncapsulatedByTheReferenceIsDecapsulatedHere shows the standard-library construction
// decapsulates what Kyber v3.02 encapsulated to its public key, to the same shared secret.
func TestA_24425_KyberEncapsulatedByTheReferenceIsDecapsulatedHere(t *testing.T) {
	for _, v := range kyberVectors(t, "decapsulate") {
		seed, ciphertext, want := v[0], v[1], v[2]
		key, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		got, err := kyberDecapsulate(key, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("shared secrets differ:\n got %x\nwant %x", got, want)
		}
	}
}

// TestA_24425_KyberPublicKeysAreEncapsulatedTo shows a public key of Kyber v3.02's key generation is one the
// construction encapsulates to; that the reference decapsulates the result is shown live by TestEPA_Connect.
func TestA_24425_KyberPublicKeysAreEncapsulatedTo(t *testing.T) {
	for _, v := range kyberVectors(t, "publickey") {
		secret, ciphertext, err := KEMData(v[0]).Encapsulate()
		if err != nil {
			t.Fatalf("a Kyber public key was refused: %v", err)
		}
		if len(secret) != kyberSharedSecretSize || len(ciphertext) != 1088 {
			t.Fatalf("a %d-byte secret and a %d-byte ciphertext", len(secret), len(ciphertext))
		}
	}
}

// TestA_24425_WhatIsEncapsulatedHereDecapsulatesHere is an internal invariant: the construction agrees with
// itself on fresh keys.
func TestA_24425_WhatIsEncapsulatedHereDecapsulatesHere(t *testing.T) {
	for range 100 {
		ours, err := GenerateKEMKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		want, ciphertext, err := ours.PublicData.Encapsulate()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ours.Decapsulate(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("shared secrets differ")
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
