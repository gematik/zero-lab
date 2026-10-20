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

package vau_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/gematik/zero-lab/go/epa/vau"
)

// secretWithSpareCapacity returns n secret bytes in an array with room behind them, filled
// with a sentinel, so a write past the secret's length shows.
func secretWithSpareCapacity(n int, b byte) (secret, array []byte) {
	array = bytes.Repeat([]byte{0xEE}, 4*n)
	for i := range n {
		array[i] = b
	}
	return array[:n], array
}

// KemKDF1 and KemKDF2 derive from the concatenated shared secrets and never write into the
// secrets their callers pass, even when those slices have spare capacity.
func TestKemKDF_DoesNotWriteIntoArguments(t *testing.T) {
	var arrays [][]byte
	secret := func(n int, b byte) []byte {
		s, a := secretWithSpareCapacity(n, b)
		arrays = append(arrays, slices.Clone(a), a)
		return s
	}
	ecdh1, kem1, ecdh2, kem2 := secret(32, 1), secret(32, 2), secret(32, 3), secret(32, 4)

	k1c2s, k1s2c, err := vau.KemKDF1(ecdh1, kem1)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hkdf.Key(sha256.New, slices.Concat(ecdh1, kem1), nil, "", 64)
	if !bytes.Equal(slices.Concat(k1c2s, k1s2c), want) {
		t.Fatal("KemKDF1 output differs from HKDF over ecdh || kem")
	}

	a, b, c, d, e, err := vau.KemKDF2(ecdh1, kem1, ecdh2, kem2)
	if err != nil {
		t.Fatal(err)
	}
	want, _ = hkdf.Key(sha256.New, slices.Concat(ecdh1, kem1, ecdh2, kem2), nil, "", 5*32)
	if !bytes.Equal(slices.Concat(a, b, c, d, e), want) {
		t.Fatal("KemKDF2 output differs from HKDF over the four secrets")
	}

	for i := 0; i < len(arrays); i += 2 {
		if !bytes.Equal(arrays[i], arrays[i+1]) {
			t.Fatalf("argument %d: the caller's array was written to", i/2)
		}
	}
}
