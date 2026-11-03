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

package rc2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestRFC2268Vectors runs the test vectors of RFC 2268 §5.
func TestRFC2268Vectors(t *testing.T) {
	tests := []struct {
		key        string
		bits       int
		plaintext  string
		ciphertext string
	}{
		{"0000000000000000", 63, "0000000000000000", "ebb773f993278eff"},
		{"ffffffffffffffff", 64, "ffffffffffffffff", "278b27e42e2f0d49"},
		{"3000000000000000", 64, "1000000000000001", "30649edf9be7d2c2"},
		{"88", 64, "0000000000000000", "61a8a244adacccf0"},
		{"88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"},
		{"88bca90e90875a7f0f79c384627bafb2", 64, "0000000000000000", "1a807d272bbe5db1"},
		{"88bca90e90875a7f0f79c384627bafb2", 128, "0000000000000000", "2269552ab0f85ca6"},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", 129, "0000000000000000", "5b78d3a43dfff1f1"},
	}
	for _, tt := range tests {
		t.Run(tt.key+"/"+tt.ciphertext, func(t *testing.T) {
			key, _ := hex.DecodeString(tt.key)
			plaintext, _ := hex.DecodeString(tt.plaintext)
			want, _ := hex.DecodeString(tt.ciphertext)

			block, err := New(key, tt.bits)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, BlockSize)
			block.Encrypt(got, plaintext)
			if !bytes.Equal(got, want) {
				t.Errorf("Encrypt = %x, want %x", got, want)
			}
			block.Decrypt(got, want)
			if !bytes.Equal(got, plaintext) {
				t.Errorf("Decrypt = %x, want %x", got, plaintext)
			}
		})
	}
}

func TestNewRejectsInvalidParameters(t *testing.T) {
	for _, tt := range []struct {
		key  int
		bits int
	}{{0, 64}, {129, 64}, {8, 0}, {8, 1025}} {
		if _, err := New(make([]byte, tt.key), tt.bits); err == nil {
			t.Errorf("New(%d-byte key, %d bits) succeeded", tt.key, tt.bits)
		}
	}
}
