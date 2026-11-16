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

package conformance

import (
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Vector is one case of spec/pkcs12/testdata/private-key-info.json.
type Vector struct {
	ID     string `json:"id"`
	Expect string `json:"expect"`
	// Input is der for a check vector, value for a keyBag vector.
	Input []byte
	// Key is what a keyBag vector that decodes returns.
	Key []byte
}

type vectorJSON struct {
	ID     string `json:"id"`
	Expect string `json:"expect"`
	DER    string `json:"der"`
	Value  string `json:"value"`
	Key    string `json:"key"`
}

// PrivateKeyInfoVectors reads the shared PrivateKeyInfo vectors of spec/pkcs12:
// the PrivateKeyInfo encodings of the P12-041 check, and the keyBag values a
// legacy decoder normalises and then checks.
func PrivateKeyInfoVectors(t testing.TB) (check, keyBag []Vector) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "spec", "pkcs12", "testdata", "private-key-info.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Check  []vectorJSON `json:"check"`
		KeyBag []vectorJSON `json:"key_bag"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	convert := func(in []vectorJSON) []Vector {
		out := make([]Vector, 0, len(in))
		for _, v := range in {
			input, err := hex.DecodeString(v.DER + v.Value)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			key, err := hex.DecodeString(v.Key)
			if err != nil {
				t.Fatalf("%s: %v", v.ID, err)
			}
			if v.Expect != "ok" && v.Expect != "malformed" {
				t.Fatalf("%s: expect %q", v.ID, v.Expect)
			}
			out = append(out, Vector{ID: v.ID, Expect: v.Expect, Input: input, Key: key})
		}
		return out
	}
	return convert(vectors.Check), convert(vectors.KeyBag)
}
