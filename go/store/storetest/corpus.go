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

package storetest

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/gematik/zero-lab/go/store"
)

// Case is one case of the manifest.
type Case struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Rules  []string `json:"rules"`
	Input  Obj      `json:"input"`
	Expect struct {
		Code   string `json:"code"`
		Output Obj    `json:"output"`
	} `json:"expect"`
}

// Load reads the manifest at path, keeping numbers exact.
func Load(t testing.TB, path string) []Case {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m struct{ Cases []Case }
	if err := d.Decode(&m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if len(m.Cases) == 0 {
		t.Fatalf("%s: no cases", path)
	}
	return m.Cases
}

// RunCorpus runs every case of the manifest at path that include accepts, as a subtest
// named after its most specific rule and its id, and fails if include accepts none, so
// that a renamed kind or backend cannot pass silently.
func RunCorpus(t *testing.T, path string, include func(Case) bool, backends Backends) {
	t.Helper()
	ran := 0
	for _, c := range Load(t, path) {
		if !include(c) {
			continue
		}
		ran++
		t.Run(c.Rules[0]+"/"+c.ID, func(t *testing.T) {
			code, out, err := Evaluate(c.Kind, c.Input, backends)
			if err != nil {
				t.Fatalf("broken case: %v", err)
			}
			if string(code) != c.Expect.Code {
				t.Fatalf("code %s, want %s", code, c.Expect.Code)
			}
			if code != store.CodeOK {
				return
			}
			want := c.Expect.Output
			if want == nil {
				want = Obj{}
			}
			if got, w := normalize(t, out), normalize(t, want); !reflect.DeepEqual(got, w) {
				t.Errorf("output\n got  %v\n want %v", got, w)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no case selected")
	}
}

// normalize gives a value the shape it has after a JSON round trip, so that outputs
// compare with reflect.DeepEqual.
func normalize(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var out any
	if err := d.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
