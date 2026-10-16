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

package store_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/filestore"
	"github.com/gematik/zero-lab/go/store/internal/conformance"
)

type manifestCase struct {
	ID     string          `json:"id"`
	Kind   string          `json:"kind"`
	Rules  []string        `json:"rules"`
	Input  conformance.Obj `json:"input"`
	Expect struct {
		Code   string          `json:"code"`
		Output conformance.Obj `json:"output"`
	} `json:"expect"`
}

func corpus(t testing.TB) []manifestCase {
	t.Helper()
	raw, err := os.ReadFile("../../spec/store/testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var m struct{ Cases []manifestCase }
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) == 0 {
		t.Fatal("empty corpus")
	}
	return m.Cases
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

// backends: the files backend for real, in a temporary directory; the memory backend for
// the SQLite scenarios, whose semantics it shares (the SQLite backend is TASK-103.7).
func backends(t *testing.T) conformance.Backends {
	return func(name string) (store.Backend, func(), error) {
		switch name {
		case "files":
			b, err := filestore.Open(t.TempDir())
			if err != nil {
				return nil, nil, err
			}
			return b, func() { _ = b.Close() }, nil
		case "sqlite":
			return store.NewMemoryBackend(), func() {}, nil
		}
		return nil, nil, nil
	}
}

// TestSTORE_Corpus runs every case of spec/store as a subtest named after its most
// specific rule and its id.
func TestSTORE_Corpus(t *testing.T) {
	for _, c := range corpus(t) {
		t.Run(c.Rules[0]+"/"+c.ID, func(t *testing.T) {
			if c.Kind == "capabilities" && c.Input["backend"] == "sqlite" {
				t.Skip("SQLite backend not in this module yet (TASK-103.7); the memory backend stands in only for its scenarios")
			}
			code, out, err := conformance.Evaluate(c.Kind, c.Input, backends(t))
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
				want = conformance.Obj{}
			}
			if got, w := normalize(t, out), normalize(t, want); !reflect.DeepEqual(got, w) {
				t.Errorf("output\n got  %v\n want %v", got, w)
			}
		})
	}
}
