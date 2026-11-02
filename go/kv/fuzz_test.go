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

package kv_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gematik/zero-lab/go/kv"
)

// fuzzSealedRecord is "value" sealed under kv key "a", purpose "fuzz" and the key in FuzzSealedOpen. It is a
// constant because each fuzz worker runs the setup anew, and a record sealed there would differ in every one.
const fuzzSealedRecord = "01026b317e9647004446ddf8b6a7c72e2e64efc4e833bc94ca1093904436dca0603f268474d9aad2cd215e945f26f2058df26f5ee9"

// FuzzSealedOpen feeds whatever a store could hold to the record parser: it must never panic,
// never hand back a value it did not seal itself, and name every refusal ErrIntegrity.
func FuzzSealedOpen(f *testing.F) {
	ctx := context.Background()
	ring, err := kv.ParseKeyring([]byte("k1 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"))
	if err != nil {
		f.Fatal(err)
	}
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, ring, "fuzz")
	good, err := hex.DecodeString(fuzzSealedRecord)
	if err != nil {
		f.Fatal(err)
	}
	if err := raw.Set(ctx, "a", good, 0); err != nil {
		f.Fatal(err)
	}
	if got, _, err := sealed.Get(ctx, "a"); err != nil || string(got) != "value" {
		f.Fatalf("the fixture does not open: %q, %v", got, err)
	}
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, 255})
	f.Add([]byte{1, 0})
	f.Add([]byte(`{"id":"s1"}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		if err := raw.Set(ctx, "a", value, 0); err != nil {
			t.Fatal(err)
		}
		got, found, err := sealed.Get(ctx, "a")
		if err == nil {
			if !found || !bytes.Equal(value, good) || string(got) != "value" {
				t.Fatalf("opened %x as %q, found=%v", value, got, found)
			}
			return
		}
		if !errors.Is(err, kv.ErrIntegrity) || found || got != nil {
			t.Fatalf("value %x: %q found=%v err=%v", value, got, found, err)
		}
	})
}

// FuzzParseKeyring: an accepted file always yields a usable ring.
func FuzzParseKeyring(f *testing.F) {
	f.Add([]byte("k1 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"))
	f.Add([]byte("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"))
	f.Add([]byte("# comment\n\nk2 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\r\nk1 AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n"))
	f.Add([]byte("k1 k1 k1\n"))
	f.Add([]byte{0, 0xff, '\n'})
	f.Fuzz(func(t *testing.T, data []byte) {
		ring, err := kv.ParseKeyring(data)
		if err != nil {
			return
		}
		id, key := ring.Current()
		if id == "" || len(id) > 64 || len(key) != 32 {
			t.Fatalf("current %q with %d key bytes", id, len(key))
		}
		if looked, ok := ring.Lookup(id); !ok || !bytes.Equal(looked, key) {
			t.Fatalf("the current key %q is not found by its ID", id)
		}
	})
}
