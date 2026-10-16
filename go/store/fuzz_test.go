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
	"context"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/store"
)

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

// seeds adds the corpus outputs of a kind as fuzz seeds.
func seeds(f *testing.F, kinds ...string) {
	for _, c := range corpus(f) {
		for _, k := range kinds {
			if c.Kind != k || c.Expect.Code != "ok" {
				continue
			}
			for _, field := range []string{"record", "file"} {
				if s, ok := c.Expect.Output[field].(string); ok {
					b, _ := hex.DecodeString(s)
					f.Add(b)
				}
			}
		}
	}
}

// FuzzOpenRecord: any bytes as a sealed or plain record: errors, never panics, and
// nothing opens without the right key (spec/store section F).
func FuzzOpenRecord(f *testing.F) {
	seeds(f, "seal", "plain")
	keys, _ := store.Derive(bytes.Repeat([]byte{7}, 32))
	name, _ := keys.Name("popp", []byte("id"))
	f.Fuzz(func(t *testing.T, rec []byte) {
		_, err := store.OpenSealed(func(kid string) *[32]byte {
			if kid == "k1" {
				return keys.ValueKey()
			}
			return nil
		}, [16]byte{1}, "popp", name, time.Unix(0, 0), rec)
		if err == nil {
			t.Fatal("random bytes opened as a sealed record")
		}
		_, _ = store.OpenPlain(time.Unix(0, 0), rec)
	})
}

// FuzzKeyringFile: what parses encodes to the same bytes, and unwrapping under a wrong
// key never succeeds (STORE-005, section G).
func FuzzKeyringFile(f *testing.F) {
	seeds(f, "keyring_write")
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := store.ParseKeyringFile(b)
		if err != nil {
			return
		}
		if !bytes.Equal(k.Encode(), b) {
			t.Fatal("two encodings of one keyring")
		}
		w := store.NewKeyFileWrapper([32]byte{9}, bytes.NewReader(nil))
		if _, err := store.OpenKeyring(context.Background(), k, w, bytes.NewReader(nil)); err == nil {
			t.Fatal("a keyring opened under a wrong key")
		}
	})
}

// FuzzRecordFile: what parses encodes to the same bytes (STORE-080, STORE-086).
func FuzzRecordFile(f *testing.F) {
	seeds(f, "record_file_write")
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := store.ParseRecordFile(b); err == nil && !bytes.Equal(store.EncodeRecordFile(r), b) {
			t.Fatal("two encodings of one record file")
		}
		if m, err := store.ParseFilesMeta(b); err == nil && !bytes.Equal(m.Encode(), b) {
			t.Fatal("two encodings of one files meta")
		}
	})
}

// FuzzKEKFile: a key has one accepted encoding (STORE-094).
func FuzzKEKFile(f *testing.F) {
	f.Add([]byte(base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		kek, err := store.ParseKEKFile(b, 0o600)
		if err != nil {
			return
		}
		if base64.StdEncoding.EncodeToString(kek[:]) != string(bytes.TrimSuffix(b, []byte("\n"))) {
			t.Fatal("two encodings of one key")
		}
	})
}
