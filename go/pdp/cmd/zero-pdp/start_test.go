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

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rule 17: the refusal comes before any connection, so an unreachable database cannot hide it.
func TestServerRule17_APersistentStoreWithoutAKeyFileRefusesToStartNamingTheVariable(t *testing.T) {
	_, _, err := openStore("postgres://nobody@127.0.0.1:1/none", "")
	if err == nil {
		t.Fatal("started")
	}
	if !strings.Contains(err.Error(), "PDP_STORE_KEY_PATH") {
		t.Fatalf("%v", err)
	}
}

func TestServerRule17_ABrokenKeyFileRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.key")
	if err := os.WriteFile(path, []byte("k1 short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{"postgres://nobody@127.0.0.1:1/none", ""} {
		if _, _, err := openStore(dsn, path); err == nil || !strings.Contains(err.Error(), "PDP_STORE_KEY_PATH") {
			t.Fatalf("dsn %q: %v", dsn, err)
		}
	}
}

func TestOpenStore_InMemoryWithoutAKeyFileGetsAPerProcessNonceKey(t *testing.T) {
	store, keys, err := openStore("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if id, key := keys.Current(); id == "" || len(key) != 32 {
		t.Fatalf("current %q with %d key bytes", id, len(key))
	}
}

func TestOpenStore_InMemoryWithAKeyFileUsesItForNonces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.key")
	line := "k1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	store, keys, err := openStore("", path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if id, _ := keys.Current(); id != "k1" {
		t.Fatalf("current %q", id)
	}
}
