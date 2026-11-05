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
func TestStoreKeys_APersistentStoreWithoutAKeyFileRefusesToStartNamingTheVariable(t *testing.T) {
	_, err := storeKeys("postgres://nobody@127.0.0.1:1/none", "")
	if err == nil {
		t.Fatal("started")
	}
	if !strings.Contains(err.Error(), "PEP_SESSION_STORE_KEY_PATH") {
		t.Fatalf("%v", err)
	}
}

func TestStoreKeys_ABrokenKeyFileRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.key")
	if err := os.WriteFile(path, []byte("k1 short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storeKeys("postgres://x", path); err == nil || !strings.Contains(err.Error(), "PEP_SESSION_STORE_KEY_PATH") {
		t.Fatalf("%v", err)
	}
}

// The file format PEP_SESSION_STORE_KEY_PATH had before stays a valid ring: an operator keeps the file.
func TestStoreKeys_ABareBase64KeyFileStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.key")
	bare := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"
	if err := os.WriteFile(path, []byte(bare), 0o600); err != nil {
		t.Fatal(err)
	}
	ring, err := storeKeys("postgres://x", path)
	if err != nil {
		t.Fatal(err)
	}
	if id, key := ring.Current(); id != "default" || len(key) != 32 {
		t.Fatalf("current %q", id)
	}
}

func TestStoreKeys_InMemoryNeedsNoKeyFile(t *testing.T) {
	ring, err := storeKeys("", "")
	if err != nil || ring != nil {
		t.Fatalf("ring %v err %v", ring, err)
	}
}

// Rule 17: the session cookie goes without Secure only where there is no TLS to require, on this machine.
func TestInsecureCookie_IsTakenForPlainHTTPOnThisMachineOnly(t *testing.T) {
	for _, publicURL := range []string{"http://localhost", "http://localhost:8080", "http://127.0.0.1", "http://127.0.0.1:4180"} {
		if err := checkInsecureCookie(publicURL); err != nil {
			t.Errorf("%s: %v", publicURL, err)
		}
	}
	for _, publicURL := range []string{
		"",
		"localhost:8080",
		"https://localhost",
		"https://127.0.0.1:8443",
		"https://pep.example",
		"http://pep.example",
		"http://localhost.evil.example",
		"http://127.0.0.1.evil.example",
		"http://localhost@evil.example",
		"http://10.0.0.1",
	} {
		err := checkInsecureCookie(publicURL)
		if err == nil {
			t.Errorf("%q accepted", publicURL)
			continue
		}
		if !strings.Contains(err.Error(), "PEP_INSECURE_COOKIE") || !strings.Contains(err.Error(), "PEP_PUBLIC_URL") {
			t.Errorf("%q: the variables are not named: %v", publicURL, err)
		}
	}
}
