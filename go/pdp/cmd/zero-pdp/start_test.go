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
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
	"github.com/gematik/zero-lab/go/pdp/authzserver"
)

// The interfaces are met by shape, so that the modules need not import each other; this is where that holds.
var (
	_ nonce.Keys = (*kv.Keyring)(nil)
	_ kv.Keys    = nonce.Keys(nil)
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

// Server rule 11: two replicas wired on one store share sessions, nonce redemptions and DPoP replays.
func TestServerRule11_ReplicasWiredOnOneStoreShareTheirState(t *testing.T) {
	store := kv.NewMemory()
	var a, b authzserver.Config
	wireStores(&a, store, testKeyring(t))
	wireStores(&b, store, testKeyring(t))
	until := time.Now().Add(time.Minute)
	if err := a.Sessions.SaveAutzhServerSession(&authzserver.Session{ID: "s1", Code: "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sessions.GetAuthzServerSessionByCode("c1"); err != nil {
		t.Fatalf("session at the other replica: %v", err)
	}
	if seen, err := a.NonceRedemptions.Seen(t.Context(), "n1", until); err != nil || seen {
		t.Fatalf("first redemption: %v %v", seen, err)
	}
	if seen, err := b.NonceRedemptions.Seen(t.Context(), "n1", until); err != nil || !seen {
		t.Fatalf("redemption at the other replica: %v %v", seen, err)
	}
	if seen, err := a.Replays.Seen(t.Context(), "p1", until); err != nil || seen {
		t.Fatalf("first proof: %v %v", seen, err)
	}
	if seen, err := b.Replays.Seen(t.Context(), "p1", until); err != nil || !seen {
		t.Fatalf("proof at the other replica: %v %v", seen, err)
	}
	// A nonce id and a proof id that are equal stay apart.
	if seen, err := a.Replays.Seen(t.Context(), "n1", until); err != nil || seen {
		t.Fatalf("a proof id collided with a nonce id: %v %v", seen, err)
	}
}
