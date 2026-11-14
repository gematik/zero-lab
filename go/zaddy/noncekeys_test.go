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

package zaddy

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/gematik/zero-lab/go/nonce"
)

var _ nonce.Keys = (*nonceKeys)(nil)

func keyB64(b byte, n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, n))
}

func writeNonceKeys(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nonce.keys")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// provision provisions an app with the key file content, as Caddy does at start and on every config reload.
func provision(t *testing.T, content string) error {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	a := &App{DPoPNonceKeyringPath: writeNonceKeys(t, content)}
	return a.Provision(ctx)
}

func TestNonceKeys_TheFirstKeyIsCurrentAndAllOpen(t *testing.T) {
	keys, err := loadNonceKeys(writeNonceKeys(t, "# rotation\n\nk2 "+keyB64(2, 32)+"\nk1 "+keyB64(1, 32)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	id, key := keys.Current()
	if id != "k2" || !bytes.Equal(key, bytes.Repeat([]byte{2}, 32)) {
		t.Fatalf("current %q %x", id, key)
	}
	if key, ok := keys.Lookup("k1"); !ok || !bytes.Equal(key, bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("k1 %x %v", key, ok)
	}
	if _, ok := keys.Lookup("k3"); ok {
		t.Fatal("found a key the file does not hold")
	}
}

// The caller clears what it gets; the keys stay whole.
func TestNonceKeys_CurrentAndLookupReturnCopiesTheCallerOwns(t *testing.T) {
	keys, err := parseNonceKeys([]byte("k1 " + keyB64(1, 32)))
	if err != nil {
		t.Fatal(err)
	}
	_, key := keys.Current()
	clear(key)
	looked, _ := keys.Lookup("k1")
	clear(looked)
	if _, key := keys.Current(); !bytes.Equal(key, bytes.Repeat([]byte{1}, 32)) {
		t.Fatalf("a caller's clear reached the keys: %x", key)
	}
}

func TestNonceKeys_ABareKeyIsTheDefaultKey(t *testing.T) {
	keys, err := loadNonceKeys(writeNonceKeys(t, keyB64(7, 32)+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if id, key := keys.Current(); id != "default" || !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("current %q", id)
	}
}

func TestNonceKeys_AMalformedLineRefusesProvisioning(t *testing.T) {
	for name, content := range map[string]string{
		"three fields":              "k1 " + keyB64(1, 32) + " extra\n",
		"not base64":                "k1 !!!!\n",
		"a bare key beside another": "k1 " + keyB64(1, 32) + "\n" + keyB64(2, 32) + "\n",
		"a key beside a bare one":   keyB64(2, 32) + "\nk1 " + keyB64(1, 32) + "\n",
	} {
		if err := provision(t, content); err == nil || !strings.Contains(err.Error(), "line ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNonceKeys_AKeyNotOf32BytesRefusesProvisioning(t *testing.T) {
	for _, n := range []int{16, 31, 33, 64} {
		if err := provision(t, "k1 "+keyB64(1, n)+"\n"); err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

func TestNonceKeys_ADuplicateIDRefusesProvisioning(t *testing.T) {
	err := provision(t, "k1 "+keyB64(1, 32)+"\nk1 "+keyB64(2, 32)+"\n")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("%v", err)
	}
}

func TestNonceKeys_AnEmptyRingRefusesProvisioning(t *testing.T) {
	for _, content := range []string{"", "# only a comment\n\n"} {
		if err := provision(t, content); err == nil || !strings.Contains(err.Error(), "no keys") {
			t.Errorf("%q: %v", content, err)
		}
	}
}

func TestNonceKeys_AnInvalidIDRefusesProvisioning(t *testing.T) {
	for _, id := range []string{"k/1", "k:1", strings.Repeat("k", 65)} {
		if err := provision(t, id+" "+keyB64(1, 32)+"\n"); err == nil || !strings.Contains(err.Error(), "key ID") {
			t.Errorf("%q: %v", id, err)
		}
	}
}

// Errors name the line, never its content, which holds a key.
func TestNonceKeys_ErrorsNameNoKey(t *testing.T) {
	secret := keyB64(9, 16)
	if err := provision(t, "k1 "+secret+"\n"); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("%v", err)
	}
}

func TestNonceKeys_AMissingFileRefusesProvisioning(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	a := &App{DPoPNonceKeyringPath: filepath.Join(t.TempDir(), "absent")}
	if err := a.Provision(ctx); err == nil {
		t.Fatal("provisioned without the key file")
	}
}

func TestNonceKeys_ProvisioningWithAValidFileSealsNonces(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	a := &App{DPoPNonceKeyringPath: writeNonceKeys(t, "k1 "+keyB64(1, 32)+"\n")}
	if err := a.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	source, err := a.dpopNonces()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := source.Fresh(t.Context())
	if err != nil || fresh == "" {
		t.Fatalf("%q %v", fresh, err)
	}
}
