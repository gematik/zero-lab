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

// Package conformance runs the PKCS#12 conformance corpus of spec/pkcs12 in
// Go tests: it generates the corpus with the spec's own tool and compares a
// decoder's result with the expectations, as `p12conformance verify` does for
// external decoders.
package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/gematik/zero-lab/go/pkcs12"
)

// Case is one entry of the generated expected.json.
type Case struct {
	ID           string   `json:"id"`
	Encoding     string   `json:"encoding"`
	File         string   `json:"file"`
	PasswordFile string   `json:"password_file"`
	Profile      string   `json:"profile"`
	Codes        []string `json:"codes"`
	Result       struct {
		Certificates []item   `json:"certificates"`
		Keys         []item   `json:"keys"`
		Pairs        [][2]int `json:"pairs"`
	} `json:"result"`

	Data     []byte
	Password []byte
}

type item struct {
	SHA256       string `json:"sha256"`
	FriendlyName string `json:"friendly_name"`
}

// Corpus generates the corpus into a temporary directory and returns its
// cases. Without openssl the test is skipped.
func Corpus(t *testing.T) []Case {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed; the corpus is generated with it")
	}
	_, file, _, _ := runtime.Caller(0)
	spec := filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "spec", "pkcs12")
	out := t.TempDir()
	//nolint:gosec // G204: the arguments are paths of this repository and a temporary directory.
	cmd := exec.Command("go", "run", ".", "generate", "-manifest", filepath.Join(spec, "testdata", "manifest.json"), "-out", out)
	cmd.Dir = filepath.Join(spec, "tool")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating the corpus: %v\n%s", err, msg)
	}

	raw, err := os.ReadFile(filepath.Join(out, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []Case
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for i := range cases {
		if cases[i].Data, err = os.ReadFile(filepath.Join(out, cases[i].File)); err != nil {
			t.Fatal(err)
		}
		if cases[i].Password, err = os.ReadFile(filepath.Join(out, cases[i].PasswordFile)); err != nil {
			t.Fatal(err)
		}
	}
	return cases
}

// Code maps an error of package pkcs12 to the result code of the spec.
func Code(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, pkcs12.ErrLimitExceeded):
		return "limit_exceeded"
	case errors.Is(err, pkcs12.ErrUnsupportedAlgorithm):
		return "unsupported_algorithm"
	case errors.Is(err, pkcs12.ErrAuthentication):
		return "mac_mismatch"
	case errors.Is(err, pkcs12.ErrDecryption):
		return "decryption_failed"
	default:
		return "malformed"
	}
}

// Check compares a decoder result with the case.
func Check(t *testing.T, c Case, bags *pkcs12.Bags, err error) {
	t.Helper()
	code := Code(err)
	if !slices.Contains(c.Codes, code) {
		t.Fatalf("code %s (%v), want %v", code, err, c.Codes)
	}
	if code != "ok" {
		return
	}
	var certs, keys []item
	for _, cb := range bags.Certificates {
		certs = append(certs, item{digest(cb.Raw), cb.FriendlyName})
	}
	for _, kb := range bags.PrivateKeys {
		keys = append(keys, item{digest(kb.Raw), kb.FriendlyName})
	}
	match(t, "certificate", c.Result.Certificates, certs)
	match(t, "key", c.Result.Keys, keys)
	if got, want := len(bags.FindMatchingPairs()), len(c.Result.Pairs); got != want {
		t.Errorf("%d pairs, want %d", got, want)
	}
}

func match(t *testing.T, kind string, want, got []item) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d %ss, want %d", len(got), kind, len(want))
	}
	for _, w := range want {
		i := slices.IndexFunc(got, func(g item) bool { return g.SHA256 == w.SHA256 })
		if i < 0 {
			t.Errorf("%s %.12s missing", kind, w.SHA256)
			continue
		}
		if w.FriendlyName != "" && got[i].FriendlyName != w.FriendlyName {
			t.Errorf("%s %.12s: friendly name %q, want %q", kind, w.SHA256, got[i].FriendlyName, w.FriendlyName)
		}
	}
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
