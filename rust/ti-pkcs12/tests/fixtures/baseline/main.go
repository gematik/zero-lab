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

// Command baseline writes go-baseline.json: what go/pkcs12 decodes from every fixture of
// rust/ti-pkcs12/tests/fixtures, which tests/decode.rs holds ti-pkcs12 against.
//
//	baseline DIR > DIR/go-baseline.json
//
// It reads DIR/*.p12 with pkcs12.Decode and DIR/legacy/*.p12, the BER vendor files, with
// legacy.Decode. The output depends on the certificates, keys and attributes in the files, not
// on their salts and IVs.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
)

type bag struct {
	Subject      string `json:"subject,omitempty"`
	FriendlyName string `json:"friendly_name"`
	LocalKeyID   string `json:"local_key_id"`
	SHA256       string `json:"sha256"`
}

type entry struct {
	File         string `json:"file"`
	Certificates []bag  `json:"certificates"`
	Keys         []bag  `json:"keys"`
	Pairs        int    `json:"pairs"`
	// Error is the code of spec/pkcs12/CONFORMANCE.md, not go/pkcs12's wording.
	Error string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: baseline DIR")
		os.Exit(2)
	}
	entries, err := describe(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}

func describe(dir string) ([]entry, error) {
	var names []string
	for _, pattern := range []string{"*.p12", "legacy/*.p12"} {
		found, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range found {
			name, err := filepath.Rel(dir, path)
			if err != nil {
				return nil, err
			}
			names = append(names, filepath.ToSlash(name))
		}
	}
	slices.Sort(names)

	entries := make([]entry, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, filepath.FromSlash(name))
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		password, err := passwordOf(path)
		if err != nil {
			return nil, err
		}
		decode := pkcs12.Decode
		if strings.HasPrefix(name, "legacy/") {
			decode = legacy.Decode
		}
		e := entry{File: name, Certificates: []bag{}, Keys: []bag{}}
		bags, err := decode(data, password)
		if err != nil {
			e.Error = code(err)
			entries = append(entries, e)
			continue
		}
		for _, c := range bags.Certificates {
			b := bag{FriendlyName: c.FriendlyName, LocalKeyID: hex.EncodeToString(c.LocalKeyID), SHA256: digest(c.Raw)}
			if cert, err := x509.ParseCertificate(c.Raw); err == nil {
				b.Subject = cert.Subject.CommonName
			}
			e.Certificates = append(e.Certificates, b)
		}
		for _, k := range bags.PrivateKeys {
			e.Keys = append(e.Keys, bag{FriendlyName: k.FriendlyName, LocalKeyID: hex.EncodeToString(k.LocalKeyID), SHA256: digest(k.Raw)})
		}
		e.Pairs = len(bags.FindMatchingPairs())
		entries = append(entries, e)
	}
	return entries, nil
}

// passwordOf is the password of a fixture: the content of NAME-password.txt beside it, the
// empty one for empty-pass.p12, test1234 otherwise (as tests/decode.rs has it).
func passwordOf(path string) ([]byte, error) {
	beside := strings.TrimSuffix(path, ".p12") + "-password.txt"
	password, err := os.ReadFile(beside)
	switch {
	case err == nil:
		return []byte(strings.TrimSpace(string(password))), nil
	case !os.IsNotExist(err):
		return nil, err
	case filepath.Base(path) == "empty-pass.p12":
		return nil, nil
	default:
		return []byte("test1234"), nil
	}
}

func code(err error) string {
	switch {
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

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
