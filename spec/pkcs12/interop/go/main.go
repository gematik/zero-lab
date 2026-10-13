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

// Command decoder is the go/pkcs12 adapter of the PKCS#12 conformance
// harness (spec/pkcs12/CONFORMANCE.md, command-line contract):
//
//	decoder [-legacy] decode --password-file FILE P12
//
// Without -legacy it decodes with pkcs12.Decode (profile modern), with
// -legacy with legacy.Decode (profile legacy).
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
	"github.com/gematik/zero-lab/go/pkcs12/legacy/ber"
)

type item struct {
	SHA256          string `json:"sha256"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	FriendlyName    string `json:"friendly_name,omitempty"`
	LocalKeyID      string `json:"local_key_id,omitempty"`
}

type result struct {
	Code         string   `json:"code"`
	Detail       string   `json:"detail,omitempty"`
	Certificates []item   `json:"certificates"`
	Keys         []item   `json:"keys"`
	Pairs        [][2]int `json:"pairs"`
	MAC          *string  `json:"mac"`
}

func main() {
	args := os.Args[1:]
	useLegacy := len(args) > 0 && args[0] == "-legacy"
	if useLegacy {
		args = args[1:]
	}
	if len(args) != 4 || args[0] != "decode" || args[1] != "--password-file" {
		fmt.Fprintln(os.Stderr, "usage: decoder [-legacy] decode --password-file FILE P12")
		os.Exit(2)
	}
	password, err := os.ReadFile(args[2]) //nolint:gosec // G703: the harness names the files to read.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	data, err := os.ReadFile(args[3]) //nolint:gosec // G703: the harness names the files to read.
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := json.Marshal(decode(data, password, useLegacy))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Println(string(out))
}

func decode(data, password []byte, useLegacy bool) result {
	r := result{Certificates: []item{}, Keys: []item{}, Pairs: [][2]int{}}
	var bags *pkcs12.Bags
	var err error
	if useLegacy {
		bags, err = legacy.Decode(data, password)
	} else {
		bags, err = pkcs12.Decode(data, password)
	}
	if err != nil {
		r.Code, r.Detail = code(err), err.Error()
		return r
	}
	r.Code = "ok"
	fill(&r, bags)
	// The MAC algorithm is not part of Bags; read it from the PFX.
	if der, err := ber.ToDER(data); err == nil {
		if pfx, err := pkcs12.Parse(der); err == nil && pfx.MacData != nil {
			name := macName(pfx.MacData.Mac.Algorithm.Algorithm.String())
			r.MAC = &name
		}
	}
	return r
}

func fill(r *result, bags *pkcs12.Bags) {
	for _, c := range bags.Certificates {
		r.Certificates = append(r.Certificates, item{
			SHA256: digest(c.Raw), FriendlyName: c.FriendlyName, LocalKeyID: hex.EncodeToString(c.LocalKeyID),
		})
	}
	for _, k := range bags.PrivateKeys {
		it := item{SHA256: digest(k.Raw), FriendlyName: k.FriendlyName, LocalKeyID: hex.EncodeToString(k.LocalKeyID)}
		// crypto/x509 knows no brainpool curves; those keys match by their PKCS#8 digest.
		if key, err := x509.ParsePKCS8PrivateKey(k.Raw); err == nil {
			if spki, err := publicKeyDER(key); err == nil {
				it.PublicKeySHA256 = digest(spki)
			}
		}
		r.Keys = append(r.Keys, it)
	}
	for _, p := range bags.FindMatchingPairs() {
		r.Pairs = append(r.Pairs, [2]int{indexOf(bags.Certificates, p.Certificate.Raw), indexOfKey(bags.PrivateKeys, p.PrivateKey.Raw)})
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

func macName(oid string) string {
	names := map[string]string{
		"1.3.14.3.2.26":          "sha1",
		"2.16.840.1.101.3.4.2.4": "sha224",
		"2.16.840.1.101.3.4.2.1": "sha256",
		"2.16.840.1.101.3.4.2.2": "sha384",
		"2.16.840.1.101.3.4.2.3": "sha512",
	}
	if n, ok := names[oid]; ok {
		return n
	}
	return oid
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func indexOf(certs []pkcs12.CertificateBag, raw []byte) int {
	for i := range certs {
		if bytes.Equal(certs[i].Raw, raw) {
			return i
		}
	}
	return -1
}

func indexOfKey(keys []pkcs12.PrivateKeyBag, raw []byte) int {
	for i := range keys {
		if bytes.Equal(keys[i].Raw, raw) {
			return i
		}
	}
	return -1
}
