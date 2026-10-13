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

// Manifest is testdata/manifest.json.
type Manifest struct {
	Version int    `json:"version"`
	Cases   []Case `json:"cases"`
}

// Case is one manifest entry.
type Case struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Rules       []string `json:"rules"`
	// Profile is "modern" or "legacy" (README.md, Profiles). Every BER
	// encoding belongs to profile legacy.
	Profile string `json:"profile"`

	// Exactly one source: openssl export arguments or a committed file.
	OpenSSL []string `json:"openssl,omitempty"`
	File    string   `json:"file,omitempty"`
	Raw     string   `json:"raw,omitempty"` // "random" or "pem": not a PKCS#12 file at all

	// Material for OpenSSL sources: "rsa" or "ec" leaf key; chain adds the CA.
	Key   string `json:"key,omitempty"`
	Chain bool   `json:"chain,omitempty"`

	Password       string  `json:"password"`
	PasswordFile   string  `json:"password_file,omitempty"`
	DecodePassword *string `json:"decode_password,omitempty"`

	Encodings []string  `json:"encodings"`
	Mutation  *Mutation `json:"mutation,omitempty"`
	Expect    Expect    `json:"expect"`
}

// Mutation alters the produced file to build a negative case.
type Mutation struct {
	Kind    string `json:"kind"` // truncate, append, patch, flip, mac-iterations
	Hex     string `json:"hex,omitempty"`
	Find    string `json:"find,omitempty"`
	Replace string `json:"replace,omitempty"`
	Offset  int    `json:"offset,omitempty"` // flip: byte offset from the end
	Value   int64  `json:"value,omitempty"`
}

// Expect is what a conformant decoder reports for a case.
type Expect struct {
	Code  string   `json:"code,omitempty"`
	Codes []string `json:"codes,omitempty"` // any of these

	// Symbolic contents for OpenSSL sources ("leaf", "ca").
	Certificates []string `json:"certificates,omitempty"`
	Keys         []string `json:"keys,omitempty"`

	// Literal contents for committed files.
	CertificatesSHA256 []string `json:"certificates_sha256,omitempty"`
	KeysSHA256         []string `json:"keys_sha256,omitempty"`
	KeysPublicSHA256   []string `json:"keys_public_key_sha256,omitempty"`

	Pairs         int               `json:"pairs"`
	MAC           *string           `json:"mac"`
	FriendlyNames map[string]string `json:"friendly_names,omitempty"` // sha256 → name
}

// Expected is one entry of expected.json, written by generate.
type Expected struct {
	ID           string   `json:"id"`
	Encoding     string   `json:"encoding"`
	File         string   `json:"file"`
	PasswordFile string   `json:"password_file"`
	Rules        []string `json:"rules"`
	Profile      string   `json:"profile"`
	Codes        []string `json:"codes"`
	Result       Result   `json:"result"`
}

// Result is the JSON a decoder writes for one file (CONFORMANCE.md, command-line contract).
type Result struct {
	Code         string   `json:"code"`
	Detail       string   `json:"detail,omitempty"`
	Certificates []Item   `json:"certificates"`
	Keys         []Item   `json:"keys"`
	Pairs        [][2]int `json:"pairs"`
	MAC          *string  `json:"mac"`
}

// Item is a certificate (SHA-256 of its DER) or a key (SHA-256 of its PKCS#8
// DER). Decoders that re-encode keys may report PublicKeySHA256 instead: the
// SHA-256 of the key's SubjectPublicKeyInfo DER.
type Item struct {
	SHA256          string `json:"sha256,omitempty"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	FriendlyName    string `json:"friendly_name,omitempty"`
	LocalKeyID      string `json:"local_key_id,omitempty"`
}
