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

package pbe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1" //nolint:gosec // test vectors of SHA-1 based schemes
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPKCS12KDF uses the vectors Bouncy Castle's PKCS12 tests and
// golang.org/x/crypto/pkcs12 share; RFC 7292 has none.
func TestPKCS12KDF(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		salt       string
		iterations int
		purpose    byte
		want       string
	}{
		{"smeg key", "smeg", "0A58CF64530D823F", 1, PurposeKey, "8aaae6297b6cb04642ab5b077851284eb7128f1a2a7fbca3"},
		{"smeg IV", "smeg", "0A58CF64530D823F", 1, PurposeIV, "79993dfe048d3b76"},
		{"queeg key", "queeg", "1682C0FC5B3F7EC5", 1000, PurposeKey, "483dd6e919d7de2e8e648ba8f862f3fbfbdc2bcb2c02957f"},
		{"queeg IV", "queeg", "1682C0FC5B3F7EC5", 1000, PurposeIV, "9d461d1b00355c50"},
		{"smeg MAC key", "smeg", "3D83C0E4546AC140", 1, PurposeMAC, "8d967d88f6caa9d714800ab3d48051d63f73a312"},
		{"sesame key", "sesame", "ffffffffffffffff", 2048, PurposeKey, "7cd9fd3e2b3be7691a44e3bef0f9ea0fb9b897d4e325d9d1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := unhex(t, tt.want)
			got := PKCS12KDF(sha1.New, BMPPassword([]byte(tt.password)), unhex(t, tt.salt), tt.iterations, tt.purpose, len(want))
			if !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

// TestPKCS12KDFLongOutput derives more than one hash block, which exercises
// the I_j update of step 6c, and checks that a prefix stays stable.
func TestPKCS12KDFLongOutput(t *testing.T) {
	password := BMPPassword([]byte("sesame"))
	salt := unhex(t, "ffffffffffffffff")
	long := PKCS12KDF(sha1.New, password, salt, 2048, PurposeKey, 100)
	short := PKCS12KDF(sha1.New, password, salt, 2048, PurposeKey, 24)
	if !bytes.Equal(long[:24], short) {
		t.Error("a longer output does not extend the shorter one")
	}
}

func TestBMPPassword(t *testing.T) {
	tests := []struct {
		password []byte
		want     string
	}{
		{[]byte(""), "0000"},
		{[]byte("00"), "0030 0030 0000"},
		{[]byte("ä"), "00e4 0000"},
		{[]byte("😀"), "d83d de00 0000"},        // surrogate pair, as OpenSSL and Java write it
		{[]byte{0xe4, 0x41}, "00e4 0041 0000"}, // not UTF-8: byte by byte
	}
	for _, tt := range tests {
		if got, want := BMPPassword(tt.password), unhex(t, tt.want); !bytes.Equal(got, want) {
			t.Errorf("BMPPassword(%q) = % x, want % x", tt.password, got, want)
		}
	}
}

// TestPBKDF2PRF checks the PRF wiring with the PBKDF2 vectors of RFC 6070
// (HMAC-SHA-1) and RFC 7914 §11 (HMAC-SHA-256).
func TestPBKDF2PRF(t *testing.T) {
	tests := []struct {
		prf        asn1.ObjectIdentifier
		password   string
		salt       string
		iterations int
		want       string
	}{
		{oidHMACSHA1, "password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
		{oidHMACSHA1, "password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
		{oidHMACSHA1, "password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1"},
		{oidHMACSHA1, "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
		{oidHMACSHA1, "pass\x00word", "sa\x00lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3"},
		{oidHMACSHA256, "passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{oidHMACSHA256, "Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
	}
	for _, tt := range tests {
		t.Run(tt.prf.String()+"/"+tt.password, func(t *testing.T) {
			prf, ok := PBKDF2PRF(tt.prf)
			if !ok {
				t.Fatalf("PRF %v unknown", tt.prf)
			}
			want := unhex(t, tt.want)
			got, err := pbkdf2.Key(prf, tt.password, []byte(tt.salt), tt.iterations, len(want))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}

	for _, oid := range []asn1.ObjectIdentifier{oidHMACSHA224, oidHMACSHA384, oidHMACSHA512, oidSHA256} {
		if _, ok := PBKDF2PRF(oid); !ok {
			t.Errorf("PRF %v unknown", oid)
		}
	}
	if _, ok := PBKDF2PRF(asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 127}); ok {
		t.Error("unknown PRF accepted")
	}
}

func TestDecryptCBC(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 16)
	encrypt := func(plaintext []byte) []byte {
		out := make([]byte, len(plaintext))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
		return out
	}
	pad := func(data []byte, n int) []byte { return append(data, bytes.Repeat([]byte{byte(n)}, n)...) }

	got, err := DecryptCBC(block, iv, encrypt(pad([]byte("0123456789"), 6)))
	if err != nil || string(got) != "0123456789" {
		t.Errorf("DecryptCBC = %q, %v", got, err)
	}
	got, err = DecryptCBC(block, iv, encrypt(pad(nil, 16)))
	if err != nil || len(got) != 0 {
		t.Errorf("full padding block: %q, %v", got, err)
	}

	bad := []struct {
		name     string
		iv, data []byte
		wantErr  error
	}{
		{"zero padding", iv, encrypt(make([]byte, 16)), ErrPadding},
		{"padding above block size", iv, encrypt(bytes.Repeat([]byte{17}, 16)), ErrPadding},
		{"inconsistent padding", iv, encrypt(append(bytes.Repeat([]byte{0}, 14), 1, 2)), ErrPadding},
		{"empty", iv, nil, ErrLength},
		{"partial block", iv, make([]byte, 15), ErrLength},
		{"short IV", iv[:8], make([]byte, 16), ErrLength},
	}
	for _, tt := range bad {
		if _, err := DecryptCBC(block, tt.iv, tt.data); !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: error = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
}
