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

// Package pbe holds the password-based building blocks that package pkcs12
// and package pkcs12/legacy share: the PKCS#12 key derivation, the password
// encoding it needs, the PBKDF2 PRFs and CBC decryption with PKCS#7 padding.
package pbe

import (
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // HMAC-SHA-1 is PBKDF2's default PRF.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxIterations bounds every iteration count read from a file (PKCS#12 KDF,
// PBKDF2, MAC). Producers use 1 to a few hundred thousand: OpenSSL 2048, the
// gematik card vendors 51200 and 102400. The bound keeps a crafted file from
// occupying a CPU for minutes.
const MaxIterations = 10_000_000

// Purposes of the PKCS#12 KDF, the diversifier ID of RFC 7292 §B.3.
const (
	PurposeKey byte = 1
	PurposeIV  byte = 2
	PurposeMAC byte = 3
)

// PKCS12KDF is the key derivation of RFC 7292 appendix B.2. password is the
// encoded form from BMPPassword. The step numbers follow the RFC.
func PKCS12KDF(newHash func() hash.Hash, password, salt []byte, iterations int, purpose byte, size int) []byte {
	h := newHash()
	u, v := h.Size(), h.BlockSize()

	// 1. D: v copies of the purpose byte.
	d := make([]byte, v)
	for i := range d {
		d[i] = purpose
	}
	// 2.–4. I = S || P, salt and password each repeated to a multiple of v bytes.
	i := append(repeatToBlocks(salt, v), repeatToBlocks(password, v)...)

	out := make([]byte, 0, size)
	for {
		// 6a. A = H^r(D || I)
		h.Reset()
		h.Write(d)
		h.Write(i)
		a := h.Sum(nil)
		for range iterations - 1 {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a[:min(u, size-len(out))]...)
		if len(out) == size {
			return out
		}
		// 6b.–6c. I_j = (I_j + B + 1) mod 2^(8v) for every v-byte block I_j
		// of I, where B is A repeated to v bytes.
		b := repeatToBlocks(a, v)[:v]
		for j := 0; j < len(i); j += v {
			addBlock(i[j:j+v], b)
		}
	}
}

// addBlock sets block = block + b + 1 modulo 2^(8·len(block)), big-endian.
func addBlock(block, b []byte) {
	carry := uint(1)
	for k := len(block) - 1; k >= 0; k-- {
		sum := uint(block[k]) + uint(b[k]) + carry
		block[k] = byte(sum)
		carry = sum >> 8
	}
}

// repeatToBlocks repeats data to fill v·⌈len(data)/v⌉ bytes; empty stays empty.
func repeatToBlocks(data []byte, v int) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, (len(data)+v-1)/v*v)
	for k := range out {
		out[k] = data[k%len(data)]
	}
	return out
}

// BMPPassword encodes a password for the PKCS#12 KDF (RFC 7292 §B.1):
// UTF-16BE with a two-byte zero terminator, so the empty password is 00 00.
// Characters outside the BMP become surrogate pairs, as OpenSSL and Java
// write them. A password that is not valid UTF-8 maps byte by byte, the
// fallback of OpenSSL's OPENSSL_utf82uni.
func BMPPassword(password []byte) []byte {
	var units []uint16
	if utf8.Valid(password) {
		units = utf16.Encode([]rune(string(password)))
	} else {
		units = make([]uint16, len(password))
		for k, b := range password {
			units[k] = uint16(b)
		}
	}
	out := make([]byte, 0, 2*len(units)+2)
	for _, unit := range units {
		out = append(out, byte(unit>>8), byte(unit))
	}
	return append(out, 0, 0)
}

// OIDs of the PBKDF2 PRFs (RFC 8018 §B.1) and of the SHA digests, which some
// producers, including package pkcs12 up to v0.99.3, wrote in their place.
var (
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidSHA1       = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// PBKDF2PRF returns the hash of a PBKDF2 PRF.
func PBKDF2PRF(oid asn1.ObjectIdentifier) (func() hash.Hash, bool) {
	switch {
	case oid.Equal(oidHMACSHA1), oid.Equal(oidSHA1):
		return sha1.New, true
	case oid.Equal(oidHMACSHA224), oid.Equal(oidSHA224):
		return sha256.New224, true
	case oid.Equal(oidHMACSHA256), oid.Equal(oidSHA256):
		return sha256.New, true
	case oid.Equal(oidHMACSHA384), oid.Equal(oidSHA384):
		return sha512.New384, true
	case oid.Equal(oidHMACSHA512), oid.Equal(oidSHA512):
		return sha512.New, true
	}
	return nil, false
}

// Errors of DecryptCBC; callers wrap them into their own error values.
var (
	ErrLength  = errors.New("ciphertext or IV length does not fit the block size")
	ErrPadding = errors.New("invalid padding")
)

// DecryptCBC decrypts CBC and removes the PKCS#7 padding (RFC 8018 §6.1.1).
func DecryptCBC(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(iv) != size || len(ciphertext) == 0 || len(ciphertext)%size != 0 {
		return nil, ErrLength
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	n := int(plaintext[len(plaintext)-1])
	if n == 0 || n > size {
		return nil, ErrPadding
	}
	for _, b := range plaintext[len(plaintext)-n:] {
		if int(b) != n {
			return nil, ErrPadding
		}
	}
	return plaintext[:len(plaintext)-n], nil
}
