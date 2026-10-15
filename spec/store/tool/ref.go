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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"regexp"
)

// The reference computes the expected results of the corpus. It follows README.md rule by
// rule and is not an implementation to embed: it holds keys in ordinary slices.

type code string

func (c code) Error() string { return string(c) }

const (
	codeOK                  code = "ok"
	codeNotFound            code = "not_found"
	codeExpired             code = "expired"
	codeMalformed           code = "malformed"
	codeUnsupportedVersion  code = "unsupported_version"
	codeUnknownKid          code = "unknown_kid"
	codeAuthFailed          code = "auth_failed"
	codeLimitExceeded       code = "limit_exceeded"
	codeInvalidArgument     code = "invalid_argument"
	codeCapabilityMissing   code = "capability_missing"
	codeNoKeyring           code = "no_keyring"
	codeInsecurePermissions code = "insecure_permissions"
)

const (
	label        = "zl-store/1"
	keyringLabel = "zl-keyring/1"
	maxID        = 4096
	maxTags      = 16
	maxPayload   = 16 << 20
	minSealed    = 1 + 1 + 1 + 8 + 12 + 16
)

var (
	nsSyntax      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	fieldSyntax   = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	profileSyntax = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	wrapperSyntax = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// STORE-001
func lp(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// STORE-051
func validKid(kid []byte) bool {
	if len(kid) < 1 || len(kid) > 64 {
		return false
	}
	for _, c := range kid {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

type derived struct{ value, name, index []byte }

// STORE-041
func derive(dk []byte) derived {
	k := func(info string) []byte {
		out, err := hkdf.Key(sha256.New, dk, []byte(label), info, 32)
		if err != nil {
			panic(err)
		}
		return out
	}
	return derived{value: k("value"), name: k("name"), index: k("index")}
}

func hmacSHA256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func sha(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// STORE-020, STORE-030, STORE-031, STORE-032. kName is nil for a plain namespace.
func recordName(kName []byte, ns string, id []byte) ([]byte, error) {
	if !nsSyntax.MatchString(ns) {
		return nil, codeInvalidArgument
	}
	if len(id) > maxID {
		return nil, codeLimitExceeded
	}
	if kName == nil {
		return sha(lp([]byte("zl-store/1/plain-name")), lp([]byte(ns)), lp(id)), nil
	}
	return hmacSHA256(kName, lp([]byte(ns)), lp(id)), nil
}

// STORE-033, STORE-034. kIndex is nil for a plain namespace.
func recordTag(kIndex []byte, ns, field string, value []byte) ([]byte, error) {
	if !nsSyntax.MatchString(ns) || !fieldSyntax.MatchString(field) {
		return nil, codeInvalidArgument
	}
	if len(value) > maxID {
		return nil, codeLimitExceeded
	}
	if kIndex == nil {
		return sha(lp([]byte("zl-store/1/plain-tag")), lp([]byte(ns)), lp([]byte(field)), lp(value)), nil
	}
	return hmacSHA256(kIndex, lp([]byte(ns)), lp([]byte(field)), lp(value)), nil
}

// STORE-055
func aad(profileID, kid []byte, ns string, name []byte, notAfter uint64) []byte {
	return cat(lp([]byte(label)), lp(profileID), lp(kid), lp([]byte(ns)), lp(name), u64(notAfter))
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// Section F, sealed record. The nonce is a parameter so that vectors are reproducible.
func seal(kValue, profileID, kid []byte, ns string, name []byte, notAfter uint64, nonce, payload []byte) ([]byte, error) {
	if !validKid(kid) {
		return nil, codeInvalidArgument
	}
	if len(payload) > maxPayload {
		return nil, codeLimitExceeded
	}
	head := cat([]byte{1, byte(len(kid))}, kid, u64(notAfter), nonce)
	return gcm(kValue).Seal(head, nonce, payload, aad(profileID, kid, ns, name, notAfter)), nil
}

type opened struct {
	kid      []byte
	notAfter uint64
	payload  []byte
}

// STORE-050, STORE-051, STORE-054 to STORE-056. keys maps kid to k_value.
func openSealed(keys map[string][]byte, profileID []byte, ns string, name []byte, now uint64, rec []byte) (opened, error) {
	if len(rec) < 1 {
		return opened{}, codeMalformed
	}
	if rec[0] != 1 {
		return opened{}, codeUnsupportedVersion
	}
	if len(rec) < 2 {
		return opened{}, codeMalformed
	}
	kl := int(rec[1])
	if kl < 1 || kl > 64 || len(rec) < 2+kl+8+12+16 {
		return opened{}, codeMalformed
	}
	kid := rec[2 : 2+kl]
	if !validKid(kid) {
		return opened{}, codeMalformed
	}
	notAfter := binary.BigEndian.Uint64(rec[2+kl:])
	nonce := rec[2+kl+8 : 2+kl+8+12]
	ct := rec[2+kl+8+12:]
	if len(ct)-16 > maxPayload {
		return opened{}, codeLimitExceeded
	}
	kv, ok := keys[string(kid)]
	if !ok {
		return opened{}, codeUnknownKid
	}
	pt, err := gcm(kv).Open(nil, nonce, ct, aad(profileID, kid, ns, name, notAfter))
	if err != nil {
		return opened{}, codeAuthFailed
	}
	if notAfter != 0 && notAfter <= now {
		return opened{}, codeExpired
	}
	return opened{kid: kid, notAfter: notAfter, payload: pt}, nil
}

// Section F, plain record.
func plainRecord(notAfter uint64, payload []byte) ([]byte, error) {
	if len(payload) > maxPayload {
		return nil, codeLimitExceeded
	}
	return cat([]byte{0}, u64(notAfter), payload), nil
}

// STORE-050, STORE-054, STORE-057
func openPlain(now uint64, rec []byte) (opened, error) {
	if len(rec) < 1 {
		return opened{}, codeMalformed
	}
	if rec[0] != 0 {
		return opened{}, codeUnsupportedVersion
	}
	if len(rec) < 9 {
		return opened{}, codeMalformed
	}
	notAfter := binary.BigEndian.Uint64(rec[1:])
	payload := rec[9:]
	if len(payload) > maxPayload {
		return opened{}, codeLimitExceeded
	}
	if notAfter != 0 && notAfter <= now {
		return opened{}, codeExpired
	}
	return opened{notAfter: notAfter, payload: payload}, nil
}

// reader walks a byte string and reports malformed input (STORE-005).
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = codeMalformed
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return int(b[0])
}

func (r *reader) u16() int {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(b))
}

func (r *reader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (r *reader) lp() []byte {
	b := r.take(4)
	if b == nil {
		return nil
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(r.b)) {
		r.err = codeMalformed
		return nil
	}
	return r.take(int(n))
}

type keyringEntry struct {
	kid, wrapperID, wrapped []byte
	created                 uint64
}

type keyring struct {
	profileID            []byte
	currentKid, indexKid []byte
	entries              []keyringEntry
}

// Section G, keyring file.
func buildKeyring(k keyring) []byte {
	out := cat([]byte("ZLKR"), []byte{1}, k.profileID, lp(k.currentKid), lp(k.indexKid))
	out = binary.BigEndian.AppendUint16(out, uint16(len(k.entries)))
	for _, e := range k.entries {
		out = append(out, cat(lp(e.kid), u64(e.created), lp(e.wrapperID), lp(e.wrapped))...)
	}
	return out
}

// STORE-060 to STORE-063
func parseKeyring(b []byte) (keyring, error) {
	r := &reader{b: b}
	if !bytes.Equal(r.take(4), []byte("ZLKR")) {
		return keyring{}, codeMalformed
	}
	if v := r.u8(); r.err == nil && v != 1 {
		return keyring{}, codeUnsupportedVersion
	}
	k := keyring{profileID: r.take(16), currentKid: r.lp(), indexKid: r.lp()}
	count := r.u16()
	if r.err != nil {
		return keyring{}, r.err
	}
	if count < 1 || count > 256 || !validKid(k.currentKid) || !validKid(k.indexKid) {
		return keyring{}, codeMalformed
	}
	seen := map[string]bool{}
	for range count {
		e := keyringEntry{kid: r.lp(), created: r.u64(), wrapperID: r.lp(), wrapped: r.lp()}
		if r.err != nil {
			return keyring{}, r.err
		}
		if !validKid(e.kid) || seen[string(e.kid)] || !wrapperSyntax.Match(e.wrapperID) {
			return keyring{}, codeMalformed
		}
		seen[string(e.kid)] = true
		k.entries = append(k.entries, e)
	}
	if len(r.b) != 0 || !seen[string(k.currentKid)] || !seen[string(k.indexKid)] {
		return keyring{}, codeMalformed
	}
	return k, nil
}

func keyFileAAD(profileID, kid []byte) []byte {
	return cat(lp([]byte(keyringLabel)), lp(profileID), lp(kid))
}

// Wrapper registry, key-file.
func wrapKeyFile(kek, profileID, kid, nonce, dk []byte) []byte {
	return gcm(kek).Seal(append([]byte{}, nonce...), nonce, dk, keyFileAAD(profileID, kid))
}

// STORE-063, STORE-064
func unwrap(kek, profileID []byte, e keyringEntry) ([]byte, error) {
	if string(e.wrapperID) != "key-file" {
		return nil, codeUnsupportedVersion
	}
	if len(e.wrapped) != 12+32+16 {
		return nil, codeMalformed
	}
	dk, err := gcm(kek).Open(nil, e.wrapped[:12], e.wrapped[12:], keyFileAAD(profileID, e.kid))
	if err != nil {
		return nil, codeAuthFailed
	}
	return dk, nil
}

// STORE-094. mode is the POSIX file mode, or -1 where the platform has none.
func parseKEKFile(content []byte, mode int) ([]byte, error) {
	if mode >= 0 && mode&0o077 != 0 {
		return nil, codeInsecurePermissions
	}
	content = bytes.TrimSuffix(content, []byte("\n"))
	if len(content) != 44 {
		return nil, codeMalformed
	}
	kek, err := base64.StdEncoding.Strict().DecodeString(string(content))
	if err != nil || len(kek) != 32 {
		return nil, codeMalformed
	}
	return kek, nil
}

type fileTag struct {
	field string
	tag   []byte
}

// Section I, record file.
func buildRecordFile(expiresAt uint64, tags []fileTag, value []byte) []byte {
	out := cat([]byte("ZLRF"), []byte{1}, u64(expiresAt), []byte{byte(len(tags))})
	for _, t := range tags {
		out = append(out, cat(lp([]byte(t.field)), t.tag)...)
	}
	return append(out, value...)
}

// STORE-080
func parseRecordFile(b []byte) (uint64, []fileTag, []byte, error) {
	r := &reader{b: b}
	if !bytes.Equal(r.take(4), []byte("ZLRF")) {
		return 0, nil, nil, codeMalformed
	}
	if v := r.u8(); r.err == nil && v != 1 {
		return 0, nil, nil, codeUnsupportedVersion
	}
	expiresAt := r.u64()
	n := r.u8()
	if r.err != nil {
		return 0, nil, nil, r.err
	}
	if n > maxTags {
		return 0, nil, nil, codeLimitExceeded
	}
	var tags []fileTag
	for range n {
		f := r.lp()
		t := r.take(32)
		if r.err != nil {
			return 0, nil, nil, r.err
		}
		if !fieldSyntax.Match(f) {
			return 0, nil, nil, codeMalformed
		}
		tags = append(tags, fileTag{field: string(f), tag: t})
	}
	return expiresAt, tags, r.b, nil
}

// Format level meta of the files backend (STORE-086).
func parseFilesMeta(b []byte) (level, minCompatible int, err error) {
	r := &reader{b: b}
	if !bytes.Equal(r.take(4), []byte("ZLFM")) {
		return 0, 0, codeMalformed
	}
	level, minCompatible = r.u16(), r.u16()
	if r.err != nil || len(r.b) != 0 || minCompatible < 1 || minCompatible > level {
		return 0, 0, codeMalformed
	}
	return level, minCompatible, nil
}

// STORE-100: whether an implementation supporting levels up to max may open the tree.
func openLevel(max, level, minCompatible int) error {
	if minCompatible > max {
		return codeUnsupportedVersion
	}
	return nil
}
