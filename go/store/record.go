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

package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const label = "zl-store/1"

// MaxTime is the latest time a record, record file or keyring holds:
// 9999-12-31T23:59:59Z, so that every language's time type holds it (STORE-002).
const MaxTime = 253402300799

// checkWriteTime refuses a time beyond MaxTime (STORE-002).
func checkWriteTime(t time.Time) error {
	if !t.IsZero() && t.Unix() > MaxTime {
		return fail(CodeInvalidArgument, "time beyond 9999")
	}
	return nil
}

// DerivedKeys are the value, name and index keys of one data key (STORE-041).
type DerivedKeys struct {
	value, name, index [32]byte
}

// Derive computes HKDF-SHA-256(dk, salt = "zl-store/1", info) for the value, name and
// index keys (STORE-041).
func Derive(dk []byte) (DerivedKeys, error) {
	var k DerivedKeys
	for _, x := range []struct {
		info string
		out  *[32]byte
	}{{"value", &k.value}, {"name", &k.name}, {"index", &k.index}} {
		b, err := hkdf.Key(sha256.New, dk, []byte(label), x.info, 32)
		if err != nil {
			return DerivedKeys{}, err
		}
		copy(x.out[:], b)
		clear(b)
	}
	return k, nil
}

// Keys returns k_value, k_name and k_index, for test vectors.
func (k *DerivedKeys) Keys() (value, name, index [32]byte) { return k.value, k.name, k.index }

// Name is the name of id under these keys as the index kid's (STORE-031).
func (k *DerivedKeys) Name(ns string, id []byte) (Name, error) {
	if err := checkID(ns, id); err != nil {
		return Name{}, err
	}
	return Name(hmacSHA256(k.name[:], nameInput(ns, id))), nil
}

// Tag is a tag under these keys as the index kid's (STORE-034).
func (k *DerivedKeys) Tag(ns, field string, value []byte) (Tag, error) {
	if err := checkTag(ns, field, value); err != nil {
		return Tag{}, err
	}
	return Tag{Field: field, Tag: hmacSHA256(k.index[:], tagInput(ns, field, value))}, nil
}

// ValueKey is k_value, for [SealRecord] and [OpenSealed].
func (k *DerivedKeys) ValueKey() *[32]byte { return &k.value }

// Clear overwrites the keys.
func (k *DerivedKeys) Clear() { clear(k.value[:]); clear(k.name[:]); clear(k.index[:]) }

// wireTime is a time as seconds, 0 for the zero time, which means no expiry (STORE-002).
func wireTime(t time.Time) uint64 {
	if t.IsZero() || t.Unix() <= 0 {
		return 0
	}
	return uint64(t.Unix())
}

// FromWire is the time of a wire value; 0 is the zero time.
func FromWire(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// Live reports whether an expiry has not passed at now (STORE-003).
func Live(expiresAt, now time.Time) bool {
	e := wireTime(expiresAt)
	return e == 0 || e > uint64(max(now.Unix(), 0))
}

func aad(profileID, kid []byte, ns string, name Name, notAfter uint64) []byte {
	a := appendLP(nil, []byte(label))
	a = appendLP(a, profileID)
	a = appendLP(a, kid)
	a = appendLP(a, []byte(ns))
	a = appendLP(a, name[:])
	return binary.BigEndian.AppendUint64(a, notAfter)
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // keys are 32 bytes by construction
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return g
}

// SealRecord seals payload under kValue (section F). The nonce must be fresh random bytes
// (STORE-052); a [Keyring] draws it.
func SealRecord(kValue *[32]byte, profileID [16]byte, kid, ns string, name Name, notAfter time.Time, nonce [12]byte, payload []byte) ([]byte, error) {
	if !ValidKid(kid) {
		return nil, fail(CodeInvalidArgument, "kid")
	}
	if len(payload) > MaxPayload {
		return nil, fail(CodeLimitExceeded, "payload")
	}
	if err := checkWriteTime(notAfter); err != nil {
		return nil, err
	}
	na := wireTime(notAfter)
	out := make([]byte, 0, 2+len(kid)+8+12+len(payload)+16)
	out = append(out, 1, byte(len(kid)))
	out = append(out, kid...)
	out = binary.BigEndian.AppendUint64(out, na)
	out = append(out, nonce[:]...)
	return gcm(kValue[:]).Seal(out, nonce[:], payload, aad(profileID[:], []byte(kid), ns, name, na)), nil
}

// Opened is an opened record.
type Opened struct {
	// Kid is the kid it was sealed under; empty for a plain record.
	Kid string
	// NotAfter is its expiry; the zero time for none.
	NotAfter time.Time
	Payload  []byte
}

func checkExpiry(notAfter uint64, now time.Time) error {
	if notAfter != 0 && notAfter <= uint64(max(now.Unix(), 0)) {
		return ErrExpired
	}
	return nil
}

// OpenSealed opens a sealed record (STORE-050, STORE-051, STORE-054 to STORE-056).
// valueKey looks up k_value of a kid. The tag is checked before any plaintext is returned
// and the expiry only after the tag, so that the code says what the record really is.
func OpenSealed(valueKey func(kid string) *[32]byte, profileID [16]byte, ns string, name Name, now time.Time, record []byte) (Opened, error) {
	r := &reader{b: record, what: "record"}
	v := r.u8()
	if r.err != nil {
		return Opened{}, r.err
	}
	if v != 1 {
		return Opened{}, fail(CodeUnsupportedVersion, "record")
	}
	kl := int(r.u8())
	if r.err == nil && (kl < 1 || kl > 64) {
		return Opened{}, r.malformed()
	}
	kid := string(r.take(kl))
	na := r.u64()
	nonce := r.take(12)
	if r.err != nil {
		return Opened{}, r.err
	}
	if !ValidKid(kid) || len(r.b) < 16 || na > MaxTime {
		return Opened{}, r.malformed()
	}
	if len(r.b)-16 > MaxPayload {
		return Opened{}, fail(CodeLimitExceeded, "payload")
	}
	key := valueKey(kid)
	if key == nil {
		return Opened{}, ErrUnknownKid
	}
	pt, err := gcm(key[:]).Open(nil, nonce, r.b, aad(profileID[:], []byte(kid), ns, name, na))
	if err != nil {
		return Opened{}, fail(CodeAuthFailed, "record")
	}
	if err := checkExpiry(na, now); err != nil {
		return Opened{}, err
	}
	return Opened{Kid: kid, NotAfter: FromWire(na), Payload: pt}, nil
}

// PlainRecord is a plain record (section F).
func PlainRecord(notAfter time.Time, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, fail(CodeLimitExceeded, "payload")
	}
	if err := checkWriteTime(notAfter); err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint64([]byte{0}, wireTime(notAfter))
	return append(out, payload...), nil
}

// OpenPlain opens a plain record (STORE-050, STORE-054, STORE-057); it has no integrity
// of its own.
func OpenPlain(now time.Time, record []byte) (Opened, error) {
	r := &reader{b: record, what: "record"}
	v := r.u8()
	if r.err != nil {
		return Opened{}, r.err
	}
	if v != 0 {
		return Opened{}, fail(CodeUnsupportedVersion, "record")
	}
	na := r.u64()
	if r.err != nil {
		return Opened{}, r.err
	}
	if na > MaxTime {
		return Opened{}, r.malformed()
	}
	if len(r.b) > MaxPayload {
		return Opened{}, fail(CodeLimitExceeded, "payload")
	}
	if err := checkExpiry(na, now); err != nil {
		return Opened{}, err
	}
	return Opened{NotAfter: FromWire(na), Payload: append([]byte(nil), r.b...)}, nil
}
