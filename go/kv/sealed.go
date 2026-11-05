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

package kv

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrIntegrity is what a sealed store returns for a record it cannot authenticate: tampered, moved to another
// key or purpose, sealed under a key the ring does not hold, or not sealed at all. It can mean an attack on the
// store, so callers treat the record as absent and raise an alert; a failure of the store itself stays a
// different error.
var ErrIntegrity = errors.New("kv: record failed its integrity check")

const sealedVersion byte = 1

const (
	sealedSaltSize  = 16
	sealedNonceSize = 12
	sealedTagSize   = 16
	// maxSealedSize bounds what the parser takes from the store. Records are small JSON documents.
	maxSealedSize = 16 << 20
	// sealedKDFInfo separates this use of a ring key from every other, such as go/nonce's on the same ring.
	sealedKDFInfo = "zero-lab/kv/sealed/v1\x00"
)

// NewSealed wraps inner so that it sees ciphertext only (server rule 5). Each record is sealed with AES-256-GCM
// under a key derived by HKDF-SHA256 from the ring's current key, purpose and a fresh random salt, and
// bound through the associated data to its version, key ID, purpose and kv key, so a record opens neither under
// another kv key nor another purpose.
//
//	record = version(1) | len(key ID)(1) | key ID | salt(16) | nonce(12) | ciphertext and tag
//
// Set, SetMany and SetIfAbsent seal; Get and Take open and return [ErrIntegrity] for anything that does not
// open. A Take that finds such a record has deleted it by then, as it would a good one, and the error reports
// it. Delete, Keys, Cleanup and Close pass through; kv keys stay in the clear, so a key must not carry a secret.
//
// It panics on a nil inner or keys or an empty purpose: those are wiring mistakes at start-up, and carrying on
// could only mean storing plaintext.
func NewSealed(inner Store, keys Keys, purpose string) Store {
	if inner == nil || keys == nil || purpose == "" {
		panic("kv: NewSealed needs a store, keys and a purpose")
	}
	return &sealedStore{inner: inner, keys: keys, purpose: purpose}
}

type sealedStore struct {
	inner   Store
	keys    Keys
	purpose string
}

// aead derives a key per record from a random salt. Every accepted proof and nonce seals a record, so a key shared
// by all of them could run up against the limit of random GCM nonces, 2^32 messages per key.
func (s *sealedStore) aead(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("kv: a sealing key has %d bytes, not %d", keySize, len(key))
	}
	derived, err := hkdf.Key(sha256.New, key, salt, sealedKDFInfo+s.purpose, keySize)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// associatedData is length-prefixed, so no two different triples encode alike.
func (s *sealedStore) associatedData(id, kvKey string) []byte {
	ad := make([]byte, 0, 1+4+len(id)+4+len(s.purpose)+len(kvKey))
	ad = append(ad, sealedVersion)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(id)))
	ad = append(ad, id...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(s.purpose)))
	ad = append(ad, s.purpose...)
	return append(ad, kvKey...)
}

func (s *sealedStore) seal(kvKey string, value []byte) ([]byte, error) {
	id, key := s.keys.Current()
	defer clear(key)
	if !validKeyID(id) {
		return nil, errors.New("kv: the current key has an invalid ID")
	}
	size := 2 + len(id) + sealedSaltSize + sealedNonceSize + len(value) + sealedTagSize
	if size > maxSealedSize {
		return nil, fmt.Errorf("kv: a value of %d bytes is too large to seal", len(value))
	}
	random := make([]byte, sealedSaltSize+sealedNonceSize)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	salt, nonce := random[:sealedSaltSize], random[sealedSaltSize:]
	aead, err := s.aead(key, salt)
	if err != nil {
		return nil, err
	}
	record := make([]byte, 0, size)
	record = append(record, sealedVersion, byte(len(id)))
	record = append(record, id...)
	record = append(record, random...)
	return aead.Seal(record, nonce, value, s.associatedData(id, kvKey)), nil
}

// parseSealed splits a record without trusting any of it. The key ID is only a hint for the lookup: the
// associated data authenticates it.
func parseSealed(record []byte) (id string, salt, nonce, ciphertext []byte, err error) {
	if len(record) > maxSealedSize || len(record) < 2 || record[0] != sealedVersion {
		return "", nil, nil, nil, fmt.Errorf("%w: not a sealed record", ErrIntegrity)
	}
	idLen := int(record[1])
	if idLen == 0 || idLen > maxKeyIDLen || len(record) < 2+idLen+sealedSaltSize+sealedNonceSize+sealedTagSize {
		return "", nil, nil, nil, fmt.Errorf("%w: not a sealed record", ErrIntegrity)
	}
	rest := record[2+idLen:]
	return string(record[2 : 2+idLen]), rest[:sealedSaltSize], rest[sealedSaltSize : sealedSaltSize+sealedNonceSize], rest[sealedSaltSize+sealedNonceSize:], nil
}

func (s *sealedStore) open(kvKey string, record []byte) ([]byte, error) {
	id, salt, nonce, ciphertext, err := parseSealed(record)
	if err != nil {
		return nil, err
	}
	key, ok := s.keys.Lookup(id)
	if !ok {
		return nil, fmt.Errorf("%w: sealed under a key not in the ring", ErrIntegrity)
	}
	defer clear(key)
	aead, err := s.aead(key, salt)
	if err != nil {
		return nil, err
	}
	value, err := aead.Open(nil, nonce, ciphertext, s.associatedData(id, kvKey))
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrIntegrity)
	}
	return value, nil
}

func (s *sealedStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := s.inner.Get(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	value, err := s.open(key, record)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s *sealedStore) Take(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := s.inner.Take(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	value, err := s.open(key, record)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (s *sealedStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	record, err := s.seal(key, value)
	if err != nil {
		return err
	}
	return s.inner.Set(ctx, key, record, ttl)
}

func (s *sealedStore) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	record, err := s.seal(key, value)
	if err != nil {
		return false, err
	}
	return s.inner.SetIfAbsent(ctx, key, record, ttl)
}

func (s *sealedStore) SetMany(ctx context.Context, entries ...Entry) error {
	sealed := make([]Entry, len(entries))
	for i, e := range entries {
		record, err := s.seal(e.Key, e.Value)
		if err != nil {
			return err
		}
		sealed[i] = Entry{Key: e.Key, Value: record, TTL: e.TTL}
	}
	return s.inner.SetMany(ctx, sealed...)
}

func (s *sealedStore) Delete(ctx context.Context, key string) error { return s.inner.Delete(ctx, key) }

func (s *sealedStore) Keys(ctx context.Context, prefix string) ([]string, error) {
	return s.inner.Keys(ctx, prefix)
}

func (s *sealedStore) Cleanup(ctx context.Context) (int, error) { return s.inner.Cleanup(ctx) }

func (s *sealedStore) Close() error { return s.inner.Close() }
