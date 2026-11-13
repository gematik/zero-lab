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
	"bytes"
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

// A record of format 1 says nothing of when it ends; one of format 2 carries its expiry, sealed with it.
const (
	sealedVersion1 byte = 1
	sealedVersion2 byte = 2
)

const (
	sealedExpirySize = 8
	sealedSaltSize   = 16
	sealedNonceSize  = 12
	sealedTagSize    = 16
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
//	format 1 = version(1) | len(key ID)(1) | key ID | salt(16) | nonce(12) | ciphertext and tag
//	format 2 = version(1) | len(key ID)(1) | key ID | expiry(8) | salt(16) | nonce(12) | ciphertext and tag
//
// Set, SetMany and SetIfAbsent seal; Get and Take open and return [ErrIntegrity] for anything that does not
// open. A Take that finds such a record has deleted it by then, as it would a good one, and the error reports
// it. Delete, Keys, Cleanup and Close pass through; kv keys stay in the clear, so a key must not carry a secret.
//
// When a record ends is the store's to say in format 1, and whoever can write to the store can change it: make
// a record outlast its time, or put a deleted one back for good. [WithSealedExpiry] seals the expiry into the
// record. Records of both formats open either way.
//
// What sealing cannot show is that a record is missing, or that one put back within its time is not the
// newest: a caller for whom a missing record permits something has to bound that elsewhere.
//
// It panics on a nil inner or keys or an empty purpose: those are wiring mistakes at start-up, and carrying on
// could only mean storing plaintext.
func NewSealed(inner Store, keys Keys, purpose string, opts ...SealedOption) Store {
	if inner == nil || keys == nil || purpose == "" {
		panic("kv: NewSealed needs a store, keys and a purpose")
	}
	s := &sealedStore{inner: inner, keys: keys, purpose: purpose, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SealedOption adjusts the store [NewSealed] returns.
type SealedOption func(*sealedStore)

// WithSealedExpiry seals each record with the time it ends (format 2), by the clock now, and reads that clock
// to refuse a record past its sealed expiry as absent, whatever the store below says. Turn it on once every
// replica is of a version that opens format 2 (server rule 22): versions before it do not.
func WithSealedExpiry(now func() time.Time) SealedOption {
	return func(s *sealedStore) { s.now, s.sealExpiry = now, true }
}

type sealedStore struct {
	inner   Store
	keys    Keys
	purpose string
	// now is the clock sealed expiries are set and checked by; sealExpiry that new records carry one.
	now        func() time.Time
	sealExpiry bool
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

// associatedData is length-prefixed, so no two different inputs encode alike. Format 1 has no expiry in it.
func (s *sealedStore) associatedData(version byte, id, kvKey string, expiry []byte) []byte {
	ad := make([]byte, 0, 1+4+len(id)+4+len(s.purpose)+len(expiry)+len(kvKey))
	ad = append(ad, version)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(id)))
	ad = append(ad, id...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(s.purpose)))
	ad = append(ad, s.purpose...)
	ad = append(ad, expiry...)
	return append(ad, kvKey...)
}

// seal makes a record that ends after ttl; no ttl is no end, which format 2 writes as an expiry of zero.
func (s *sealedStore) seal(kvKey string, value []byte, ttl time.Duration) ([]byte, error) {
	id, key := s.keys.Current()
	defer clear(key)
	if !validKeyID(id) {
		return nil, errors.New("kv: the current key has an invalid ID")
	}
	version, expiry := sealedVersion1, []byte(nil)
	if s.sealExpiry {
		version, expiry = sealedVersion2, make([]byte, sealedExpirySize)
		if ttl > 0 {
			binary.BigEndian.PutUint64(expiry, uint64(s.now().Add(ttl).UnixMilli()))
		}
	}
	size := 2 + len(id) + len(expiry) + sealedSaltSize + sealedNonceSize + len(value) + sealedTagSize
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
	record = append(record, version, byte(len(id)))
	record = append(record, id...)
	record = append(record, expiry...)
	record = append(record, random...)
	return aead.Seal(record, nonce, value, s.associatedData(version, id, kvKey, expiry)), nil
}

// parseSealed splits a record without trusting any of it. The key ID is only a hint for the lookup, and the
// expiry only a claim: the associated data authenticates both.
func parseSealed(record []byte) (version byte, id string, expiry, salt, nonce, ciphertext []byte, err error) {
	bad := fmt.Errorf("%w: not a sealed record", ErrIntegrity)
	if len(record) > maxSealedSize || len(record) < 2 || record[0] != sealedVersion1 && record[0] != sealedVersion2 {
		return 0, "", nil, nil, nil, nil, bad
	}
	version, expirySize := record[0], 0
	if version == sealedVersion2 {
		expirySize = sealedExpirySize
	}
	idLen := int(record[1])
	if idLen == 0 || idLen > maxKeyIDLen || len(record) < 2+idLen+expirySize+sealedSaltSize+sealedNonceSize+sealedTagSize {
		return 0, "", nil, nil, nil, nil, bad
	}
	rest := record[2+idLen:]
	expiry, rest = rest[:expirySize], rest[expirySize:]
	return version, string(record[2 : 2+idLen]), expiry, rest[:sealedSaltSize], rest[sealedSaltSize : sealedSaltSize+sealedNonceSize], rest[sealedSaltSize+sealedNonceSize:], nil
}

// open returns the value of a record, and found false for one that is genuine and past its sealed expiry:
// the store below should not have had it any more, and to the caller it is as absent as if it had not.
func (s *sealedStore) open(kvKey string, record []byte) (value []byte, found bool, err error) {
	version, id, expiry, salt, nonce, ciphertext, err := parseSealed(record)
	if err != nil {
		return nil, false, err
	}
	key, ok := s.keys.Lookup(id)
	if !ok {
		return nil, false, fmt.Errorf("%w: sealed under a key not in the ring", ErrIntegrity)
	}
	defer clear(key)
	aead, err := s.aead(key, salt)
	if err != nil {
		return nil, false, err
	}
	value, err = aead.Open(nil, nonce, ciphertext, s.associatedData(version, id, kvKey, expiry))
	if err != nil {
		return nil, false, fmt.Errorf("%w: authentication failed", ErrIntegrity)
	}
	if version == sealedVersion2 {
		if ends := int64(binary.BigEndian.Uint64(expiry)); ends != 0 && s.now().UnixMilli() >= ends {
			return nil, false, nil
		}
	}
	return value, true, nil
}

func (s *sealedStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := s.inner.Get(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	return s.open(key, record)
}

func (s *sealedStore) Take(ctx context.Context, key string) ([]byte, bool, error) {
	record, found, err := s.inner.Take(ctx, key)
	if err != nil || !found {
		return nil, false, err
	}
	return s.open(key, record)
}

func (s *sealedStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	record, err := s.seal(key, value, ttl)
	if err != nil {
		return err
	}
	return s.inner.Set(ctx, key, record, ttl)
}

func (s *sealedStore) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	record, err := s.seal(key, value, ttl)
	if err != nil {
		return false, err
	}
	return s.inner.SetIfAbsent(ctx, key, record, ttl)
}

// Swap compares what the caller read with what the record opens to, and has the store below replace the
// sealed record only if it is still that one: a second swap of the same value finds another record there.
func (s *sealedStore) Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	swapper, ok := s.inner.(Swapper)
	if !ok {
		return false, ErrNotSwapper
	}
	current, found, err := s.inner.Get(ctx, key)
	if err != nil || !found {
		return false, err
	}
	opened, found, err := s.open(key, current)
	if err != nil || !found || !bytes.Equal(opened, old) {
		return false, err
	}
	record, err := s.seal(key, value, ttl)
	if err != nil {
		return false, err
	}
	return swapper.Swap(ctx, key, current, record, ttl)
}

func (s *sealedStore) SetMany(ctx context.Context, entries ...Entry) error {
	sealed := make([]Entry, len(entries))
	for i, e := range entries {
		record, err := s.seal(e.Key, e.Value, e.TTL)
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
