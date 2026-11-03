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

// Package nonce issues nonces that verify themselves, so that handing one out costs no store and no shared
// state (server rule 10): a nonce seals its expiry and random bytes with AES-256-GCM under a key derived from a
// key all replicas share. [Service] nonces are single use, which takes a record on acceptance; [Source] nonces
// are reusable within their window, as RFC 9449 Section 8 allows.
package nonce

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrInvalid is returned for a nonce this package does not accept: malformed, forged, expired, of another
// purpose, or sealed under a key no longer held.
var ErrInvalid = errors.New("nonce: invalid")

// ErrReplayed is returned by [Service.Redeem] for a valid nonce that was accepted before.
var ErrReplayed = errors.New("nonce: already used")

const version byte = 1

const (
	keySize    = 32
	saltSize   = 16
	gcmNonce   = 12
	gcmTag     = 16
	expirySize = 8
	randomSize = 16

	// MaxKeyIDLen is the longest key ID a nonce can carry.
	MaxKeyIDLen = 64
	// MaxEncodedLen is the most characters a nonce has. Anything longer is refused before any work on it.
	MaxEncodedLen = ((2+MaxKeyIDLen+saltSize+gcmNonce+expirySize+randomSize+gcmTag)*8 + 5) / 6

	// kdfInfo separates this use of a ring key from every other, such as a sealed kv store's on the same ring.
	kdfInfo = "zero-lab/nonce/v1\x00"
)

// encoding is the unpadded base64url of RFC 4648: every character is an NQCHAR of RFC 9449 Section 8.1.
var encoding = base64.RawURLEncoding.Strict()

// Keys is where nonce keys come from; kv.Keyring has this shape without this package importing kv.
type Keys interface {
	// Current returns the key that seals new nonces. The slice is a fresh copy the caller owns and clears.
	Current() (id string, key []byte)
	// Lookup returns the key with the given ID, for opening. The slice is a fresh copy the caller owns and
	// clears.
	Lookup(id string) (key []byte, ok bool)
}

// Option adjusts a [Service] or [Source].
type Option func(*sealer)

// WithClock sets the time nonces are issued and judged at; the default is the system clock.
func WithClock(now func() time.Time) Option {
	return func(s *sealer) { s.now = now }
}

// sealer is what both kinds of nonce share. kind is in the key derivation, so a nonce of one kind does not pass
// as the other even under the same purpose string.
type sealer struct {
	keys Keys
	info string
	ttl  time.Duration
	now  func() time.Time
}

func newSealer(keys Keys, kind, purpose string, ttl time.Duration, opts []Option) (*sealer, error) {
	if keys == nil || purpose == "" || ttl <= 0 {
		return nil, errors.New("nonce: keys, a purpose and a positive lifetime are required")
	}
	s := &sealer{keys: keys, info: kdfInfo + kind + "\x00" + purpose, ttl: ttl, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// aead derives a key per nonce from a random salt. Anyone may ask for nonces, so a key shared by all of them would
// let an anonymous caller run up against the limit of random GCM nonces, 2^32 messages per key.
func (s *sealer) aead(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("nonce: a key has %d bytes, not %d", keySize, len(key))
	}
	derived, err := hkdf.Key(sha256.New, key, salt, s.info, keySize)
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

// issue seals: version(1) | len(key ID)(1) | key ID | salt(16) | nonce(12) | ciphertext of expiry(8) and
// random(16) | tag, with everything before the salt as associated data; the salt is bound through the key.
func (s *sealer) issue() (string, error) {
	id, key := s.keys.Current()
	defer clear(key)
	if id == "" || len(id) > MaxKeyIDLen {
		return "", errors.New("nonce: the current key has an invalid ID")
	}
	plaintext := binary.BigEndian.AppendUint64(make([]byte, 0, expirySize+randomSize),
		uint64(s.now().Add(s.ttl).Unix()))
	plaintext = plaintext[:expirySize+randomSize]
	if _, err := rand.Read(plaintext[expirySize:]); err != nil {
		return "", err
	}
	sealed := make([]byte, 0, 2+len(id)+saltSize+gcmNonce+len(plaintext)+gcmTag)
	sealed = append(sealed, version, byte(len(id)))
	sealed = append(sealed, id...)
	header := len(sealed)
	sealed = sealed[:header+saltSize+gcmNonce]
	if _, err := rand.Read(sealed[header:]); err != nil {
		return "", err
	}
	salt, gcm := sealed[header:header+saltSize], sealed[header+saltSize:]
	aead, err := s.aead(key, salt)
	if err != nil {
		return "", err
	}
	sealed = aead.Seal(sealed, gcm, plaintext, sealed[:header])
	return encoding.EncodeToString(sealed), nil
}

// open returns the expiry of a nonce it accepts. The length comes first, since an anonymous peer picks the input.
func (s *sealer) open(candidate string) (time.Time, error) {
	if len(candidate) > MaxEncodedLen {
		return time.Time{}, ErrInvalid
	}
	raw, err := encoding.DecodeString(candidate)
	// The decoder skips newlines: only the one spelling that encodes back counts, since a single-use nonce is
	// recorded by its string and a second spelling would be a second use.
	if err != nil || encoding.EncodeToString(raw) != candidate {
		return time.Time{}, ErrInvalid
	}
	if len(raw) < 2 || raw[0] != version {
		return time.Time{}, ErrInvalid
	}
	idLen := int(raw[1])
	header := 2 + idLen
	if idLen == 0 || idLen > MaxKeyIDLen || len(raw) != header+saltSize+gcmNonce+expirySize+randomSize+gcmTag {
		return time.Time{}, ErrInvalid
	}
	key, ok := s.keys.Lookup(string(raw[2:header]))
	if !ok {
		return time.Time{}, ErrInvalid
	}
	defer clear(key)
	aead, err := s.aead(key, raw[header:header+saltSize])
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	gcm := header + saltSize
	plaintext, err := aead.Open(nil, raw[gcm:gcm+gcmNonce], raw[gcm+gcmNonce:], raw[:header])
	if err != nil {
		return time.Time{}, ErrInvalid
	}
	expiry := time.Unix(int64(binary.BigEndian.Uint64(plaintext)), 0)
	if !s.now().Before(expiry) {
		return time.Time{}, ErrInvalid
	}
	return expiry, nil
}

// Record remembers an accepted nonce: id is the SHA-256 of the nonce, until its expiry. It reports whether this
// was the first time, atomically across all replicas, and keeps the record at least until until.
type Record func(ctx context.Context, id string, until time.Time) (first bool, err error)

// Service issues nonces without touching a store, and accepts each one once, keeping a record only from
// acceptance on: an anonymous request for a nonce costs no write.
type Service struct {
	sealer *sealer
	record Record
}

// New returns a Service for one purpose: a nonce of one purpose is refused under another. ttl is how long a
// nonce stays redeemable. Replicas share a Service's single use through what record writes to, and accept each
// other's nonces by sharing keys.
func New(keys Keys, purpose string, ttl time.Duration, record Record, opts ...Option) (*Service, error) {
	if record == nil {
		return nil, errors.New("nonce: a record function is required")
	}
	sealer, err := newSealer(keys, "single-use", purpose, ttl, opts)
	if err != nil {
		return nil, err
	}
	return &Service{sealer: sealer, record: record}, nil
}

// Get returns a fresh nonce.
func (s *Service) Get() (string, error) { return s.sealer.issue() }

// Redeem accepts a nonce once. It returns [ErrInvalid] or [ErrReplayed] for a nonce it refuses, and the record's
// error if the record fails, which also refuses: a store outage fails closed.
func (s *Service) Redeem(ctx context.Context, nonce string) error {
	expiry, err := s.sealer.open(nonce)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(nonce))
	first, err := s.record(ctx, hex.EncodeToString(sum[:]), expiry)
	if err != nil {
		return fmt.Errorf("nonce: recording: %w", err)
	}
	if !first {
		return ErrReplayed
	}
	return nil
}

// Source has the shape of dpop.NonceSource (RFC 9449 Section 8) without importing dpop. Its nonces are reusable
// within their window by design and need no record; the proofs that carry them are what a replay cache watches.
type Source struct {
	sealer *sealer
}

// NewSource returns a Source for one purpose; ttl is the window in which a nonce stays valid.
func NewSource(keys Keys, purpose string, ttl time.Duration, opts ...Option) (*Source, error) {
	sealer, err := newSealer(keys, "reusable", purpose, ttl, opts)
	if err != nil {
		return nil, err
	}
	return &Source{sealer: sealer}, nil
}

// Valid reports whether nonce is one a replica recently supplied.
func (s *Source) Valid(nonce string) bool {
	_, err := s.sealer.open(nonce)
	return err == nil
}

// Fresh returns an unpredictable nonce for a client's next proof.
func (s *Source) Fresh() (string, error) { return s.sealer.issue() }

// ephemeralKeys is one random key that lives and dies with the process.
type ephemeralKeys struct {
	key []byte
}

// NewEphemeralKeys returns keys that exist in this process only. They suit a single replica whose store is
// per-process as well; replicas with one of these each refuse the others' nonces.
func NewEphemeralKeys() (Keys, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &ephemeralKeys{key: key}, nil
}

const ephemeralKeyID = "ephemeral"

func (k *ephemeralKeys) Current() (string, []byte) {
	return ephemeralKeyID, append([]byte(nil), k.key...)
}

func (k *ephemeralKeys) Lookup(id string) ([]byte, bool) {
	if id != ephemeralKeyID {
		return nil, false
	}
	return append([]byte(nil), k.key...), true
}
