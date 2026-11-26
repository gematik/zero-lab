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
	"log/slog"
	"time"
)

const (
	sealedEventVersion = 1
	// sealedEventKDFInfo keeps the keys of events apart from those of records under the same ring.
	sealedEventKDFInfo = "zero-lab/kv/event/v1\x00"
)

// eventSealer seals the events of a feed: each with AES-256-GCM under a key derived by HKDF-SHA256 from the
// ring's current key, the purpose and a fresh random salt, and bound through the associated data to its
// key ID, the purpose, its topic and its number.
//
//	event = version(1) | len(key ID)(1) | key ID | salt(16) | nonce(12) | ciphertext and tag
type eventSealer struct {
	keys    Keys
	purpose string
}

func (e *eventSealer) aead(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("kv: a sealing key has %d bytes, not %d", keySize, len(key))
	}
	derived, err := hkdf.Key(sha256.New, key, salt, sealedEventKDFInfo+e.purpose, keySize)
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

// associatedData is length-prefixed, so no two different inputs encode alike.
func (e *eventSealer) associatedData(id, topic string, cursor Cursor) []byte {
	ad := make([]byte, 0, 1+4+len(id)+4+len(e.purpose)+4+len(topic)+8)
	ad = append(ad, sealedEventVersion)
	for _, part := range []string{id, e.purpose, topic} {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part)))
		ad = append(ad, part...)
	}
	return binary.BigEndian.AppendUint64(ad, uint64(cursor))
}

// sealedEventOverhead is what sealing adds to an event besides the key ID.
const sealedEventOverhead = 2 + sealedSaltSize + sealedNonceSize + sealedTagSize

func (e *eventSealer) seal(topic string, cursor Cursor, payload []byte) ([]byte, error) {
	id, key := e.keys.Current()
	defer clear(key)
	if !validKeyID(id) {
		return nil, errors.New("kv: the current key has an invalid ID")
	}
	if len(payload)+sealedEventOverhead+len(id) > MaxEventLen {
		return nil, ErrEvent
	}
	random := make([]byte, sealedSaltSize+sealedNonceSize)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	salt, nonce := random[:sealedSaltSize], random[sealedSaltSize:]
	aead, err := e.aead(key, salt)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(payload)+sealedEventOverhead+len(id))
	sealed = append(sealed, sealedEventVersion, byte(len(id)))
	sealed = append(sealed, id...)
	sealed = append(sealed, random...)
	return aead.Seal(sealed, nonce, payload, e.associatedData(id, topic, cursor)), nil
}

// open returns [ErrIntegrity] for anything that does not open: an event that was altered, is of another
// purpose, or stands under another topic or number than it was sealed for.
func (e *eventSealer) open(topic string, cursor Cursor, sealed []byte) ([]byte, error) {
	if len(sealed) < 2 || sealed[0] != sealedEventVersion {
		return nil, ErrIntegrity
	}
	idLen := int(sealed[1])
	if len(sealed) < 2+idLen+sealedSaltSize+sealedNonceSize+sealedTagSize {
		return nil, ErrIntegrity
	}
	id := string(sealed[2 : 2+idLen])
	rest := sealed[2+idLen:]
	salt, nonce, ciphertext := rest[:sealedSaltSize], rest[sealedSaltSize:sealedSaltSize+sealedNonceSize], rest[sealedSaltSize+sealedNonceSize:]
	key, ok := e.keys.Lookup(id)
	if !ok {
		return nil, ErrIntegrity
	}
	defer clear(key)
	aead, err := e.aead(key, salt)
	if err != nil {
		return nil, ErrIntegrity
	}
	payload, err := aead.Open(nil, nonce, ciphertext, e.associatedData(id, topic, cursor))
	if err != nil {
		return nil, ErrIntegrity
	}
	if payload == nil {
		payload = []byte{}
	}
	return payload, nil
}

// follow opens the events of a follower. One that does not open is left out, and logged with its topic and
// number: the follower sees a number missing, which is what tells it that it has not seen all there was
// and to read its state anew, as when an event's retention is over. Whoever can write to the database can
// take an event away in any case; what sealing adds is that they cannot make one up, change one, or put
// one where it was not.
func (e *eventSealer) follow(ctx context.Context, topic string, in <-chan Event) <-chan Event {
	out := make(chan Event, cap(in))
	go func() {
		defer close(out)
		for event := range in {
			payload, err := e.open(topic, event.Cursor, event.Payload)
			if err != nil {
				slog.ErrorContext(ctx, "kv: an event of the feed does not open and is left out", "topic", topic, "number", uint64(event.Cursor))
				continue
			}
			event.Payload = payload
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (e *eventSealer) publish(ctx context.Context, feed Feed, topic string, event []byte, retention time.Duration) (Cursor, error) {
	numbered, ok := feed.(NumberedFeed)
	if !ok {
		return 0, ErrNotFeed
	}
	return numbered.PublishNumbered(ctx, topic, retention, func(cursor Cursor) ([]byte, error) {
		return e.seal(topic, cursor, event)
	})
}

// NewSealedFeed wraps a feed so that the database sees ciphertext only (server rule 5): what Publish writes
// is sealed, and what Follow delivers is opened. An event is bound to the purpose, its topic and its
// number, so it opens neither under another purpose nor moved to another topic or place. Topics stay in
// the clear, as keys do: a topic must not carry a secret. The feed below must be a [NumberedFeed].
//
// It is for a program that follows or publishes events and holds no records, with keys of its own for the
// feed. A sealed store ([NewSealed]) is a sealed feed already, under the store's keys unless
// [WithSealedEvents] gives others.
//
// It panics on a nil feed or keys or an empty purpose: those are wiring mistakes at start-up, and carrying
// on could only mean publishing plaintext.
func NewSealedFeed(feed Feed, keys Keys, purpose string) Feed {
	if feed == nil || keys == nil || purpose == "" {
		panic("kv: NewSealedFeed needs a feed, keys and a purpose")
	}
	return &sealedFeed{inner: feed, events: &eventSealer{keys: keys, purpose: purpose}}
}

type sealedFeed struct {
	inner  Feed
	events *eventSealer
}

func (f *sealedFeed) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) (Cursor, error) {
	return f.events.publish(ctx, f.inner, topic, event, retention)
}

func (f *sealedFeed) Follow(ctx context.Context, topic string, from Cursor) (<-chan Event, error) {
	in, err := f.inner.Follow(ctx, topic, from)
	if err != nil {
		return nil, err
	}
	return f.events.follow(ctx, topic, in), nil
}

func (f *sealedFeed) Latest(ctx context.Context, topic string) (Cursor, error) {
	return f.inner.Latest(ctx, topic)
}

// WithSealedEvents seals the events of a sealed store under keys and a purpose of their own instead of the
// store's: so that a program that only follows the events (with [NewSealedFeed] over the same keys and
// purpose) needs no key that opens the records.
func WithSealedEvents(keys Keys, purpose string) SealedOption {
	if keys == nil || purpose == "" {
		panic("kv: WithSealedEvents needs keys and a purpose")
	}
	return func(s *sealedStore) { s.events = &eventSealer{keys: keys, purpose: purpose} }
}

// Publish implements [Feed] over the store below, which must be a [NumberedFeed]: the event is sealed.
func (s *sealedStore) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) (Cursor, error) {
	feed, ok := s.inner.(Feed)
	if !ok {
		return 0, ErrNotFeed
	}
	return s.events.publish(ctx, feed, topic, event, retention)
}

// Follow implements [Feed] over the store below: events are opened.
func (s *sealedStore) Follow(ctx context.Context, topic string, from Cursor) (<-chan Event, error) {
	feed, ok := s.inner.(Feed)
	if !ok {
		return nil, ErrNotFeed
	}
	in, err := feed.Follow(ctx, topic, from)
	if err != nil {
		return nil, err
	}
	return s.events.follow(ctx, topic, in), nil
}

// Latest implements [Feed] over the store below.
func (s *sealedStore) Latest(ctx context.Context, topic string) (Cursor, error) {
	feed, ok := s.inner.(Feed)
	if !ok {
		return 0, ErrNotFeed
	}
	return feed.Latest(ctx, topic)
}
