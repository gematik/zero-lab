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
	"time"
)

// memTopic is a topic of the memory store: its counter, which never goes back, and the events kept.
type memTopic struct {
	seq    uint64
	events []memEvent
}

type memEvent struct {
	event     Event
	expiresAt time.Time
}

// memTx is a transaction of the memory store. The store's lock is held while fn runs, so nothing else
// reads or writes; what fn changed is undone from before and topics when it fails.
type memTx struct {
	s   *memoryStore
	ops TxOps
	// before holds, for each key the transaction wrote, the record of before it (nil: none).
	before map[string]*memEntry
	// topics holds, for each topic it published to, the counter and the events of before.
	topics    map[string]memTopic
	published bool
}

// Tx implements [Transactor]. The store is locked while fn runs: a call of the store itself inside fn
// waits for the transaction that makes it, which is forever.
func (s *memoryStore) Tx(_ context.Context, fn func(tx Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	tx := &memTx{s: s, before: map[string]*memEntry{}, topics: map[string]memTopic{}}
	if err := fn(tx); err != nil {
		tx.undo()
		return err
	}
	if tx.published {
		s.wake()
	}
	return nil
}

func (tx *memTx) undo() {
	for key, entry := range tx.before {
		if entry == nil {
			delete(tx.s.items, key)
		} else {
			tx.s.items[key] = *entry
		}
	}
	for name, was := range tx.topics {
		if was.seq == 0 {
			delete(tx.s.topics, name)
			continue
		}
		topic := tx.s.topics[name]
		topic.seq, topic.events = was.seq, was.events
	}
}

// remember keeps the record of before the first write of key.
func (tx *memTx) remember(key string) {
	if _, kept := tx.before[key]; kept {
		return
	}
	if entry, ok := tx.s.items[key]; ok {
		tx.before[key] = &entry
	} else {
		tx.before[key] = nil
	}
}

func (tx *memTx) live(key string) (memEntry, bool) {
	entry, ok := tx.s.items[key]
	if !ok || entry.expired(tx.s.now()) {
		return memEntry{}, false
	}
	return entry, true
}

func (tx *memTx) Get(_ context.Context, key string) ([]byte, bool, error) {
	if err := tx.ops.Count(); err != nil {
		return nil, false, err
	}
	entry, ok := tx.live(key)
	return clone(entry.value), ok, nil
}

func (tx *memTx) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if err := tx.ops.Count(); err != nil {
		return err
	}
	tx.remember(key)
	tx.s.items[key] = memEntry{value: clone(value), expiresAt: tx.s.ttlExpiry(ttl)}
	return nil
}

func (tx *memTx) SetIfAbsent(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := tx.ops.Count(); err != nil {
		return false, err
	}
	if _, ok := tx.live(key); ok {
		return false, nil
	}
	tx.remember(key)
	tx.s.items[key] = memEntry{value: clone(value), expiresAt: tx.s.ttlExpiry(ttl)}
	return true, nil
}

func (tx *memTx) Take(_ context.Context, key string) ([]byte, bool, error) {
	if err := tx.ops.Count(); err != nil {
		return nil, false, err
	}
	entry, ok := tx.live(key)
	tx.remember(key)
	delete(tx.s.items, key)
	return clone(entry.value), ok, nil
}

func (tx *memTx) Delete(_ context.Context, key string) error {
	if err := tx.ops.Count(); err != nil {
		return err
	}
	tx.remember(key)
	delete(tx.s.items, key)
	return nil
}

func (tx *memTx) Publish(_ context.Context, topic string, event []byte, retention time.Duration) error {
	if err := tx.ops.Count(); err != nil {
		return err
	}
	if tx.s.ephemeral {
		return ErrEphemeralEvent
	}
	if err := CheckEvent(topic, event, retention); err != nil {
		return err
	}
	if _, kept := tx.topics[topic]; !kept {
		was := memTopic{}
		if t := tx.s.topics[topic]; t != nil {
			// publish makes a new slice of events, so this one stays as it is.
			was = memTopic{seq: t.seq, events: t.events}
		}
		tx.topics[topic] = was
	}
	tx.s.publish(topic, event, retention)
	tx.published = true
	return nil
}

// publish appends an event; the store's lock is held.
func (s *memoryStore) publish(topic string, event []byte, retention time.Duration) Cursor {
	t := s.topics[topic]
	if t == nil {
		t = &memTopic{}
		s.topics[topic] = t
	}
	now := s.now()
	// Events whose time is over go when the next one comes.
	kept := t.events[:0:0]
	for _, e := range t.events {
		if e.expiresAt.After(now) {
			kept = append(kept, e)
		}
	}
	t.seq++
	kept = append(kept, memEvent{
		event:     Event{Cursor: Cursor(t.seq), Payload: clone(event), At: now},
		expiresAt: now.Add(retention),
	})
	t.events = kept
	return Cursor(t.seq)
}

// wake lets every follower look again; the store's lock is held.
func (s *memoryStore) wake() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// Publish implements [Feed].
func (s *memoryStore) Publish(_ context.Context, topic string, event []byte, retention time.Duration) (Cursor, error) {
	if s.ephemeral {
		return 0, ErrEphemeralEvent
	}
	if err := CheckEvent(topic, event, retention); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	cursor := s.publish(topic, event, retention)
	s.wake()
	return cursor, nil
}

// Latest implements [Feed].
func (s *memoryStore) Latest(_ context.Context, topic string) (Cursor, error) {
	if s.ephemeral {
		return 0, ErrEphemeralEvent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if t := s.topics[topic]; t != nil {
		return Cursor(t.seq), nil
	}
	return 0, nil
}

// Follow implements [Feed].
func (s *memoryStore) Follow(ctx context.Context, topic string, from Cursor) (<-chan Event, error) {
	if s.ephemeral {
		return nil, ErrEphemeralEvent
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	out := make(chan Event, 16)
	go func() {
		defer close(out)
		cursor := from
		for {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			var batch []Event
			if t := s.topics[topic]; t != nil {
				now := s.now()
				for _, e := range t.events {
					if e.event.Cursor > cursor && e.expiresAt.After(now) {
						batch = append(batch, Event{Cursor: e.event.Cursor, Payload: clone(e.event.Payload), At: e.event.At})
					}
				}
			}
			changed := s.changed
			s.mu.Unlock()
			for _, e := range batch {
				select {
				case out <- e:
					cursor = e.Cursor
				case <-ctx.Done():
					return
				}
			}
			if len(batch) > 0 {
				continue
			}
			select {
			case <-changed:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
