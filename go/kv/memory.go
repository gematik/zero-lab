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
	"sort"
	"strings"
	"sync"
	"time"
)

type memoryStore struct {
	mu     sync.Mutex
	items  map[string]memEntry
	closed bool
	now    func() time.Time
}

type memEntry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e memEntry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && !e.expiresAt.After(now)
}

// NewMemory returns an in-memory Store — the default backend for tests and development. It is single-replica
// only: nothing in it reaches another process, so nonce, replay and session state in it holds for this
// process alone, and it is lost on exit. Several replicas need the Postgres backend (kv/postgres).
func NewMemory(opts ...MemoryOption) Store {
	s := &memoryStore{items: make(map[string]memEntry), now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// MemoryOption adjusts the store [NewMemory] returns.
type MemoryOption func(*memoryStore)

// WithMemoryClock sets the time records expire by; the default is the system clock.
func WithMemoryClock(now func() time.Time) MemoryOption {
	return func(s *memoryStore) { s.now = now }
}

func (s *memoryStore) ttlExpiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.now().Add(ttl)
}

func (s *memoryStore) Get(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, ErrClosed
	}
	e, ok := s.items[key]
	if !ok {
		return nil, false, nil
	}
	if e.expired(s.now()) {
		delete(s.items, key)
		return nil, false, nil
	}
	return clone(e.value), true, nil
}

func (s *memoryStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.items[key] = memEntry{value: clone(value), expiresAt: s.ttlExpiry(ttl)}
	return nil
}

func (s *memoryStore) SetIfAbsent(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if e, ok := s.items[key]; ok && !e.expired(s.now()) {
		return false, nil
	}
	s.items[key] = memEntry{value: clone(value), expiresAt: s.ttlExpiry(ttl)}
	return true, nil
}

func (s *memoryStore) Swap(_ context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if e, ok := s.items[key]; !ok || e.expired(s.now()) || !bytes.Equal(e.value, old) {
		return false, nil
	}
	s.items[key] = memEntry{value: clone(value), expiresAt: s.ttlExpiry(ttl)}
	return true, nil
}

func (s *memoryStore) SetMany(_ context.Context, entries ...Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, e := range entries {
		s.items[e.Key] = memEntry{value: clone(e.Value), expiresAt: s.ttlExpiry(e.TTL)}
	}
	return nil
}

func (s *memoryStore) Take(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, ErrClosed
	}
	e, ok := s.items[key]
	if !ok {
		return nil, false, nil
	}
	delete(s.items, key)
	if e.expired(s.now()) {
		return nil, false, nil
	}
	return clone(e.value), true, nil
}

func (s *memoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	delete(s.items, key)
	return nil
}

func (s *memoryStore) Keys(_ context.Context, prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	now := s.now()
	var out []string
	for k, e := range s.items {
		if !e.expired(now) && strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *memoryStore) Cleanup(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	now := s.now()
	n := 0
	for k, e := range s.items {
		if e.expired(now) {
			delete(s.items, k)
			n++
		}
	}
	return n, nil
}

func (s *memoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.items = nil
	return nil
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
