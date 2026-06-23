package kv

import (
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
}

type memEntry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

func (e memEntry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && !e.expiresAt.After(now)
}

// NewMemory returns an in-memory Store — the default backend for tests and development. Data is lost
// on process exit; for durability use the Postgres backend (kvpg).
func NewMemory() Store {
	return &memoryStore{items: make(map[string]memEntry)}
}

func ttlExpiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
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
	if e.expired(time.Now()) {
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
	s.items[key] = memEntry{value: clone(value), expiresAt: ttlExpiry(ttl)}
	return nil
}

func (s *memoryStore) SetMany(_ context.Context, entries ...Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, e := range entries {
		s.items[e.Key] = memEntry{value: clone(e.Value), expiresAt: ttlExpiry(e.TTL)}
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
	if e.expired(time.Now()) {
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
	now := time.Now()
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
	now := time.Now()
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
