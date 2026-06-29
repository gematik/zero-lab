package gempki

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RevocationCache stores [RevocationResult]s keyed by an opaque string
// (typically a hash of issuer-name + serial).
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// The context is plumbed for distributed cache backends (Redis, memcached, …);
// the in-memory implementation ignores it. Get returns (nil, false, nil) for
// a cache miss; expired entries are also reported as misses.
type RevocationCache interface {
	Get(ctx context.Context, key string) (*RevocationResult, bool, error)
	Put(ctx context.Context, key string, result *RevocationResult, ttl time.Duration) error
}

// NoCache returns a [RevocationCache] that stores nothing and reports every
// lookup as a miss. Suitable for tests and for callers that want to disable
// caching without conditionals at every call site.
func NoCache() RevocationCache { return noCache{} }

type noCache struct{}

func (noCache) Get(context.Context, string) (*RevocationResult, bool, error) {
	return nil, false, nil
}

func (noCache) Put(context.Context, string, *RevocationResult, time.Duration) error {
	return nil
}

// InMemoryCache is a bounded, in-process [RevocationCache] suitable for a
// single-instance Validator. Eviction policy when the cache is full:
//   - first, remove any expired entry (cleans up cheaply)
//   - otherwise, remove the entry with the earliest insertion time
//
// This is not LRU — it is "oldest first." Production-grade caches with
// access-pattern-aware eviction can be added behind the same interface
// when there is evidence they would help.
type InMemoryCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[string]cacheEntry
	now      func() time.Time // overridable for tests
}

type cacheEntry struct {
	result    *RevocationResult
	expiresAt time.Time
	insertAt  time.Time
}

// NewInMemoryCache returns an InMemoryCache bounded to capacity entries.
// capacity must be > 0; values ≤ 0 are clamped to 1.
func NewInMemoryCache(capacity int) *InMemoryCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &InMemoryCache{
		capacity: capacity,
		entries:  make(map[string]cacheEntry, capacity),
		now:      time.Now,
	}
}

// Get returns the cached result if present and unexpired.
func (c *InMemoryCache) Get(_ context.Context, key string) (*RevocationResult, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	if c.now().After(e.expiresAt) {
		delete(c.entries, key)
		return nil, false, nil
	}
	return e.result, true, nil
}

// Put stores result under key with the given TTL. A non-positive TTL is
// rejected — callers must decide caching policy explicitly.
func (c *InMemoryCache) Put(_ context.Context, key string, result *RevocationResult, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("gempki: cache TTL must be positive, got %s", ttl)
	}
	if result == nil {
		return fmt.Errorf("gempki: cannot cache nil RevocationResult")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if _, present := c.entries[key]; !present && len(c.entries) >= c.capacity {
		c.evictOneLocked(now)
	}
	c.entries[key] = cacheEntry{
		result:    result,
		expiresAt: now.Add(ttl),
		insertAt:  now,
	}
	return nil
}

// Len returns the number of entries currently held. Useful for tests and
// metrics; do not depend on it for correctness — entries may be expired but
// not yet swept.
func (c *InMemoryCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// evictOneLocked removes one entry, preferring an expired one.
// Caller must hold c.mu.
func (c *InMemoryCache) evictOneLocked(now time.Time) {
	var oldestKey string
	var oldestInsert time.Time
	first := true
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
			return
		}
		if first || e.insertAt.Before(oldestInsert) {
			oldestKey = k
			oldestInsert = e.insertAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}
