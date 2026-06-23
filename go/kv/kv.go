// Package kv is a small Redis-style JSON key/value store with per-entry TTLs. Values are opaque JSON
// bytes; callers handle their own (de)serialization. The store is the single persistence primitive for
// the authorization server, the bff, and the nonce service — multi-index lookups are modelled with
// secondary-index keys (a record under "<ns>:<id>" plus "<ns>:<field>:<v>" keys holding the id).
//
// This package has no external dependencies: it ships the interface and the in-memory backend
// (NewMemory — the default for tests and dev). The Postgres backend lives in the sibling kvpg module so
// that importing kv never pulls in a database driver; only code that wires Postgres imports kvpg.
// Consumers accept the kv.Store interface (the duck type), not a concrete backend.
//
// Atomicity: Take (get+delete) and SetMany (multi-key write) are atomic, which the security-critical
// single-use (nonce redeem, authorization-code exchange) and index-consistency operations rely on.
package kv

import (
	"context"
	"errors"
	"time"
)

// ErrClosed is returned by every method after Close.
var ErrClosed = errors.New("kv: store closed")

// Entry is one key/value/TTL triple for SetMany. A zero TTL means no expiry.
type Entry struct {
	Key   string
	Value []byte
	TTL   time.Duration
}

// Store is the persistence interface. Implementations must be safe for concurrent use.
type Store interface {
	// Get returns the value for key. found is false when the key is absent or expired.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)

	// Set stores value under key with an optional TTL (0 = no expiry), overwriting any existing value.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// SetMany writes all entries atomically (one transaction), used to keep a record and its
	// secondary-index keys consistent.
	SetMany(ctx context.Context, entries ...Entry) error

	// Take atomically returns and deletes key — single-use semantics for nonce redemption and
	// authorization-code exchange. found is false when the key is absent or expired.
	Take(ctx context.Context, key string) (value []byte, found bool, err error)

	// Delete removes key. No error if it doesn't exist.
	Delete(ctx context.Context, key string) error

	// Keys returns all non-expired keys with the given prefix, sorted. The prefix is matched
	// literally (callers use wildcard-free namespace prefixes).
	Keys(ctx context.Context, prefix string) ([]string, error)

	// Cleanup removes expired entries and returns the count removed.
	Cleanup(ctx context.Context) (removed int, err error)

	// Close releases resources; subsequent calls return ErrClosed.
	Close() error
}
