// Package state provides a small Redis-style key/value store with per-entry
// TTLs. Values are opaque bytes; callers handle their own (de)serialization.
//
// The current backend is SQLite (see sqlite_store.go) — chosen for fast
// cold-start, the ability to hold the occasional MB-scale blob (TI's TSL XML)
// without bloating other operations, and for being readable from Go, Rust,
// and Kotlin/JVM via mature drivers. The Store interface is deliberately
// narrow so future backends can drop in without callers noticing.
//
// Concurrency: a single Store is safe for use from multiple goroutines in one
// process. Cross-process readers are safe (SQLite WAL); cross-process writers
// are serialized by SQLite's busy_timeout.
package state

import "time"

// Store is the high-level API. Implementations must be safe for concurrent use
// within one process.
type Store interface {
	// Get returns the value for key. The second return is false when the key
	// is absent OR present-but-expired (expired entries are dropped lazily).
	Get(key string) ([]byte, bool, error)

	// Set stores value under key. Options control TTL and future Redis-style
	// behaviors (NX/XX/KeepTTL).
	Set(key string, value []byte, opts ...SetOption) error

	// Delete removes key. No error if the key doesn't exist.
	Delete(key string) error

	// Keys returns all non-expired keys with the given prefix, sorted.
	Keys(prefix string) ([]string, error)

	// Cleanup walks the store and removes expired entries. Returns the number
	// removed.
	Cleanup() (removed int, err error)

	// Close releases any held resources. After Close, all methods return an
	// error.
	Close() error
}

// SetOption modifies the behavior of Set. Options compose; later options
// override earlier ones for the same setting.
type SetOption func(*setOptions)

// setOptions is the resolved option set passed to backends. Backend-only
// helpers (and future tests) live in this package; users see only the SetOption
// constructors below.
type setOptions struct {
	expiresAt *time.Time // nil → no TTL

	// Reserved for future Redis-like semantics. Backends are expected to honor
	// these once their constructors are exposed.
	nx      bool // only set if key does not exist (Redis NX)
	xx      bool // only set if key already exists (Redis XX)
	keepTTL bool // retain existing TTL on overwrite (Redis KEEPTTL)
}

// Expire sets a relative TTL. The entry expires at time.Now() + d at the moment
// Set is called.
func Expire(d time.Duration) SetOption {
	return func(o *setOptions) {
		t := time.Now().Add(d)
		o.expiresAt = &t
	}
}

// ExpireAt sets an absolute expiration time.
func ExpireAt(t time.Time) SetOption {
	return func(o *setOptions) {
		o.expiresAt = &t
	}
}

func resolveSetOptions(opts []SetOption) setOptions {
	var s setOptions
	for _, o := range opts {
		o(&s)
	}
	return s
}
