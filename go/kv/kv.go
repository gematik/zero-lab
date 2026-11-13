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

// Package kv is a small Redis-style key/value store with per-entry TTLs. Values are opaque bytes (JSON
// records, encrypted snapshots, or at-rest ciphertext); callers handle their own (de)serialization. The
// store is the single persistence primitive for the authorization server and the pep — multi-index lookups
// are modelled with secondary-index keys (a record under "<ns>:<id>" plus "<ns>:<field>:<v>" keys holding
// the id). [NewSealed] wraps a Store so that it sees ciphertext only (server rule 5).
//
// This package has no external dependencies: it ships the interface and the in-memory backend
// (NewMemory — the default for tests and dev). The Postgres backend is the package kv/postgres in this
// module: kv's go.mod requires pgx, but a binary links the driver only if it imports kv/postgres.
// Consumers accept the kv.Store interface (the duck type), not a concrete backend.
//
// Atomicity: Take (get+delete), SetIfAbsent and SetMany (multi-key write) are atomic, which the
// security-critical single-use (nonce redeem, authorization-code exchange, proof replay) and
// index-consistency operations rely on.
package kv

import (
	"context"
	"errors"
	"time"
)

// ErrClosed is returned by every method after Close.
var ErrClosed = errors.New("kv: store closed")

// ErrNotSwapper is what [Swapper.Swap] of a wrapping store returns when the store below cannot swap.
var ErrNotSwapper = errors.New("kv: the store cannot swap")

// Swapper is a [Store] that can replace a value only while it is still the one a caller read. It is how state
// that every replica may change moves forward one step at a time: of two that replace the same value at once,
// one succeeds, and the other learns that what it read is gone. The stores of this module are Swappers.
type Swapper interface {
	// Swap sets key to value, ending after ttl (zero: never), if key holds old now. swapped is false if it
	// holds anything else, or is absent or expired.
	Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (swapped bool, err error)
}

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

	// SetIfAbsent stores value under key only if the key is absent or expired, atomically, and reports whether
	// it did: of concurrent calls for one key across all replicas exactly one gets set = true. TTL as for Set.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (set bool, err error)

	// SetMany writes all entries atomically (one transaction), used to keep a record and its
	// secondary-index keys consistent.
	SetMany(ctx context.Context, entries ...Entry) error

	// Take atomically returns and deletes key — single-use semantics for authorization-code exchange. found is false when the key is absent or expired.
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
