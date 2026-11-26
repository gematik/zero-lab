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
	"errors"
	"time"
)

// Cursor is a place in a topic: the number of an event. Numbers of one topic count from 1 without a gap, in
// the order in which the events were committed; 0 is the place before the first.
type Cursor uint64

// Event is one event of a topic.
type Event struct {
	Cursor  Cursor
	Payload []byte
	// At is when the event was written, by the clock of the store.
	At time.Time
}

// Feed is an ordered stream of small events per topic that several processes share: every follower gets
// every event at least once, in order, and takes up where it left off by the cursor of the last event it
// handled. It is how replicas learn of a change without asking for it again and again: a revocation, an
// invalidation. Delivery is as fast as the backend can make it and is no part of the contract: one backend
// pushes, another is asked every second. A consumer must not depend on which.
//
// An event is kept for the retention its publisher gave it and then gone. Numbers are without a gap, so a
// follower that gets an event whose number is not the one after its cursor knows that events before it are
// gone, and reads its state anew from where it is kept.
type Feed interface {
	// Publish appends event to topic and returns its cursor. It is kept for retention, which must be
	// positive.
	Publish(ctx context.Context, topic string, event []byte, retention time.Duration) (Cursor, error)
	// Follow delivers the events of topic after from, those there are and those to come, until ctx ends,
	// upon which the channel is closed. An error that ends it before is logged and closes the channel too;
	// the follower calls Follow again from its cursor.
	Follow(ctx context.Context, topic string, from Cursor) (<-chan Event, error)
	// Latest returns the cursor of the last event published to topic, 0 if there was none.
	Latest(ctx context.Context, topic string) (Cursor, error)
}

// Transactor runs fn in one transaction: what fn reads with Get stays as read until the end, and what it
// writes and publishes takes effect together when fn returns nil, or not at all when it returns an error.
// A follower never hears of a change that did not happen, nor misses one that did, and records that belong
// together change together.
//
// What a caller has to know, because it holds on every backend:
//
//   - fn may run more than once. A backend runs it again when the database says the transaction lost
//     against another (a deadlock, a failed certification in a cluster). So fn has no effect outside tx and
//     decides anew from what it reads each time.
//   - Records are named, not searched: tx lists no keys. What belongs together is reached by key, from a
//     record that names its relatives or an index record that lists them.
//   - Records that change together hang under one root record. Every transaction that changes any of them
//     calls Get of the root first and Set of it last: the Get makes transactions of one root wait for each
//     other on one database node, and the Set is what a cluster with several writing nodes checks between
//     them. A decision that rests on a record fn only read is not protected across such nodes.
//   - A transaction is for the handful of records of one operation: at most [MaxTxOps] calls of tx.
//   - Inside fn the store is used through tx alone. A call of the store itself is outside the transaction,
//     and in some backends waits for the transaction that makes it.
type Transactor interface {
	Tx(ctx context.Context, fn func(tx Tx) error) error
}

// Tx is the store inside a transaction ([Transactor]).
type Tx interface {
	// Get returns the value for key and holds the record against other writers until the transaction ends.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (set bool, err error)
	Take(ctx context.Context, key string) (value []byte, found bool, err error)
	Delete(ctx context.Context, key string) error
	// Publish appends event to topic when the transaction commits ([Feed.Publish]).
	Publish(ctx context.Context, topic string, event []byte, retention time.Duration) error
}

const (
	// MaxTxOps is how many calls of [Tx] one transaction may make.
	MaxTxOps = 256
	// MaxTopicLen is the longest name of a topic, in bytes.
	MaxTopicLen = 255
	// MaxEventLen is the longest payload of an event, in bytes: an event says that something changed, it
	// does not carry it.
	MaxEventLen = 64 << 10
)

var (
	// ErrTxTooLarge is a transaction that made more than [MaxTxOps] calls. Nothing of it took effect.
	ErrTxTooLarge = errors.New("kv: the transaction makes more calls than a transaction may")
	// ErrEvent is a topic or an event a feed does not take: an empty or too long topic, too long a payload,
	// no retention.
	ErrEvent = errors.New("kv: the feed does not take this topic or event")
	// ErrNotTransactor is what a wrapping store returns when the store below runs no transactions.
	ErrNotTransactor = errors.New("kv: the store runs no transactions")
	// ErrNotFeed is what a wrapping store returns when the store below keeps no feed.
	ErrNotFeed = errors.New("kv: the store keeps no feed")
)

// CheckEvent reports whether a feed takes an event: what every backend checks before it writes one.
func CheckEvent(topic string, event []byte, retention time.Duration) error {
	if topic == "" || len(topic) > MaxTopicLen || len(event) > MaxEventLen || retention <= 0 {
		return ErrEvent
	}
	return nil
}

// TxOps counts the calls of a transaction for a backend: Count returns [ErrTxTooLarge] from the call that
// is one too many, and from every call after it.
type TxOps struct{ n int }

// Count counts one call.
func (o *TxOps) Count() error {
	o.n++
	if o.n > MaxTxOps {
		return ErrTxTooLarge
	}
	return nil
}
