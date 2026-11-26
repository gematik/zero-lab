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

package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/gematik/zero-lab/go/kv"
)

// feedSQL is step 3: the events of the feed, and for each topic the counter its events are numbered by.
// A counter stays when its events are gone: numbers never go back.
const feedSQL = `
CREATE TABLE IF NOT EXISTS kv_topic (
  topic text PRIMARY KEY,
  seq   bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS kv_feed (
  topic      text NOT NULL,
  seq        bigint NOT NULL,
  payload    bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (topic, seq)
);
CREATE INDEX IF NOT EXISTS idx_kv_feed_expires_at ON kv_feed(expires_at);
`

// feedChannel is the one NOTIFY channel of the feed. A notification carries the topic and nothing of the
// event: it says that there is something to read, and what there is is read from the table.
const feedChannel = "kv_feed"

// defaultFeedPoll is how often a follower looks without having been told: what a notification that was
// lost costs.
const defaultFeedPoll = 30 * time.Second

// followBatch is how many events a follower reads at a time.
const followBatch = 256

// WithFeedPoll sets how often a follower of the feed looks for events without a notification, 30 seconds
// without it. Notifications are how events arrive at once; the look is what makes a lost one cost time and
// not an event.
func WithFeedPoll(every time.Duration) Option {
	return func(s *store) { s.poll = every }
}

// The SQLSTATEs of a transaction that lost against another and is right to run again.
const (
	serializationFailure = "40001"
	deadlockDetected     = "40P01"
)

// txAttempts bounds how often a transaction is run.
const txAttempts = 8

func lost(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == serializationFailure || pg.Code == deadlockDetected)
}

// jitter is a number below n, uneven enough to keep writers apart.
func jitter(n int) int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return int(b[0]) % n
}

// Tx implements kv.Transactor.
func (s *store) Tx(ctx context.Context, fn func(tx kv.Tx) error) error {
	var err error
	for try := range txAttempts {
		err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if s.ephemeral {
				if _, err := tx.Exec(ctx, asyncCommitSQL); err != nil {
					return err
				}
			}
			return fn(&pgTx{s: s, tx: tx})
		})
		if !lost(err) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(1+jitter(4*(try+1))) * time.Millisecond):
		}
	}
	if err != nil && !errors.Is(err, kv.ErrTxTooLarge) && !errors.Is(err, kv.ErrEvent) && !errors.Is(err, kv.ErrEphemeralEvent) {
		if _, database := errors.AsType[*pgconn.PgError](err); database {
			return fmt.Errorf("kv/postgres: transaction: %w", err)
		}
	}
	return err
}

type pgTx struct {
	s   *store
	tx  pgx.Tx
	ops kv.TxOps
}

func (t *pgTx) exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	return t.tx.Exec(ctx, t.s.q(query), args...)
}

func (t *pgTx) queryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return t.tx.QueryRow(ctx, t.s.q(query), args...)
}

// keyLock is the seed of the advisory locks Get takes on keys, so that they are no other lock of this
// package's by chance of a hash.
const keyLock = 0x6b765f6b6579 // "kv_key"

// Get holds the record until the transaction ends, also a record that is not there: a transaction's
// advisory lock on the key makes the transactions that read one key wait for each other, and the row lock
// keeps a writer outside a transaction from changing a record that is there.
func (t *pgTx) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := t.ops.Count(); err != nil {
		return nil, false, err
	}
	if _, err := t.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`, key, int64(keyLock)); err != nil {
		return nil, false, err
	}
	var v []byte
	err := t.queryRow(ctx, `SELECT value FROM @kv WHERE key=$1 AND `+live+` FOR UPDATE`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return nonNil(v), true, nil
}

func (t *pgTx) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	_, err := t.exec(ctx, upsertSQL, key, nonNil(value), ttlMicroseconds(ttl), t.s.markOf(key, value))
	return err
}

func (t *pgTx) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := t.ops.Count(); err != nil {
		return false, err
	}
	tag, err := t.exec(ctx, upsertSQL+` WHERE @kv.expires_at IS NOT NULL AND @kv.expires_at <= now()`,
		key, nonNil(value), ttlMicroseconds(ttl), t.s.markOf(key, value))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (t *pgTx) Take(ctx context.Context, key string) ([]byte, bool, error) {
	if err := t.ops.Count(); err != nil {
		return nil, false, err
	}
	var v []byte
	err := t.queryRow(ctx, `DELETE FROM @kv WHERE key=$1 AND `+live+` RETURNING value`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return nonNil(v), true, nil
}

func (t *pgTx) Delete(ctx context.Context, key string) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	_, err := t.exec(ctx, `DELETE FROM @kv WHERE key=$1`, key)
	return err
}

func (t *pgTx) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) error {
	return t.PublishNumbered(ctx, topic, retention, func(kv.Cursor) ([]byte, error) { return event, nil })
}

// PublishNumbered implements kv.NumberedTx.
func (t *pgTx) PublishNumbered(ctx context.Context, topic string, retention time.Duration, event func(kv.Cursor) ([]byte, error)) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	if t.s.ephemeral {
		return kv.ErrEphemeralEvent
	}
	_, err := publish(ctx, t.tx, topic, retention, event)
	return err
}

// publish numbers the event by the topic's counter and writes it, in the caller's transaction. The update
// of the counter locks its row until the commit, so the publishers of one topic commit one after another:
// the numbers have no gap and become visible in their own order, and a follower that reads the events
// after its cursor steps over none. A sequence would not do: its values become visible in the order of the
// commits, not in their own. The notification is sent by the database when the transaction commits.
func publish(ctx context.Context, tx pgx.Tx, topic string, retention time.Duration, event func(kv.Cursor) ([]byte, error)) (kv.Cursor, error) {
	if err := kv.CheckEvent(topic, nil, retention); err != nil {
		return 0, err
	}
	var seq int64
	if err := tx.QueryRow(ctx, `INSERT INTO kv_topic(topic, seq) VALUES($1, 1)
		ON CONFLICT(topic) DO UPDATE SET seq = kv_topic.seq + 1 RETURNING seq`, topic).Scan(&seq); err != nil {
		return 0, err
	}
	// The event is made for its number: a sealed one is bound to it.
	payload, err := event(cursorOf(seq))
	if err == nil {
		err = kv.CheckEvent(topic, payload, retention)
	}
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO kv_feed(topic, seq, payload, expires_at)
		VALUES($1, $2, $3, now() + $4::bigint * interval '1 microsecond')`,
		topic, seq, nonNil(payload), retention.Microseconds()); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, feedChannel, topic); err != nil {
		return 0, err
	}
	return cursorOf(seq), nil
}

// cursorOf is a counter of the database as a cursor; counters start at 1 and count up.
func cursorOf(seq int64) kv.Cursor {
	if seq < 0 {
		return 0
	}
	return kv.Cursor(seq)
}

// numberOf is a cursor as the database's number. A cursor beyond what the database counts to is after
// every event.
func numberOf(cursor kv.Cursor) int64 {
	if cursor > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(cursor)
}

// Publish implements kv.Feed.
func (s *store) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) (kv.Cursor, error) {
	return s.PublishNumbered(ctx, topic, retention, func(kv.Cursor) ([]byte, error) { return event, nil })
}

// PublishNumbered implements kv.NumberedFeed.
func (s *store) PublishNumbered(ctx context.Context, topic string, retention time.Duration, event func(kv.Cursor) ([]byte, error)) (kv.Cursor, error) {
	if s.ephemeral {
		return 0, kv.ErrEphemeralEvent
	}
	var cursor kv.Cursor
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		cursor, err = publish(ctx, tx, topic, retention, event)
		return err
	})
	if _, database := errors.AsType[*pgconn.PgError](err); database {
		return 0, fmt.Errorf("kv/postgres: publish: %w", err)
	}
	return cursor, err
}

// Latest implements kv.Feed.
func (s *store) Latest(ctx context.Context, topic string) (kv.Cursor, error) {
	if s.ephemeral {
		return 0, kv.ErrEphemeralEvent
	}
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT seq FROM kv_topic WHERE topic=$1`, topic).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("kv/postgres: latest: %w", err)
	}
	return cursorOf(seq), nil
}

// Follow implements kv.Feed. A follower listens on a connection of its own and looks when it is told and
// every [WithFeedPoll]; while that connection cannot be made it only looks.
func (s *store) Follow(ctx context.Context, topic string, from kv.Cursor) (<-chan kv.Event, error) {
	if s.ephemeral {
		return nil, kv.ErrEphemeralEvent
	}
	if topic == "" || len(topic) > kv.MaxTopicLen {
		return nil, kv.ErrEvent
	}
	out := make(chan kv.Event, 16)
	go s.follow(ctx, topic, from, out)
	return out, nil
}

func (s *store) follow(ctx context.Context, topic string, cursor kv.Cursor, out chan<- kv.Event) {
	defer close(out)
	var listener *pgx.Conn
	defer func() {
		if listener != nil {
			_ = listener.Close(context.WithoutCancel(ctx))
		}
	}()
	for ctx.Err() == nil {
		// The listener stands before the look: what is published between the look and the wait has
		// its notification waiting on the connection.
		if listener == nil {
			conn, err := pgx.ConnectConfig(ctx, s.listen.Copy())
			if err == nil {
				if _, err = conn.Exec(ctx, `LISTEN `+feedChannel); err != nil {
					_ = conn.Close(context.WithoutCancel(ctx))
				} else {
					listener = conn
				}
			}
			if err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "kv/postgres: the feed's follower does not listen and only looks", "error", err)
			}
		}
		for {
			events, err := s.eventsAfter(ctx, topic, cursor)
			if err != nil {
				if ctx.Err() == nil {
					slog.WarnContext(ctx, "kv/postgres: the feed's follower ends", "error", err)
				}
				return
			}
			for _, e := range events {
				select {
				case out <- e:
					cursor = e.Cursor
				case <-ctx.Done():
					return
				}
			}
			if len(events) < followBatch {
				break
			}
		}
		wait, cancel := context.WithTimeout(ctx, s.poll)
		if listener == nil {
			<-wait.Done()
		} else if _, err := listener.WaitForNotification(wait); err != nil && wait.Err() == nil {
			// The connection broke; the next round makes a new one.
			_ = listener.Close(context.WithoutCancel(ctx))
			listener = nil
		}
		cancel()
	}
}

func (s *store) eventsAfter(ctx context.Context, topic string, cursor kv.Cursor) ([]kv.Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT seq, payload, created_at FROM kv_feed
		WHERE topic=$1 AND seq > $2 AND expires_at > now() ORDER BY seq LIMIT $3`,
		topic, numberOf(cursor), followBatch)
	if err != nil {
		return nil, err
	}
	var events []kv.Event
	var seq int64
	var e kv.Event
	_, err = pgx.ForEachRow(rows, []any{&seq, &e.Payload, &e.At}, func() error {
		events = append(events, kv.Event{Cursor: cursorOf(seq), Payload: nonNil(e.Payload), At: e.At})
		e.Payload = nil
		return nil
	})
	return events, err
}
