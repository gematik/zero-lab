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

package mariadb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/gematik/zero-lab/go/kv"
)

// The feed is two tables, each a step: for each topic the counter its events are numbered by, and the
// events. A counter stays when its events are gone: numbers never go back.
const (
	topicTableSQL = `CREATE TABLE IF NOT EXISTS kv_topic (
  topic VARBINARY(255) NOT NULL PRIMARY KEY,
  seq   BIGINT NOT NULL
) ENGINE=InnoDB`

	feedTableSQL = `CREATE TABLE IF NOT EXISTS kv_feed (
  topic      VARBINARY(255) NOT NULL,
  seq        BIGINT NOT NULL,
  payload    MEDIUMBLOB NOT NULL,
  created_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NOT NULL,
  PRIMARY KEY (topic, seq),
  KEY idx_kv_feed_expires_at (expires_at)
) ENGINE=InnoDB`
)

// defaultFeedPoll is how often a follower looks for events. MariaDB tells nobody of a commit, so looking
// is how events arrive.
const defaultFeedPoll = time.Second

// followBatch is how many events a follower reads at a time.
const followBatch = 256

// WithFeedPoll sets how often a follower of the feed looks for events, a second without it. It is how
// long an event takes to arrive at most.
func WithFeedPoll(every time.Duration) Option {
	return func(s *store) { s.poll = every }
}

// Tx implements kv.Transactor. The transaction is at the level REPEATABLE READ, where a locking read of a
// record that is not there locks its place: of two transactions that then write it, the database ends one
// as a deadlock, which is run again and finds the other's record. Across the writing nodes of a cluster
// only what a transaction wrote is checked against the others; a record it only read is not.
func (s *store) Tx(ctx context.Context, fn func(tx kv.Tx) error) error {
	err := s.inTxAt(ctx, sql.LevelRepeatableRead, func(tx tabledTx) error {
		return fn(&mariaTx{s: s, tx: tx})
	})
	if err != nil && !errors.Is(err, kv.ErrTxTooLarge) && !errors.Is(err, kv.ErrEvent) && !errors.Is(err, kv.ErrEphemeralEvent) && isDatabase(err) {
		return fmt.Errorf("kv/mariadb: transaction: %w", err)
	}
	return err
}

type mariaTx struct {
	s   *store
	tx  tabledTx
	ops kv.TxOps
}

func (t *mariaTx) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if err := t.ops.Count(); err != nil {
		return nil, false, err
	}
	if len(key) > MaxKeyLen {
		return nil, false, nil
	}
	var v []byte
	err := t.tx.QueryRowContext(ctx, "SELECT value FROM @kv WHERE `key`=? AND "+live+" FOR UPDATE", []byte(key)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return nonNil(v), true, nil
}

func (t *mariaTx) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	return t.s.upsert(ctx, t.tx, kv.Entry{Key: key, Value: value, TTL: ttl})
}

func (t *mariaTx) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := t.ops.Count(); err != nil {
		return false, err
	}
	if err := checkKey(key); err != nil {
		return false, err
	}
	mark, err := t.s.markOf(key, value)
	if err != nil {
		return false, err
	}
	res, err := t.tx.ExecContext(ctx, setIfAbsentSQL, []byte(key), nonNil(value), ttlMicroseconds(ttl), mark)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (t *mariaTx) Take(ctx context.Context, key string) ([]byte, bool, error) {
	if err := t.ops.Count(); err != nil {
		return nil, false, err
	}
	if len(key) > MaxKeyLen {
		return nil, false, nil
	}
	var v []byte
	err := t.tx.QueryRowContext(ctx, "DELETE FROM @kv WHERE `key`=? AND "+live+" RETURNING value", []byte(key)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return nonNil(v), true, nil
}

func (t *mariaTx) Delete(ctx context.Context, key string) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	if len(key) > MaxKeyLen {
		return nil
	}
	_, err := t.tx.ExecContext(ctx, "DELETE FROM @kv WHERE `key`=?", []byte(key))
	return err
}

func (t *mariaTx) Publish(ctx context.Context, topic string, event []byte, retention time.Duration) error {
	if err := t.ops.Count(); err != nil {
		return err
	}
	if t.s.ephemeral {
		return kv.ErrEphemeralEvent
	}
	_, err := publish(ctx, t.tx.Tx, topic, event, retention)
	return err
}

// publish numbers the event by the topic's counter and writes it, in the caller's transaction. The update
// of the counter locks its row until the commit, so on one node the publishers of one topic commit one
// after another; across the writing nodes of a cluster two that raise the same counter cannot both commit,
// and the one that is refused runs again. Either way the numbers have no gap and are in the order of the
// commits on every node, and a follower that reads the events after its cursor steps over none. An
// AUTO_INCREMENT column would not do: its values are neither.
func publish(ctx context.Context, tx *sql.Tx, topic string, event []byte, retention time.Duration) (kv.Cursor, error) {
	if err := kv.CheckEvent(topic, event, retention); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO kv_topic(topic, seq) VALUES(?, 1) ON DUPLICATE KEY UPDATE seq = seq + 1`, []byte(topic)); err != nil {
		return 0, err
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT seq FROM kv_topic WHERE topic=?`, []byte(topic)).Scan(&seq); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kv_feed(topic, seq, payload, created_at, expires_at)
		VALUES(?, ?, ?, NOW(6), NOW(6) + INTERVAL ? MICROSECOND)`,
		[]byte(topic), seq, nonNil(event), retention.Microseconds()); err != nil {
		// The number is taken: a publisher on another node of the cluster raised the counter to the same
		// number and committed first (seen with publishers on three nodes at once). This transaction
		// could not commit any more; it is told so here, before its commit would be, and runs again.
		var my *mysql.MySQLError
		if errors.As(err, &my) && my.Number == errDuplicateEntry {
			return 0, &lostError{err}
		}
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
	if s.ephemeral {
		return 0, kv.ErrEphemeralEvent
	}
	var cursor kv.Cursor
	err := s.inTx(ctx, func(tx tabledTx) error {
		var err error
		cursor, err = publish(ctx, tx.Tx, topic, event, retention)
		return err
	})
	if err != nil && !errors.Is(err, kv.ErrEvent) {
		return 0, fmt.Errorf("kv/mariadb: publish: %w", err)
	}
	return cursor, err
}

// Latest implements kv.Feed.
func (s *store) Latest(ctx context.Context, topic string) (kv.Cursor, error) {
	if s.ephemeral {
		return 0, kv.ErrEphemeralEvent
	}
	var seq int64
	err := again(ctx, func() error {
		return s.db.QueryRowContext(ctx, `SELECT seq FROM kv_topic WHERE topic=?`, []byte(topic)).Scan(&seq)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("kv/mariadb: latest: %w", err)
	}
	return cursorOf(seq), nil
}

// Follow implements kv.Feed: the follower looks for events every [WithFeedPoll].
func (s *store) Follow(ctx context.Context, topic string, from kv.Cursor) (<-chan kv.Event, error) {
	if s.ephemeral {
		return nil, kv.ErrEphemeralEvent
	}
	if topic == "" || len(topic) > kv.MaxTopicLen {
		return nil, kv.ErrEvent
	}
	out := make(chan kv.Event, 16)
	go func() {
		defer close(out)
		cursor := from
		for {
			events, err := s.eventsAfter(ctx, topic, cursor)
			if err != nil {
				if ctx.Err() == nil {
					slog.WarnContext(ctx, "kv/mariadb: the feed's follower ends", "error", err)
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
			if len(events) == followBatch {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.poll):
			}
		}
	}()
	return out, nil
}

func (s *store) eventsAfter(ctx context.Context, topic string, cursor kv.Cursor) ([]kv.Event, error) {
	var events []kv.Event
	err := again(ctx, func() error {
		events = events[:0]
		rows, err := s.db.QueryContext(ctx, `SELECT seq, payload, created_at FROM kv_feed
			WHERE topic=? AND seq > ? AND expires_at > NOW(6) ORDER BY seq LIMIT ?`,
			[]byte(topic), numberOf(cursor), followBatch)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var seq int64
			var e kv.Event
			if err := rows.Scan(&seq, &e.Payload, &e.At); err != nil {
				return err
			}
			e.Cursor, e.Payload = cursorOf(seq), nonNil(e.Payload)
			events = append(events, e)
		}
		return rows.Err()
	})
	return events, err
}
