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

// Package mariadb is the MariaDB backend for the kv.Store interface, a module of its own so that only a
// program that wires MariaDB has its driver in the module graph. It holds what kv/postgres holds, in a
// database of the other kind; a host picks one by the scheme of its DSN.
//
// It is written for every way MariaDB is run: one node, a primary with replicas, and a Galera cluster with
// one or several writing nodes. So nothing in it rests on what holds on one node only: no GET_LOCK, no
// order of AUTO_INCREMENT values. A statement that loses against another writer (a deadlock, or in a
// cluster a certification failure at commit) is repeated a bounded number of times, and every operation is
// written so that repeating it is right. In a cluster a read waits until the node has applied what the
// cluster committed ([WithSyncWait]), so that a value written through one node is found through another.
package mariadb

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/gematik/zero-lab/go/kv"
)

// MaxKeyLen is the longest key the store takes, in bytes: keys are the primary key of the table, and the
// database bounds what it indexes. A longer key is refused, never cut short: two keys that differ only
// after the bound would otherwise be one record.
const MaxKeyLen = 1024

// maxMarkLen is the longest mark of a record.
const maxMarkLen = 255

// ErrKeyTooLong is a key of more than [MaxKeyLen] bytes.
var ErrKeyTooLong = errors.New("kv/mariadb: the key is longer than 1024 bytes")

// SyncWait says whether a session waits, before a statement, until its node has applied what the cluster
// committed (wsrep_sync_wait). Without it a value set through one node of a Galera cluster may not be found
// through another a moment later.
type SyncWait int

const (
	// SyncWaitAuto waits when the server says it is part of a cluster (wsrep_on), and not otherwise.
	SyncWaitAuto SyncWait = iota
	// SyncWaitAlways waits whatever the server says.
	SyncWaitAlways
	// SyncWaitNever does not wait: for a host that knows its cluster has one writing node and reads there,
	// or accepts the window.
	SyncWaitNever
)

// syncWaitMask is wsrep_sync_wait for reads, updates and deletes, and inserts: every statement of this
// package decides on what is in the table.
const syncWaitMask = "7"

type store struct {
	db       *sql.DB
	mark     func(key string, value []byte) string
	migrate  bool
	syncWait SyncWait
	tls      *tls.Config
	// poll is how often a follower of the feed looks (feed.go).
	poll time.Duration
}

// Option adjusts the store [Open] returns.
type Option func(*store)

// WithMark makes the store a kv.Marker: beside each record it keeps what mark says of the record's key and
// value, kv.SealedMarker for a store that is sealed.
func WithMark(mark func(key string, value []byte) string) Option {
	return func(s *store) { s.mark = mark }
}

// WithMigrate makes [Open] apply the schema steps the database lacks before it checks the version, as
// [Migrate] does, but never a contract step. It is for a deployment without a migration job; the server's
// role then needs the right to change the schema, which the default exists to take away.
func WithMigrate() Option {
	return func(s *store) { s.migrate = true }
}

// WithSyncWait sets whether sessions wait for the cluster's commits; [SyncWaitAuto] without it.
func WithSyncWait(mode SyncWait) Option {
	return func(s *store) { s.syncWait = mode }
}

// WithTLS sets the TLS configuration of the connections, for a server whose certificate the system's roots
// do not vouch for. Without it the server's certificate is verified against the system's roots and the
// host of the DSN, unless the DSN says tls=false.
func WithTLS(config *tls.Config) Option {
	return func(s *store) { s.tls = config }
}

// config makes the driver's configuration from a DSN of the form
//
//	mariadb://host:port/database
//
// with the port 3306 when none is given, and from the user and the password, which are not part of it: a
// DSN is an address, written into configuration and logs, and a password in a URL has to be escaped to be
// read as it is meant. A DSN that carries a user or a password is refused. The connection is TLS unless the
// DSN says ?tls=false, the operator's statement that the deployment protects it. Every session runs in UTC
// and in strict mode: a value that does not fit a column is an error, never cut short.
func config(dsn, user, password string, custom *tls.Config) (*mysql.Config, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		// What is not a URL may still hold a secret someone put there: the parse error, which quotes it,
		// is not passed on.
		return nil, errors.New("kv/mariadb: the DSN is not a URL")
	}
	if u.User != nil {
		return nil, errors.New("kv/mariadb: the DSN carries a user or a password: they are given beside it")
	}
	if u.Scheme != "mariadb" && u.Scheme != "mysql" {
		return nil, errors.New("kv/mariadb: the DSN's scheme is not mariadb")
	}
	database := strings.TrimPrefix(u.Path, "/")
	if u.Hostname() == "" || database == "" || strings.Contains(database, "/") {
		return nil, errors.New("kv/mariadb: the DSN names no host or no database")
	}
	cfg := mysql.NewConfig()
	cfg.User = user
	cfg.Passwd = password
	cfg.Net = "tcp"
	port := u.Port()
	if port == "" {
		port = "3306"
	}
	cfg.Addr = net.JoinHostPort(u.Hostname(), port)
	cfg.DBName = database
	// Times are read as times, in UTC, which is what every session writes them in.
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{
		"time_zone": "'+00:00'",
		"sql_mode":  "'STRICT_ALL_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'",
	}
	query := u.Query()
	for name := range query {
		if name != "tls" {
			return nil, fmt.Errorf("kv/mariadb: the DSN has a parameter this backend does not know: %s", name)
		}
	}
	switch query.Get("tls") {
	case "", "true":
		cfg.TLS = custom
		if cfg.TLS == nil {
			cfg.TLS = &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
		}
	case "false":
		if custom != nil {
			return nil, errors.New("kv/mariadb: a TLS configuration beside tls=false in the DSN")
		}
	default:
		return nil, errors.New("kv/mariadb: tls in the DSN is true or false")
	}
	return cfg, nil
}

func connect(cfg *mysql.Config) (*sql.DB, error) {
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(connector), nil
}

// OpenDB opens connections to the database of dsn as this package's sessions are: for [Migrate], which
// takes a user that may change the schema.
func OpenDB(dsn, user, password string, opts ...Option) (*sql.DB, error) {
	s := &store{}
	for _, opt := range opts {
		opt(s)
	}
	cfg, err := config(dsn, user, password, s.tls)
	if err != nil {
		return nil, err
	}
	db, err := connect(cfg)
	if err != nil {
		return nil, fmt.Errorf("kv/mariadb: open: %w", err)
	}
	return db, nil
}

// Open connects to MariaDB at dsn as user, checks the schema and returns a kv.Store. The DSN is the address
// alone (mariadb://host:port/database); user and password are given beside it, as a deployment has them: an
// address in its configuration and the two in a secret. It runs no DDL: it refuses a
// database that lacks a step this release needs, or on which a contract step it does not know was applied
// (an error that is a schema.ErrVersion and names the versions). The steps are applied by [Migrate], or by
// Open itself with [WithMigrate]. The user needs SELECT, INSERT, UPDATE and DELETE on the tables kv, kv_feed
// and kv_topic and SELECT on kv_schema, and with [WithMigrate] CREATE and ALTER on the database.
func Open(ctx context.Context, dsn, user, password string, opts ...Option) (kv.Store, error) {
	return open(ctx, dsn, user, password, steps, opts...)
}

func open(ctx context.Context, dsn, user, password string, steps []step, opts ...Option) (kv.Store, error) {
	s := &store{poll: defaultFeedPoll}
	for _, opt := range opts {
		opt(s)
	}
	if s.poll <= 0 {
		return nil, errors.New("kv/mariadb: the feed's followers look every positive duration")
	}
	cfg, err := config(dsn, user, password, s.tls)
	if err != nil {
		return nil, err
	}
	db, err := connect(cfg)
	if err != nil {
		return nil, fmt.Errorf("kv/mariadb: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/mariadb: ping: %w", err)
	}
	wait := s.syncWait == SyncWaitAlways
	if s.syncWait == SyncWaitAuto {
		if err := db.QueryRowContext(ctx, `SELECT @@wsrep_on`).Scan(&wait); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("kv/mariadb: asking whether the server is in a cluster: %w", err)
		}
	}
	if wait {
		// A session variable: every connection of the pool has to set it, so the pool is made anew.
		_ = db.Close()
		cfg.Params["wsrep_sync_wait"] = syncWaitMask
		if db, err = connect(cfg); err != nil {
			return nil, fmt.Errorf("kv/mariadb: open: %w", err)
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("kv/mariadb: ping: %w", err)
		}
	}
	s.db = db
	if s.migrate {
		if _, err := migrate(ctx, db, steps, migrateOptions{}); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("kv/mariadb: schema: %w", err)
		}
	}
	if err := checkSchema(ctx, db, steps); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/mariadb: schema: %w", err)
	}
	return s, nil
}

// The MariaDB errors of a statement that lost against another writer and is right to repeat: a deadlock,
// which is also what a Galera node reports for a transaction that failed certification; a lock wait that
// timed out; and an interrupted query, which is what a node reports for a statement it broke off to let a
// schema change of the cluster through first (seen with migrators on different nodes at once). Each left
// nothing behind.
const (
	errLockWaitTimeout  = 1205
	errLockDeadlock     = 1213
	errQueryInterrupted = 1317
	errNoSuchTable      = 1146
	errDuplicateEntry   = 1062
)

// lostError marks an error that is not one of those above by its number but means the same where it
// arose: the transaction lost against another and is right to run again.
type lostError struct{ err error }

func (e *lostError) Error() string { return e.err.Error() }
func (e *lostError) Unwrap() error { return e.err }

// attempts bounds how often an operation is tried, and maxPause the pause between two tries. In a cluster
// with several writing nodes every writer of one row but one loses at each commit, so many writers of one
// row (the publishers of one topic) each lose many times before they have all committed: with fewer tries
// some of 16 publishers through three nodes gave up.
const (
	attempts = 32
	maxPause = 64
)

// isDatabase reports whether an error is one the database returned.
func isDatabase(err error) bool {
	var my *mysql.MySQLError
	return errors.As(err, &my)
}

func lost(err error) bool {
	var marked *lostError
	if errors.As(err, &marked) {
		return true
	}
	var my *mysql.MySQLError
	return errors.As(err, &my) &&
		(my.Number == errLockDeadlock || my.Number == errLockWaitTimeout || my.Number == errQueryInterrupted)
}

// again runs do until it does not lose against another writer, at most attempts times, with a short and
// uneven pause so that the writers it lost against do not meet it again at once.
func again(ctx context.Context, do func() error) error {
	var err error
	for try := range attempts {
		if err = do(); !lost(err) {
			return err
		}
		pause := time.Duration(1+jitter(min(4*(try+1), maxPause))) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
	}
	return err
}

// jitter is a number below n, uneven enough to keep writers apart.
func jitter(n int) int {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return int(b[0]) % n
}

// The errors of this store name the operation and never the key: a key names what it holds, and errors
// reach logs.

func checkKey(key string) error {
	if len(key) > MaxKeyLen {
		return ErrKeyTooLong
	}
	return nil
}

// markOf is the statement parameter for the mark of a value: NULL without one.
func (s *store) markOf(key string, value []byte) (any, error) {
	if s.mark == nil {
		return nil, nil
	}
	mark := s.mark(key, value)
	if len(mark) > maxMarkLen {
		return nil, errors.New("kv/mariadb: the mark of a record is longer than 255 bytes")
	}
	if mark == "" {
		return nil, nil
	}
	return []byte(mark), nil
}

// ttlMicroseconds is the statement parameter for an expiry of NOW(6) + TTL: the expiry comes from the
// database clock, the one every read compares against, so skew between the replicas and the database cannot
// stretch or cut short a TTL. NULL makes the sum NULL, which is no expiry.
func ttlMicroseconds(ttl time.Duration) any {
	if ttl <= 0 {
		return nil
	}
	return ttl.Microseconds()
}

// live is the condition of a record that has not expired.
const live = `(expires_at IS NULL OR expires_at > NOW(6))`

// expired is the condition of a record whose time is over.
const expired = `(expires_at IS NOT NULL AND expires_at <= NOW(6))`

// A record's mark counts only while marked_at is created_at: both are the NOW(6) of the statement that
// wrote the record, so a writer of a release without marks, which sets created_at alone, leaves a mark
// that no longer counts (server rule 22).
const markedOther = `(NOT (mark <=> ?) OR NOT (marked_at <=> created_at))`

const upsertSQL = "INSERT INTO kv(`key`, value, created_at, expires_at, mark, marked_at)" + `
	VALUES(?, ?, NOW(6), NOW(6) + INTERVAL ? MICROSECOND, ?, NOW(6))
	ON DUPLICATE KEY UPDATE value=VALUES(value), created_at=VALUES(created_at), expires_at=VALUES(expires_at),
	  mark=VALUES(mark), marked_at=VALUES(marked_at)`

// setIfAbsentSQL is one statement, so two replicas cannot both win. MariaDB assigns the columns of ON
// DUPLICATE KEY UPDATE in order and each assignment sees the ones before it: expires_at, which the
// condition reads, is assigned last.
const setIfAbsentSQL = "INSERT INTO kv(`key`, value, created_at, expires_at, mark, marked_at)" + `
	VALUES(?, ?, NOW(6), NOW(6) + INTERVAL ? MICROSECOND, ?, NOW(6))
	ON DUPLICATE KEY UPDATE
	  value      = IF(` + expired + `, VALUES(value), value),
	  mark       = IF(` + expired + `, VALUES(mark), mark),
	  marked_at  = IF(` + expired + `, VALUES(marked_at), marked_at),
	  created_at = IF(` + expired + `, VALUES(created_at), created_at),
	  expires_at = IF(` + expired + `, VALUES(expires_at), expires_at)`

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *store) upsert(ctx context.Context, e execer, ent kv.Entry) error {
	if err := checkKey(ent.Key); err != nil {
		return err
	}
	mark, err := s.markOf(ent.Key, ent.Value)
	if err != nil {
		return err
	}
	_, err = e.ExecContext(ctx, upsertSQL, []byte(ent.Key), nonNil(ent.Value), ttlMicroseconds(ent.TTL), mark)
	return err
}

// nonNil is value as a parameter: a nil slice would be sent as NULL, which the column does not take.
func nonNil(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func (s *store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if len(key) > MaxKeyLen {
		return nil, false, nil
	}
	var v []byte
	err := again(ctx, func() error {
		return s.db.QueryRowContext(ctx, "SELECT value FROM kv WHERE `key`=? AND "+live, []byte(key)).Scan(&v)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/mariadb: get: %w", err)
	}
	return nonNil(v), true, nil
}

func (s *store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	err := again(ctx, func() error { return s.upsert(ctx, s.db, kv.Entry{Key: key, Value: value, TTL: ttl}) })
	if err != nil {
		return fmt.Errorf("kv/mariadb: set: %w", err)
	}
	return nil
}

// SetIfAbsent reports what the statement did by the rows it counts: one for a record that was not there,
// two for an expired one it replaced, none for a standing one it left.
func (s *store) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := checkKey(key); err != nil {
		return false, fmt.Errorf("kv/mariadb: set if absent: %w", err)
	}
	mark, err := s.markOf(key, value)
	if err != nil {
		return false, err
	}
	var n int64
	err = again(ctx, func() error {
		res, err := s.db.ExecContext(ctx, setIfAbsentSQL, []byte(key), nonNil(value), ttlMicroseconds(ttl), mark)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return false, fmt.Errorf("kv/mariadb: set if absent: %w", err)
	}
	return n > 0, nil
}

// inTx runs do in one transaction and repeats the whole of it when it lost against another writer.
func (s *store) inTx(ctx context.Context, do func(tx *sql.Tx) error) error {
	return s.inTxAt(ctx, sql.LevelReadCommitted, do)
}

func (s *store) inTxAt(ctx context.Context, level sql.IsolationLevel, do func(tx *sql.Tx) error) error {
	return again(ctx, func() error {
		tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: level})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := do(tx); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// Swap reads the record under a lock and writes it in the same transaction, so of two replicas that swap
// the same value the second finds the first one's. It is two statements because the count of an UPDATE
// says how many rows changed, not how many matched.
func (s *store) Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	if len(key) > MaxKeyLen {
		return false, nil
	}
	mark, err := s.markOf(key, value)
	if err != nil {
		return false, err
	}
	var swapped bool
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		swapped = false
		var one int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM kv WHERE `key`=? AND value=? AND "+live+" FOR UPDATE",
			[]byte(key), nonNil(old)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE kv SET value=?, created_at=NOW(6), "+
			"expires_at=NOW(6) + INTERVAL ? MICROSECOND, mark=?, marked_at=NOW(6) WHERE `key`=?",
			nonNil(value), ttlMicroseconds(ttl), mark, []byte(key)); err != nil {
			return err
		}
		swapped = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("kv/mariadb: swap: %w", err)
	}
	return swapped, nil
}

func (s *store) SetMany(ctx context.Context, entries ...kv.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		for _, e := range entries {
			if err := s.upsert(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("kv/mariadb: set many: %w", err)
	}
	return nil
}

func (s *store) Take(ctx context.Context, key string) ([]byte, bool, error) {
	if len(key) > MaxKeyLen {
		return nil, false, nil
	}
	var v []byte
	err := again(ctx, func() error {
		return s.db.QueryRowContext(ctx, "DELETE FROM kv WHERE `key`=? AND "+live+" RETURNING value", []byte(key)).Scan(&v)
	})
	if errors.Is(err, sql.ErrNoRows) {
		// Absent or expired: an expired row is dropped so that it does not linger.
		_ = again(ctx, func() error {
			_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE `key`=? AND "+expired, []byte(key))
			return err
		})
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/mariadb: take: %w", err)
	}
	return nonNil(v), true, nil
}

func (s *store) Delete(ctx context.Context, key string) error {
	if len(key) > MaxKeyLen {
		return nil
	}
	err := again(ctx, func() error {
		_, err := s.db.ExecContext(ctx, "DELETE FROM kv WHERE `key`=?", []byte(key))
		return err
	})
	if err != nil {
		return fmt.Errorf("kv/mariadb: delete: %w", err)
	}
	return nil
}

func (s *store) keys(ctx context.Context, op, query string, args ...any) ([]string, error) {
	var out []string
	err := again(ctx, func() error {
		out = out[:0]
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k []byte
			if err := rows.Scan(&k); err != nil {
				return err
			}
			out = append(out, string(k))
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("kv/mariadb: %s: %w", op, err)
	}
	return out, nil
}

func (s *store) Keys(ctx context.Context, prefix string) ([]string, error) {
	return s.keys(ctx, "keys",
		"SELECT `key` FROM kv WHERE "+live+" AND `key` LIKE ? ESCAPE '!' ORDER BY `key`", likePrefix(prefix))
}

func (s *store) Cleanup(ctx context.Context) (int, error) {
	var n int64
	err := again(ctx, func() error {
		res, err := s.db.ExecContext(ctx, `DELETE FROM kv WHERE `+expired)
		if err != nil {
			return err
		}
		if n, err = res.RowsAffected(); err != nil {
			return err
		}
		// The events of the feed whose retention is over go too; they are not counted.
		_, err = s.db.ExecContext(ctx, `DELETE FROM kv_feed WHERE expires_at <= NOW(6)`)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("kv/mariadb: cleanup: %w", err)
	}
	return int(n), nil
}

func (s *store) Close() error { return s.db.Close() }

// MarkedOther implements kv.Marker.
func (s *store) MarkedOther(ctx context.Context, prefix, mark, after string, limit int) ([]string, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	return s.keys(ctx, "marked other",
		"SELECT `key` FROM kv WHERE "+live+" AND `key` LIKE ? ESCAPE '!' AND "+markedOther+
			" AND `key` > ? ORDER BY `key` LIMIT ?", likePrefix(prefix), []byte(mark), []byte(after), limit)
}

// CountMarkedOther implements kv.Marker.
func (s *store) CountMarkedOther(ctx context.Context, prefix, mark string) (int, error) {
	if s.mark == nil {
		return 0, kv.ErrNotMarker
	}
	var n int
	err := again(ctx, func() error {
		return s.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM kv WHERE "+live+" AND `key` LIKE ? ESCAPE '!' AND "+markedOther,
			likePrefix(prefix), []byte(mark)).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("kv/mariadb: count marked other: %w", err)
	}
	return n, nil
}

// Marks implements kv.Marker.
func (s *store) Marks(ctx context.Context, prefix string) (map[string]int, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	marks := map[string]int{}
	err := again(ctx, func() error {
		clear(marks)
		rows, err := s.db.QueryContext(ctx,
			"SELECT CASE WHEN NOT (marked_at <=> created_at) THEN '' ELSE COALESCE(mark, '') END AS m, COUNT(*)"+
				" FROM kv WHERE "+live+" AND `key` LIKE ? ESCAPE '!' GROUP BY m", likePrefix(prefix))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var mark []byte
			var n int
			if err := rows.Scan(&mark, &n); err != nil {
				return err
			}
			marks[string(mark)] = n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("kv/mariadb: marks: %w", err)
	}
	return marks, nil
}

// likePrefix escapes the wildcards of LIKE in a literal prefix and appends '%'. The escape character is
// named in every statement, so that the session's sql_mode (NO_BACKSLASH_ESCAPES) does not decide it.
func likePrefix(prefix string) []byte {
	return []byte(strings.NewReplacer(`!`, `!!`, `%`, `!%`, `_`, `!_`).Replace(prefix) + "%")
}
