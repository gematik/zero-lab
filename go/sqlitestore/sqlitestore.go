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

// Package sqlitestore is the SQLite backend of spec/store (section H): state.db and cache.db,
// shared with ti and the other tools of a profile. It has every capability of STORE-018.
// The driver is github.com/ncruces/go-sqlite3, SQLite compiled to Go without cgo; it is a
// module of its own so that go/store stays free of dependencies.
package sqlitestore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	// registers the database/sql driver "sqlite3"
	_ "github.com/ncruces/go-sqlite3/driver"

	"github.com/gematik/zero-lab/go/store"
)

// schema is spec/store/schema.sql; TestSchemaIsTheSpecification keeps the copy current.
//
//go:embed schema.sql
var schema string

// applicationID is "ZLST" (STORE-070).
const applicationID = 0x5A4C5354

// DB says which of a profile's databases a file is, for the durability it needs
// (STORE-072).
type DB int

const (
	// State is state.db: records that must survive.
	State DB = iota
	// Cache is cache.db: records that may be lost.
	Cache
)

// Backend keeps records in one database file. Its connections are pooled; other
// processes and tools coordinate through SQLite's locks.
type Backend struct {
	db *sql.DB
	// pinned keeps the shared-memory file open, and so in place with the mode
	// createPrivate gave it, while the backend is open.
	pinned *sql.Conn
}

// Open opens the database at path, creating it with the schema if it does not exist, and
// checks its format level (STORE-070, STORE-071, STORE-100, STORE-101): malformed for a
// file that is not a store database, unsupported_version for one a newer, incompatible
// tool wrote, busy if another process holds it past the busy timeout.
func Open(ctx context.Context, path string, kind DB) (*Backend, error) {
	if err := createPrivate(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", dsn(path, kind))
	if err != nil {
		return nil, store.BackendError("open "+path, err)
	}
	b := &Backend{db: db}
	if b.pinned, err = db.Conn(ctx); err != nil {
		_ = db.Close()
		return nil, sqlErr(err)
	}
	if err := b.init(ctx); err != nil {
		_ = b.Close()
		return nil, err
	}
	return b, nil
}

// Close closes the database.
func (b *Backend) Close() error {
	if b.pinned != nil {
		_ = b.pinned.Close()
	}
	return b.db.Close()
}

// dsn gives every pooled connection the settings of STORE-072 and makes transactions
// begin with BEGIN IMMEDIATE (STORE-073).
func dsn(path string, kind DB) string {
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive letter
	}
	q := url.Values{}
	// the journal and WAL get the database's mode (STORE-077)
	q.Set("modeof", path)
	q.Set("_txlock", "immediate")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	if kind == State {
		q.Add("_pragma", "synchronous(FULL)")
		q.Add("_pragma", "secure_delete(1)")
	} else {
		q.Add("_pragma", "synchronous(NORMAL)")
	}
	return (&url.URL{Scheme: "file", OmitHost: true, Path: p, RawQuery: q.Encode()}).String()
}

// sqliteHeader starts every SQLite database file.
const sqliteHeader = "SQLite format 3\x00"

// createPrivate makes the database and its shared-memory file with mode 0600 before
// SQLite opens them (STORE-077): the driver creates the shared-memory file with the
// process's default mode, unlike SQLite's own VFS, and the WAL follows "modeof". It also
// refuses a file that is not a database: the driver reports that only as text.
func createPrivate(path string) error {
	for _, p := range []string{path, path + "-shm"} {
		f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return store.BackendError("create "+p, err)
		}
		_ = f.Close()
	}
	f, err := os.Open(path)
	if err != nil {
		return store.BackendError("open "+path, err)
	}
	defer f.Close()
	head := make([]byte, len(sqliteHeader))
	n, err := io.ReadFull(f, head)
	switch {
	case n == 0 && errors.Is(err, io.EOF):
		return nil // new
	case err != nil && !errors.Is(err, io.ErrUnexpectedEOF):
		return store.BackendError("read "+path, err)
	case string(head[:n]) != sqliteHeader:
		return &store.Error{Code: store.CodeMalformed, What: "database"}
	}
	return nil
}

// busyTimeout is STORE-072's minimum, also for creating a database.
const busyTimeout = 5 * time.Second

// init creates the schema in a new database, or checks an existing one. Two processes
// may create the same database at once: the transaction looks again after taking the
// write lock, and the second finds the tables the first created. Switching a new
// database to WAL can fail as busy at once rather than wait, when two connections each
// hold a read lock and need the write lock; creation is then tried again until the busy
// timeout.
func (b *Backend) init(ctx context.Context) error {
	deadline := time.Now().Add(busyTimeout)
	for {
		err := b.create(ctx)
		if !errors.Is(err, store.ErrBusy) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (b *Backend) create(ctx context.Context) error {
	conn, err := b.db.Conn(ctx)
	if err != nil {
		return sqlErr(err)
	}
	defer conn.Close()
	empty, err := isEmpty(ctx, conn)
	if err != nil {
		return err
	}
	if empty {
		pragmas, body := schemaParts()
		if _, err := conn.ExecContext(ctx, pragmas); err != nil {
			return sqlErr(err)
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return sqlErr(err)
		}
		defer func() { _ = tx.Rollback() }()
		if empty, err = isEmpty(ctx, tx); err != nil {
			return err
		}
		if empty {
			if _, err := tx.ExecContext(ctx, body); err != nil {
				return sqlErr(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return sqlErr(err)
		}
	}
	if err := checkLevel(ctx, conn); err != nil {
		return err
	}
	// A database left in another journal mode is still readable; WAL is what the other
	// tools expect (STORE-071).
	var mode string
	return sqlErr(conn.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&mode))
}

// schemaParts splits schema.sql where its transaction begins: the pragmas that must run
// outside a transaction, and the body inside one.
func schemaParts() (pragmas, body string) {
	pragmas, rest, ok := strings.Cut(schema, "BEGIN IMMEDIATE;")
	i := strings.LastIndex(rest, "COMMIT;")
	if !ok || i < 0 {
		panic("sqlite: schema.sql has no transaction")
	}
	return pragmas, rest[:i]
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func isEmpty(ctx context.Context, q querier) (bool, error) {
	var n int
	if err := q.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&n); err != nil {
		return false, sqlErr(err)
	}
	return n == 0, nil
}

// checkLevel applies STORE-070, STORE-101 and STORE-100.
func checkLevel(ctx context.Context, q querier) error {
	var id, userVersion int
	if err := q.QueryRowContext(ctx, "PRAGMA application_id").Scan(&id); err != nil {
		return sqlErr(err)
	}
	if id != applicationID {
		return &store.Error{Code: store.CodeMalformed, What: "database"}
	}
	if err := q.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil {
		return sqlErr(err)
	}
	meta := func(key string) (int, error) {
		var v int
		err := q.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, &store.Error{Code: store.CodeMalformed, What: "database meta"}
		}
		return v, sqlErr(err)
	}
	level, err := meta("level")
	if err != nil {
		return err
	}
	minCompatible, err := meta("min_compatible")
	if err != nil {
		return err
	}
	return store.CheckDatabaseLevel(store.MaxLevel, userVersion, level, minCompatible)
}

// Capabilities implements [store.Backend] (STORE-078).
func (*Backend) Capabilities() store.Capabilities {
	return store.Capabilities{AtomicTake: true, AtomicBatch: true, Indexed: true, MultiProcess: true}
}

func checkNS(ns string) error {
	if !store.ValidNamespace(ns) {
		return &store.Error{Code: store.CodeInvalidArgument, What: "namespace"}
	}
	return nil
}

// stamp is a time as the column holds it: NULL for no expiry. STORE-002 bounds times
// far below the range of an INTEGER.
func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func expiry(v sql.NullInt64) (time.Time, error) {
	if !v.Valid {
		return time.Time{}, nil
	}
	if v.Int64 <= 0 {
		return time.Time{}, &store.Error{Code: store.CodeMalformed, What: "expiry"}
	}
	return store.FromWire(uint64(v.Int64)), nil
}

type rowsQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func tags(ctx context.Context, q rowsQuerier, ns string, name store.Name) ([]store.Tag, error) {
	rows, err := q.QueryContext(ctx, "SELECT field, tag FROM tags WHERE ns = ? AND name = ?", ns, name[:])
	if err != nil {
		return nil, sqlErr(err)
	}
	defer rows.Close()
	var out []store.Tag
	for rows.Next() {
		var field string
		var tag []byte
		if err := rows.Scan(&field, &tag); err != nil {
			return nil, sqlErr(err)
		}
		if !store.ValidField(field) || len(tag) != 32 {
			return nil, &store.Error{Code: store.CodeMalformed, What: "tag"}
		}
		out = append(out, store.Tag{Field: field, Tag: [32]byte(tag)})
	}
	return out, sqlErr(rows.Err())
}

// Get implements [store.Backend].
func (b *Backend) Get(ctx context.Context, ns string, name store.Name, now time.Time) (store.StoredRecord, error) {
	if err := checkNS(ns); err != nil {
		return store.StoredRecord{}, err
	}
	var r store.StoredRecord
	var exp sql.NullInt64
	err := b.db.QueryRowContext(ctx,
		"SELECT value, expires_at FROM records WHERE ns = ? AND name = ? AND (expires_at IS NULL OR expires_at > ?)",
		ns, name[:], now.Unix()).Scan(&r.Value, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return store.StoredRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.StoredRecord{}, sqlErr(err)
	}
	if r.ExpiresAt, err = expiry(exp); err != nil {
		return store.StoredRecord{}, err
	}
	if r.Tags, err = tags(ctx, b.db, ns, name); err != nil {
		return store.StoredRecord{}, err
	}
	return r, nil
}

// inTx runs f in one BEGIN IMMEDIATE transaction and rolls it back if f fails.
func (b *Backend) inTx(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return sqlErr(err)
	}
	if err := f(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return sqlErr(tx.Commit())
}

func put(ctx context.Context, tx *sql.Tx, ns string, name store.Name, r *store.StoredRecord) error {
	// the cascade removes the old record's tags (STORE-011)
	if _, err := tx.ExecContext(ctx, "DELETE FROM records WHERE ns = ? AND name = ?", ns, name[:]); err != nil {
		return sqlErr(err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO records (ns, name, value, expires_at) VALUES (?, ?, ?, ?)",
		ns, name[:], nonNil(r.Value), stamp(r.ExpiresAt)); err != nil {
		return sqlErr(err)
	}
	for _, t := range r.Tags {
		if _, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO tags (ns, field, tag, name) VALUES (?, ?, ?, ?)",
			ns, t.Field, t.Tag[:], name[:]); err != nil {
			return sqlErr(err)
		}
	}
	return nil
}

// nonNil keeps an empty value a BLOB: a nil slice would bind as NULL.
func nonNil(v []byte) []byte {
	if v == nil {
		return []byte{}
	}
	return v
}

// Put implements [store.Backend].
func (b *Backend) Put(ctx context.Context, ns string, name store.Name, r store.StoredRecord) error {
	if err := checkNS(ns); err != nil {
		return err
	}
	if err := r.Check(); err != nil {
		return err
	}
	return b.inTx(ctx, func(tx *sql.Tx) error { return put(ctx, tx, ns, name, &r) })
}

// Take implements [store.Backend] with the one statement of STORE-074, which decides
// which taker wins.
func (b *Backend) Take(ctx context.Context, ns string, name store.Name, now time.Time) (store.StoredRecord, error) {
	if err := checkNS(ns); err != nil {
		return store.StoredRecord{}, err
	}
	var r store.StoredRecord
	err := b.inTx(ctx, func(tx *sql.Tx) error {
		// read under the write lock, before the cascade removes them
		var err error
		if r.Tags, err = tags(ctx, tx, ns, name); err != nil {
			return err
		}
		var exp sql.NullInt64
		err = tx.QueryRowContext(ctx,
			"DELETE FROM records WHERE ns = ? AND name = ? AND (expires_at IS NULL OR expires_at > ?) RETURNING value, expires_at",
			ns, name[:], now.Unix()).Scan(&r.Value, &exp)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return sqlErr(err)
		}
		r.ExpiresAt, err = expiry(exp)
		return err
	})
	if err != nil {
		return store.StoredRecord{}, err
	}
	return r, nil
}

func del(ctx context.Context, tx *sql.Tx, ns string, name store.Name) error {
	_, err := tx.ExecContext(ctx, "DELETE FROM records WHERE ns = ? AND name = ?", ns, name[:])
	return sqlErr(err)
}

// Delete implements [store.Backend].
func (b *Backend) Delete(ctx context.Context, ns string, name store.Name) error {
	if err := checkNS(ns); err != nil {
		return err
	}
	return b.inTx(ctx, func(tx *sql.Tx) error { return del(ctx, tx, ns, name) })
}

// Batch implements [store.Backend]: everything is checked first, then applied in one
// transaction (STORE-014).
func (b *Backend) Batch(ctx context.Context, ops []store.BatchOp) error {
	for _, op := range ops {
		if err := checkNS(op.NS); err != nil {
			return err
		}
		if op.Record != nil {
			if err := op.Record.Check(); err != nil {
				return err
			}
		}
	}
	return b.inTx(ctx, func(tx *sql.Tx) error {
		for _, op := range ops {
			var err error
			if op.Record != nil {
				err = put(ctx, tx, op.NS, op.Name, op.Record)
			} else {
				err = del(ctx, tx, op.NS, op.Name)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// querySQL is the query of STORE-015 and STORE-016. With filters it starts from the
// first filter's tag rows, ordered and paged by their name, so that SQLite stays on the
// tags table's key and the cost follows the matches rather than the namespace.
func querySQL(q *store.Query) (string, []any) {
	args := []any{q.NS, q.Now.Unix()}
	var text strings.Builder
	text.WriteString("SELECT r.name, r.value, r.expires_at FROM ")
	key := "r.name"
	filters := q.Filters
	if len(filters) > 0 {
		key = "t0.name"
		text.WriteString("tags t0 JOIN records r ON r.ns = t0.ns AND r.name = t0.name " +
			"WHERE t0.ns = ?1 AND t0.field = ?3 AND t0.tag = ?4 AND ")
		args = append(args, filters[0].Field, filters[0].Tag[:])
		filters = filters[1:]
	} else {
		text.WriteString("records r WHERE r.ns = ?1 AND ")
	}
	text.WriteString("(r.expires_at IS NULL OR r.expires_at > ?2)")
	for _, f := range filters {
		fmt.Fprintf(&text, " AND EXISTS (SELECT 1 FROM tags t WHERE t.ns = r.ns AND t.name = r.name AND t.field = ?%d AND t.tag = ?%d)",
			len(args)+1, len(args)+2)
		args = append(args, f.Field, f.Tag[:])
	}
	// a record that does not expire is later than any time (STORE-015)
	if !q.From.IsZero() {
		args = append(args, q.From.Unix())
		fmt.Fprintf(&text, " AND (r.expires_at IS NULL OR r.expires_at >= ?%d)", len(args))
	}
	if !q.To.IsZero() {
		args = append(args, q.To.Unix())
		fmt.Fprintf(&text, " AND r.expires_at IS NOT NULL AND r.expires_at < ?%d", len(args))
	}
	if q.Cursor != nil {
		args = append(args, q.Cursor[:])
		fmt.Fprintf(&text, " AND %s > ?%d", key, len(args))
	}
	args = append(args, q.Limit)
	fmt.Fprintf(&text, " ORDER BY %s LIMIT ?%d", key, len(args))
	return text.String(), args
}

// Query implements [store.Backend].
func (b *Backend) Query(ctx context.Context, q *store.Query) (store.Page, error) {
	if err := q.Check(); err != nil {
		return store.Page{}, err
	}
	text, args := querySQL(q)
	rows, err := b.db.QueryContext(ctx, text, args...)
	if err != nil {
		return store.Page{}, sqlErr(err)
	}
	var found []store.Entry
	for rows.Next() {
		var name, value []byte
		var exp sql.NullInt64
		if err := rows.Scan(&name, &value, &exp); err != nil {
			_ = rows.Close()
			return store.Page{}, sqlErr(err)
		}
		if len(name) != 32 {
			_ = rows.Close()
			return store.Page{}, &store.Error{Code: store.CodeMalformed, What: "name"}
		}
		e := store.Entry{Name: store.Name(name), Record: store.StoredRecord{Value: value}}
		if e.Record.ExpiresAt, err = expiry(exp); err != nil {
			_ = rows.Close()
			return store.Page{}, err
		}
		found = append(found, e)
	}
	if err := rows.Close(); err != nil {
		return store.Page{}, sqlErr(err)
	}
	if err := rows.Err(); err != nil {
		return store.Page{}, sqlErr(err)
	}
	for i := range found {
		if found[i].Record.Tags, err = tags(ctx, b.db, q.NS, found[i].Name); err != nil {
			return store.Page{}, err
		}
	}
	return store.NewPage(found, q.Limit), nil
}

// Cleanup implements [store.Backend].
func (b *Backend) Cleanup(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit < 1 {
		return 0, &store.Error{Code: store.CodeInvalidArgument, What: "limit"}
	}
	var removed int64
	err := b.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			"DELETE FROM records WHERE (ns, name) IN (SELECT ns, name FROM records WHERE expires_at IS NOT NULL AND expires_at <= ? LIMIT ?)",
			now.Unix(), limit)
		if err != nil {
			return sqlErr(err)
		}
		removed, err = res.RowsAffected()
		return sqlErr(err)
	})
	return int(removed), err
}

// sqlErr maps a lock held past the busy timeout to busy (STORE-073) and a file that is
// not a database to malformed; nil stays nil.
func sqlErr(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*store.Error](err); ok {
		return err
	}
	switch {
	case errors.Is(err, sqlite3.BUSY), errors.Is(err, sqlite3.LOCKED):
		return &store.Error{Code: store.CodeBusy, Err: err}
	case errors.Is(err, sqlite3.NOTADB), errors.Is(err, sqlite3.CORRUPT):
		return &store.Error{Code: store.CodeMalformed, What: "database", Err: err}
	}
	return store.BackendError("sqlite", err)
}
