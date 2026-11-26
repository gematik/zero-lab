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

package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/postgres"
)

// The tests of this file prove statements of the guide for hosts and of the doc comments that the other
// tests passed without: each of them fails when the code it guards is taken away.

// migrated is a database of its own with the schema of this release.
func migrated(t *testing.T) (dsn string, db *sql.DB) {
	t.Helper()
	dsn = freshDatabase(t)
	db = adminOf(t, dsn)
	if _, err := postgres.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return dsn, db
}

// Server rule 17, and the guide for hosts: the DSN is the address and nothing else. A parameter that
// sets something of the session, or names another host than the one of the address, is not part of an
// address: with synchronous_commit=off in it, the writes of the durable class would no longer wait for
// the flush.
func TestConfig_Rule17ADSNThatSetsTheSessionOrNamesAnotherHostIsRefused(t *testing.T) {
	for _, parameter := range []string{
		"synchronous_commit=off",
		"search_path=elsewhere",
		"default_transaction_read_only=on",
		"options=-c%20synchronous_commit%3Doff",
		"host=another.example",
		"port=6432",
		"no_such_parameter=1",
	} {
		if _, _, _, _, err := postgres.Config("postgres://db.example:5432/kv?"+parameter, "kv", ""); err == nil {
			t.Errorf("a DSN with %s is taken", parameter)
		}
	}
}

// Server rule 11: a write of the durable class waits for the flush, by every way of writing; a write of the
// ephemeral class waits by none. The database is asked: a trigger on each table notes the setting each
// statement that changes it runs under.
func TestPostgres_Rule11EveryWriteOfTheDurableClassWaitsForTheFlushAndNoneOfTheEphemeral(t *testing.T) {
	ctx := context.Background()
	dsn, db := migrated(t)
	if _, err := db.Exec(`
		CREATE TABLE commit_seen (tbl text, op text, setting text);
		CREATE FUNCTION note_commit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO commit_seen VALUES (TG_TABLE_NAME, TG_OP, current_setting('synchronous_commit'));
			RETURN NULL;
		END $$;
		CREATE TRIGGER note_commit AFTER INSERT OR UPDATE OR DELETE ON kv FOR EACH STATEMENT EXECUTE FUNCTION note_commit();
		CREATE TRIGGER note_commit AFTER INSERT OR UPDATE OR DELETE ON kv_cache FOR EACH STATEMENT EXECUTE FUNCTION note_commit();
	`); err != nil {
		t.Fatal(err)
	}
	for table, class := range map[string]struct {
		opts []postgres.Option
		want string
	}{
		"kv":       {nil, "on"},
		"kv_cache": {[]postgres.Option{postgres.WithEphemeral()}, "off"},
	} {
		s, err := openKV(ctx, dsn, class.opts...)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		writes := map[string]func() error{
			"Set": func() error { return s.Set(ctx, "set", []byte("v"), time.Minute) },
			"SetIfAbsent": func() error {
				_, err := s.SetIfAbsent(ctx, "set-if-absent", []byte("v"), time.Minute)
				return err
			},
			"SetMany": func() error { return s.SetMany(ctx, kv.Entry{Key: "many", Value: []byte("v")}) },
			"Swap": func() error {
				_, err := s.(kv.Swapper).Swap(ctx, "set", []byte("v"), []byte("w"), time.Minute)
				return err
			},
			"Take": func() error {
				_, _, err := s.Take(ctx, "set-if-absent")
				return err
			},
			"Delete": func() error { return s.Delete(ctx, "many") },
			"Tx": func() error {
				return s.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error { return tx.Set(ctx, "tx", []byte("v"), time.Minute) })
			},
		}
		for _, way := range []string{"Set", "SetIfAbsent", "SetMany", "Swap", "Take", "Delete", "Tx"} {
			if _, err := db.Exec(`DELETE FROM commit_seen`); err != nil {
				t.Fatal(err)
			}
			if err := writes[way](); err != nil {
				t.Fatalf("%s: %v", way, err)
			}
			var statements, other int
			if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE setting <> $2) FROM commit_seen WHERE tbl = $1`,
				table, class.want).Scan(&statements, &other); err != nil {
				t.Fatal(err)
			}
			if statements == 0 || other != 0 {
				t.Errorf("%s on %s: %d statements changed the table, %d of them not with synchronous_commit %s", way, table, statements, other, class.want)
			}
		}
	}
}

// Server rule 11, and the guide for hosts: the DSN is the address and nothing else, so an address that
// sets synchronous_commit cannot take the flush from the writes of the durable class. The store is either
// refused or writes durably as without the parameter.
func TestPostgres_Rule11AnAddressCannotTakeTheFlushFromTheDurableClass(t *testing.T) {
	ctx := context.Background()
	dsn, _ := migrated(t)
	address, user, password, opts, err := apart(dsn, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("synchronous_commit", "off")
	u.RawQuery = query.Encode()
	s, err := postgres.Open(ctx, u.String(), user, password, opts...)
	if err != nil {
		return
	}
	defer s.Close()
	for way, setting := range map[string]func(context.Context, kv.Store) (string, error){
		"a write": postgres.CommitOfWrites, "a transaction": postgres.CommitOfTx,
	} {
		if got, err := setting(ctx, s); err != nil || got != "on" {
			t.Errorf("%s of the durable class runs with synchronous_commit %q, set by the address: %v", way, got, err)
		}
	}
}

// A backlog of expired records is deleted in statements of at most a batch each, so that no statement
// holds the locks of all of it: the database is asked how many rows each deleting statement removed.
func TestPostgres_Task430NoStatementOfCleanupDeletesMoreThanABatch(t *testing.T) {
	ctx := context.Background()
	dsn, db := migrated(t)
	if _, err := db.Exec(`
		CREATE TABLE deleted_at_once (n integer);
		CREATE FUNCTION note_deleted() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO deleted_at_once SELECT count(*) FROM gone;
			RETURN NULL;
		END $$;
		CREATE TRIGGER note_deleted AFTER DELETE ON kv REFERENCING OLD TABLE AS gone FOR EACH STATEMENT EXECUTE FUNCTION note_deleted();
	`); err != nil {
		t.Fatal(err)
	}
	defer postgres.SetCleanupBatch(10)()
	expire(t, db, "gone:", 95)
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if removed, err := s.Cleanup(ctx); err != nil || removed != 95 {
		t.Fatalf("removed %d, err %v", removed, err)
	}
	var statements, most, sum int
	if err := db.QueryRow(`SELECT count(*), max(n), sum(n) FROM deleted_at_once WHERE n > 0`).Scan(&statements, &most, &sum); err != nil {
		t.Fatal(err)
	}
	if most > 10 || sum != 95 || statements != 10 {
		t.Errorf("%d statements deleted %d records, the largest %d at once: a batch is 10", statements, sum, most)
	}
}

// The guide for hosts: Cleanup removes expired records and events. A follower no longer gets an event
// whose retention is over, but only Cleanup takes it out of the table.
func TestPostgres_CleanupRemovesTheEventsWhoseRetentionIsOver(t *testing.T) {
	ctx := context.Background()
	dsn, db := migrated(t)
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	feed := s.(kv.Feed)
	for payload, retention := range map[string]time.Duration{"short": 200 * time.Millisecond, "long": time.Hour} {
		if _, err := feed.Publish(ctx, "kept", []byte(payload), retention); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	events := func() (n int, payload string) {
		t.Helper()
		if err := db.QueryRow(`SELECT count(*), coalesce(string_agg(convert_from(payload, 'UTF8'), ','), '') FROM kv_feed`).Scan(&n, &payload); err != nil {
			t.Fatal(err)
		}
		return n, payload
	}
	if n, _ := events(); n != 2 {
		t.Fatalf("%d events are in the table before Cleanup, of 2", n)
	}
	if _, err := s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if n, payload := events(); n != 1 || payload != "long" {
		t.Errorf("after Cleanup the table holds %d events: %s", n, payload)
	}
	if latest, err := feed.Latest(ctx, "kept"); err != nil || latest != 2 {
		t.Errorf("the topic's counter after Cleanup: %d, err %v", latest, err)
	}
}

// A notification can be lost while the follower's connection stands. The follower has taken an event, so
// it has looked and now waits; what is written then without a notification is found by nothing but the
// look it takes every so often.
func TestPostgres_Task432AnEventWrittenWhileTheFollowerWaitsUntoldArrivesByItsLook(t *testing.T) {
	ctx := context.Background()
	dsn, db := migrated(t)
	s, err := openKV(ctx, dsn, postgres.WithFeedPoll(300*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	follow, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := s.(kv.Feed).Follow(follow, "untold", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.(kv.Feed).Publish(ctx, "untold", []byte("told"), time.Minute); err != nil {
		t.Fatal(err)
	}
	take := func(number kv.Cursor, payload string) {
		t.Helper()
		select {
		case e := <-events:
			if e.Cursor != number || string(e.Payload) != payload {
				t.Fatalf("event %d, %q: want %d, %q", e.Cursor, e.Payload, number, payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("event %d did not arrive", number)
		}
	}
	take(1, "told")
	// Written as a publisher writes it, without the notification.
	if _, err := db.Exec(`UPDATE kv_topic SET seq = 2 WHERE topic = 'untold';
		INSERT INTO kv_feed(topic, seq, payload, expires_at) VALUES('untold', 2, 'untold', now() + interval '1 minute')`); err != nil {
		t.Fatal(err)
	}
	take(2, "untold")
}

// The contract of kv.Transactor: fn may run more than once. Two transactions that each hold a record the
// other reads next cannot both go on; the database ends one, and the store runs it again.
func TestPostgres_ATransactionThatLosesAgainstAnotherRunsAgain(t *testing.T) {
	ctx := context.Background()
	dsn, _ := migrated(t)
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var runs atomic.Int64
	var both sync.WaitGroup
	both.Add(2)
	var held [2]sync.Once
	errs := make(chan error, 2)
	for i := range 2 {
		go func() {
			errs <- s.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
				runs.Add(1)
				if _, _, err := tx.Get(ctx, fmt.Sprint("record-", i)); err != nil {
					return err
				}
				held[i].Do(both.Done)
				both.Wait()
				if _, _, err := tx.Get(ctx, fmt.Sprint("record-", 1-i)); err != nil {
					return err
				}
				return tx.Set(ctx, fmt.Sprint("written-by-", i), []byte("v"), time.Minute)
			})
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Errorf("a transaction that met another: %v", err)
		}
	}
	if got := runs.Load(); got != 3 {
		t.Errorf("the two transactions ran %d times, not 3: the one the database ended, again", got)
	}
	if keys, err := s.Keys(ctx, "written-by-"); err != nil || len(keys) != 2 {
		t.Errorf("the records of the two transactions: %v, err %v", keys, err)
	}
}

// The contract of kv.Transactor: what a transaction read with Get stays as read until its end, against a
// writer outside a transaction as against another transaction, for a record that is there and one that is
// not.
func TestPostgres_WhatATransactionReadIsHeldAgainstWritersOutsideIt(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: skipping the Postgres kv tests (just kv-postgres-test)")
	}
	kvtest.TxOutside(t, func(t *testing.T) kv.Store {
		s, err := openKV(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
