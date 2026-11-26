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

package mariadb_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/mariadb"
)

// The tests of this file prove statements of the guide for hosts and of the doc comments that the other
// tests passed without.

// The guide for hosts: Cleanup removes expired records and events. A follower no longer gets an event
// whose retention is over, but only Cleanup takes it out of the table.
func TestMariaDB_CleanupRemovesTheEventsWhoseRetentionIsOver(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	db := adminOf(t, dsn)
	if _, err := mariadb.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
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
		if err := db.QueryRow(`SELECT COUNT(*), COALESCE(GROUP_CONCAT(payload), '') FROM kv_feed`).Scan(&n, &payload); err != nil {
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

// slowLine is a connection on which the first statement that holds a given text stays on its way until the
// test lets it through: a migration job whose statement is slow to reach the database.
type slowLine struct {
	text string
	// held is whether a statement is held already: only the first is, and those after it pass at once.
	// A sync.Once would make them wait for the first.
	held    atomic.Bool
	reached chan struct{}
	through chan struct{}
}

type slowConn struct {
	net.Conn
	line *slowLine
}

func (c slowConn) Write(p []byte) (int, error) {
	if line := c.line; bytes.Contains(p, []byte(line.text)) && line.held.CompareAndSwap(false, true) {
		close(line.reached)
		<-line.through
	}
	return c.Conn.Write(p)
}

// Migrate says that any number of migrators may run at once, because a step that runs twice changes
// nothing. Two migration jobs that contract: the statement of the first one's expand step is slow on
// its way, the second job applies that step and the contract step that undoes it, and then the slow
// statement arrives. The schema the two leave has to be the one the recorded steps describe: the column
// the contract step removed is gone.
func TestMigrate_AStepThatArrivesAfterTheContractStepThatUndoesItDoesNotPutBackWhatWasRemoved(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	db := adminOf(t, dsn)
	if _, err := mariadb.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	line := &slowLine{text: "ADD COLUMN IF NOT EXISTS probe", reached: make(chan struct{}), through: make(chan struct{})}
	var dialer net.Dialer
	mysql.RegisterDialContext("tcp", func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		return slowConn{Conn: conn, line: line}, nil
	})
	t.Cleanup(func() { mysql.DeregisterDialContext("tcp") })

	job := func() error {
		db, err := openDB(dsn)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		version, err := mariadb.MigrateSteps(ctx, db, ahead(), mariadb.Contract())
		if err == nil && version != released+3 {
			err = fmt.Errorf("the job leaves the schema at version %d", version)
		}
		return err
	}
	slow := make(chan error, 1)
	go func() { slow <- job() }()
	select {
	case <-line.reached:
	case err := <-slow:
		t.Fatalf("the first job ended before its expand step was sent: %v", err)
	case <-time.After(10 * time.Second):
		t.Skip("the statement of the expand step was not seen on the connection: this test reads it in plaintext (" + plaintextEnv + ")")
	}
	if err := job(); err != nil {
		t.Fatalf("the second job: %v", err)
	}
	if hasProbe(t, db) {
		t.Fatal("the second job did not contract")
	}
	close(line.through)
	if err := <-slow; err != nil {
		t.Fatalf("the first job: %v", err)
	}
	if got := appliedVersions(t, db); fmt.Sprint(got) != upTo(released+3) {
		t.Fatalf("applied %v", got)
	}
	if hasProbe(t, db) {
		t.Errorf("the database records the contract step %d as applied, and the column it removed is there again", released+2)
	}
}

// The contract of kv.Transactor: what a transaction read with Get stays as read until its end, against a
// writer outside a transaction as against another transaction, for a record that is there and one that is
// not.
func TestMariaDB_WhatATransactionReadIsHeldAgainstWritersOutsideIt(t *testing.T) {
	dsn := testDSN(t)
	kvtest.TxOutside(t, func(t *testing.T) kv.Store {
		s, err := openKV(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// The contract of kv.Transactor: fn may run more than once. Two transactions that each hold a record the
// other reads next cannot both go on; the database ends one as a deadlock, and the store runs it again.
func TestMariaDB_ATransactionThatLosesAgainstAnotherRunsAgain(t *testing.T) {
	ctx := context.Background()
	s, err := openKV(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := fmt.Sprintf("loses:%d:", time.Now().UnixNano())
	for i := range 2 {
		if err := s.Set(ctx, fmt.Sprint(p, "record-", i), []byte("v"), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	var runs atomic.Int64
	var both sync.WaitGroup
	both.Add(2)
	var held [2]sync.Once
	errs := make(chan error, 2)
	for i := range 2 {
		go func() {
			errs <- s.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
				runs.Add(1)
				if _, _, err := tx.Get(ctx, fmt.Sprint(p, "record-", i)); err != nil {
					return err
				}
				held[i].Do(both.Done)
				both.Wait()
				if _, _, err := tx.Get(ctx, fmt.Sprint(p, "record-", 1-i)); err != nil {
					return err
				}
				return tx.Set(ctx, fmt.Sprint(p, "written-by-", i), []byte("v"), time.Minute)
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
	if keys, err := s.Keys(ctx, p+"written-by-"); err != nil || len(keys) != 2 {
		t.Errorf("the records of the two transactions: %v, err %v", keys, err)
	}
}
