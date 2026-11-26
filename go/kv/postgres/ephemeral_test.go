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
	"os"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/postgres"
)

func TestPostgres_EphemeralContract(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres kv test (see pdp/docker-compose.yaml)")
	}
	open := func(t *testing.T) kv.Store {
		s, err := openKV(context.Background(), dsn, postgres.WithEphemeral())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	kvtest.Store(t, open)
	kvtest.Ephemeral(t, open)
	kvtest.Marker(t, func(t *testing.T, mark func(string, []byte) string) kv.Store {
		s, err := openKV(context.Background(), dsn, postgres.WithEphemeral(), postgres.WithMark(mark))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// The two classes are two tables: a record of one is not a record of the other, and the durable store says
// it is durable.
func TestPostgres_Task431TheClassesKeepTheirRecordsApart(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	durable, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer durable.Close()
	ephemeral, err := openKV(ctx, dsn, postgres.WithEphemeral())
	if err != nil {
		t.Fatal(err)
	}
	defer ephemeral.Close()
	if kv.DurabilityOf(durable) != kv.Durable || kv.DurabilityOf(ephemeral) != kv.Ephemeral {
		t.Fatalf("the stores say they are %v and %v", kv.DurabilityOf(durable), kv.DurabilityOf(ephemeral))
	}
	if err := durable.Set(ctx, "k", []byte("a session"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := ephemeral.Set(ctx, "k", []byte("a document"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := durable.Get(ctx, "k"); string(got) != "a session" {
		t.Errorf("the durable store holds %q", got)
	}
	if got, _, _ := ephemeral.Get(ctx, "k"); string(got) != "a document" {
		t.Errorf("the ephemeral store holds %q", got)
	}
	for table, want := range map[string]string{"kv": "a session", "kv_cache": "a document"} {
		var got string
		if err := db.QueryRow(`SELECT convert_from(value, 'UTF8') FROM ` + table + ` WHERE key='k'`).Scan(&got); err != nil || got != want {
			t.Errorf("table %s holds %q, err %v", table, got, err)
		}
	}
	if err := ephemeral.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := durable.Get(ctx, "k"); !found {
		t.Error("deleting the ephemeral record removed the durable one")
	}
}

// What makes the ephemeral class cheap to write: its table is unlogged, so its rows are not in the
// write-ahead log, and its transactions do not wait for their commit to be flushed. The durable class keeps
// both.
func TestPostgres_Task431EphemeralWritesAreUnloggedAndDoNotWaitForTheFlush(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]string{"kv": "p", "kv_cache": "u"} {
		var persistence string
		if err := db.QueryRow(`SELECT relpersistence FROM pg_class WHERE relname=$1`, table).Scan(&persistence); err != nil || persistence != want {
			t.Errorf("table %s: persistence %q (p: logged, u: unlogged), err %v", table, persistence, err)
		}
	}
	for name, want := range map[string]string{"durable": "on", "ephemeral": "off"} {
		var opts []postgres.Option
		if name == "ephemeral" {
			opts = append(opts, postgres.WithEphemeral())
		}
		s, err := openKV(ctx, dsn, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := postgres.CommitOfWrites(ctx, s); err != nil || got != want {
			t.Errorf("a write of the %s store runs with synchronous_commit %q, err %v", name, got, err)
		}
		if got, err := postgres.CommitOfTx(ctx, s); err != nil || got != want {
			t.Errorf("a transaction of the %s store runs with synchronous_commit %q, err %v", name, got, err)
		}
		_ = s.Close()
	}
}

// Measured, not asserted: what a write costs in each class on this database.
func TestPostgres_Task431WhatAWriteCostsInEachClass(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	if _, err := postgres.Migrate(ctx, adminOf(t, dsn)); err != nil {
		t.Fatal(err)
	}
	const writes = 2000
	value := make([]byte, 512)
	for _, class := range []string{"durable", "ephemeral"} {
		var opts []postgres.Option
		if class == "ephemeral" {
			opts = append(opts, postgres.WithEphemeral())
		}
		s, err := openKV(ctx, dsn, opts...)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for i := range writes {
			if err := s.Set(ctx, "k"+string(rune('a'+i%26)), value, time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%s: %v per write of %d bytes, one after another", class, time.Since(start)/writes, len(value))
		_ = s.Close()
	}
}
