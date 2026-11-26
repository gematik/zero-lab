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

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv/postgres"
)

// TestRevocations_ReachTheOtherReplicaOverPostgres proves revocation crosses processes over real Postgres
// LISTEN/NOTIFY: two independently-connected revocations (two "replicas"), a Revoke on one must reach the other.
// Gated on PEP_PG_DSN.
func TestRevocations_ReachTheOtherReplicaOverPostgres(t *testing.T) {
	dsn := os.Getenv("PEP_PG_DSN")
	if dsn == "" {
		t.Skip("PEP_PG_DSN not set — skipping Postgres LISTEN/NOTIFY integration test")
	}
	ctx := context.Background()
	// The test's database is one without TLS: the variable says so with sslmode=disable, which becomes the
	// acceptance the server takes from PEP_DATABASE_PLAINTEXT_ACCEPTED.
	db, err := databaseOf(strings.Replace(dsn, "?sslmode=disable", "", 1), func(name string) string {
		if name == databasePlaintextEnv && strings.Contains(dsn, "sslmode=disable") {
			return "true"
		}
		return ""
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	address, user, password := db.address, db.user, db.password
	store, err := postgres.Open(ctx, address, user, password, append([]postgres.Option{postgres.WithMigrate()}, db.transport...)...)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	busA, err := postgres.OpenBus(ctx, address, user, password, db.transport...)
	if err != nil {
		t.Fatal(err)
	}
	defer busA.Close()
	busB, err := postgres.OpenBus(ctx, address, user, password, db.transport...)
	if err != nil {
		t.Fatal(err)
	}
	defer busB.Close()

	a := followed(t, busA, store)
	b := followed(t, busB, store)
	time.Sleep(300 * time.Millisecond) // let both listeners establish LISTEN before the first NOTIFY

	if err := a.Revoke(ctx, "sid-pg", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !revoked(t, b, "sid-pg") {
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate across processes via Postgres LISTEN/NOTIFY")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
